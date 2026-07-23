import asyncio
import hashlib
import ipaddress
import socket
import ssl
from pathlib import Path

import pytest

from backend.tls_collector import (
    AsyncioTcpConnector,
    AsyncioTlsHandshaker,
    collect_verified_leaf,
    create_default_ssl_context,
)
from backend.tls_models import (
    ApprovedAddress,
    FailureCode,
    FailureStage,
    TlsCollectionFailure,
    ValidatedTarget,
    VerifiedLeafCertificate,
)


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "tls"
LEAF_DER = b"controlled leaf certificate"


def ipv4_record(address: str) -> tuple:
    return (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        (address, 443),
    )


class FakeResolver:
    def __init__(self, records: list[tuple]) -> None:
        self.records = records
        self.calls: list[ValidatedTarget] = []

    async def resolve(self, target: ValidatedTarget) -> list[tuple]:
        self.calls.append(target)
        return self.records


class SlowResolver:
    async def resolve(self, target: ValidatedTarget) -> list[tuple]:
        del target
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


class FakeRawSocket:
    pass


class TrackingRawSocket:
    def __init__(self) -> None:
        self.close_calls = 0
        self.blocking: bool | None = None

    def setblocking(self, blocking: bool) -> None:
        self.blocking = blocking

    def close(self) -> None:
        self.close_calls += 1


class FakeConnector:
    def __init__(self, failures_before_success: int = 0) -> None:
        self.failures_before_success = failures_before_success
        self.addresses: list[ApprovedAddress] = []
        self.deadlines: list[float] = []

    async def connect(
        self,
        address: ApprovedAddress,
        *,
        deadline: float,
    ) -> FakeRawSocket:
        self.addresses.append(address)
        self.deadlines.append(deadline)
        if len(self.addresses) <= self.failures_before_success:
            raise OSError("controlled connection failure")
        return FakeRawSocket()


class NeverConnectingConnector(FakeConnector):
    async def connect(
        self,
        address: ApprovedAddress,
        *,
        deadline: float,
    ) -> FakeRawSocket:
        self.addresses.append(address)
        self.deadlines.append(deadline)
        if len(self.addresses) == 1:
            raise OSError("controlled connection failure")
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


class DeadlineExpiredConnector(FakeConnector):
    async def connect(
        self,
        address: ApprovedAddress,
        *,
        deadline: float,
    ) -> FakeRawSocket:
        self.addresses.append(address)
        self.deadlines.append(deadline)
        raise TimeoutError


class FailureAfterDeadlineConnector(FakeConnector):
    async def connect(
        self,
        address: ApprovedAddress,
        *,
        deadline: float,
    ) -> FakeRawSocket:
        self.addresses.append(address)
        self.deadlines.append(deadline)
        loop = asyncio.get_running_loop()
        while loop.time() < deadline:
            pass
        raise OSError("controlled failure after deadline")


class FakeSSLObject:
    def getpeercert(self, binary_form: bool = False) -> bytes:
        assert binary_form is True
        return LEAF_DER


class FakeWriter:
    def __init__(self, ssl_object: object | None = None) -> None:
        self.ssl_object = ssl_object
        self.closed = False
        self.waited_closed = False

    def get_extra_info(self, name: str) -> object | None:
        assert name == "ssl_object"
        return self.ssl_object

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        self.waited_closed = True


class DeadlineOverrunningWriter(FakeWriter):
    def __init__(self, clock_advance: float) -> None:
        super().__init__(FakeSSLObject())
        self.clock_advance = clock_advance

    async def wait_closed(self) -> None:
        self.waited_closed = True
        loop = asyncio.get_running_loop()
        original_time = loop.time
        cleanup_finished_at = original_time() + self.clock_advance
        setattr(loop, "time", lambda: cleanup_finished_at)
        loop.call_soon(setattr, loop, "time", original_time)


def test_deadline_expiring_during_stream_cleanup_returns_timeout() -> None:
    writer = DeadlineOverrunningWriter(clock_advance=2.0)
    result = asyncio.run(
        collect_verified_leaf(
            "example.com",
            overall_timeout=1.0,
            resolver=FakeResolver([ipv4_record("8.8.8.8")]),
            connector=FakeConnector(),
            tls_handshaker=FakeHandshaker(writer=writer),
        )
    )

    assert isinstance(result, TlsCollectionFailure)
    assert result.stage is FailureStage.CERTIFICATE
    assert result.code is FailureCode.OVERALL_TIMEOUT
    assert writer.closed is True
    assert writer.waited_closed is True


class OwningWriter(FakeWriter):
    def __init__(self, raw_socket: TrackingRawSocket) -> None:
        super().__init__(FakeSSLObject())
        self.raw_socket = raw_socket
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1
        self.raw_socket.close()
        super().close()


class FakeHandshaker:
    def __init__(
        self,
        writer: FakeWriter | None = None,
        error: BaseException | None = None,
    ) -> None:
        self.writer = writer or FakeWriter(FakeSSLObject())
        self.error = error
        self.calls: list[tuple[FakeRawSocket, ValidatedTarget, float]] = []

    async def handshake(
        self,
        raw_socket: FakeRawSocket,
        target: ValidatedTarget,
        *,
        deadline: float,
    ) -> FakeWriter:
        self.calls.append((raw_socket, target, deadline))
        if self.error is not None:
            raise self.error
        return self.writer


def public_ipv4_address(port: int = 443) -> ApprovedAddress:
    return ApprovedAddress(
        ip=ipaddress.IPv4Address("8.8.8.8"),
        family=socket.AF_INET,
        sockaddr=("8.8.8.8", port),
    )


def test_asyncio_connector_uses_numeric_sockaddr_without_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run_test() -> None:
        connected = asyncio.Event()

        async def accept_client(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            del reader
            connected.set()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(
            accept_client,
            host="127.0.0.1",
            port=0,
        )
        port = server.sockets[0].getsockname()[1]
        loop = asyncio.get_running_loop()

        async def reject_resolution(*args: object, **kwargs: object) -> None:
            del args, kwargs
            raise AssertionError("numeric connector attempted hostname resolution")

        monkeypatch.setattr(loop, "getaddrinfo", reject_resolution)
        address = ApprovedAddress(
            ip=ipaddress.IPv4Address("127.0.0.1"),
            family=socket.AF_INET,
            sockaddr=("127.0.0.1", port),
        )

        try:
            raw_socket = await AsyncioTcpConnector().connect(
                address,
                deadline=loop.time() + 1.0,
            )
            raw_socket.close()
            await connected.wait()
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run_test())


def test_asyncio_connector_cancellation_closes_owned_socket_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run_test() -> int:
        raw_socket = TrackingRawSocket()
        started = asyncio.Event()

        monkeypatch.setattr(socket, "socket", lambda *args: raw_socket)
        loop = asyncio.get_running_loop()

        async def wait_forever(*args: object) -> None:
            del args
            started.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(loop, "sock_connect", wait_forever)
        task = asyncio.create_task(
            AsyncioTcpConnector().connect(
                public_ipv4_address(),
                deadline=loop.time() + 1.0,
            )
        )
        await started.wait()
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task
        return raw_socket.close_calls

    assert asyncio.run(run_test()) == 1


def test_tls_upgrade_failure_is_cleaned_by_transferred_owner_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_socket = TrackingRawSocket()

    async def fail_upgrade(**kwargs: object) -> tuple[object, object]:
        transferred_socket = kwargs["sock"]
        assert transferred_socket is raw_socket
        raw_socket.close()
        raise ssl.SSLError("controlled TLS upgrade failure")

    monkeypatch.setattr(asyncio, "open_connection", fail_upgrade)

    with pytest.raises(ssl.SSLError):
        asyncio.run(
            AsyncioTlsHandshaker().handshake(
                raw_socket,
                ValidatedTarget("example.com"),
                deadline=1000000000.0,
            )
        )

    assert raw_socket.close_calls == 1


def test_tls_pretransfer_failure_closes_collector_owned_socket_once() -> None:
    raw_socket = TrackingRawSocket()

    def fail_context_creation() -> ssl.SSLContext:
        raise ValueError("controlled context creation failure")

    with pytest.raises(ValueError):
        asyncio.run(
            AsyncioTlsHandshaker(
                context_factory=fail_context_creation
            ).handshake(
                raw_socket,
                ValidatedTarget("example.com"),
                deadline=1000000000.0,
            )
        )

    assert raw_socket.close_calls == 1


def test_tls_upgrade_cancellation_is_cleaned_by_transferred_owner_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_socket = TrackingRawSocket()

    async def cancel_upgrade(**kwargs: object) -> tuple[object, object]:
        transferred_socket = kwargs["sock"]
        assert transferred_socket is raw_socket
        raw_socket.close()
        raise asyncio.CancelledError

    monkeypatch.setattr(asyncio, "open_connection", cancel_upgrade)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            AsyncioTlsHandshaker().handshake(
                raw_socket,
                ValidatedTarget("example.com"),
                deadline=1000000000.0,
            )
        )

    assert raw_socket.close_calls == 1


def test_writer_is_the_only_cleanup_owner_after_tls_transfer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_socket = TrackingRawSocket()
    writer = OwningWriter(raw_socket)

    class TrackingConnector:
        async def connect(
            self,
            address: ApprovedAddress,
            *,
            deadline: float,
        ) -> TrackingRawSocket:
            del address, deadline
            return raw_socket

    async def complete_upgrade(**kwargs: object) -> tuple[object, OwningWriter]:
        assert kwargs["sock"] is raw_socket
        return object(), writer

    monkeypatch.setattr(asyncio, "open_connection", complete_upgrade)
    result = asyncio.run(
        collect_verified_leaf(
            "example.com",
            overall_timeout=1.0,
            resolver=FakeResolver([ipv4_record("8.8.8.8")]),
            connector=TrackingConnector(),
            tls_handshaker=AsyncioTlsHandshaker(),
        )
    )

    assert isinstance(result, VerifiedLeafCertificate)
    assert writer.close_calls == 1
    assert raw_socket.close_calls == 1


def test_collects_verified_leaf_without_resolving_hostname_again() -> None:
    resolver = FakeResolver([ipv4_record("8.8.8.8")])
    connector = FakeConnector()
    writer = FakeWriter(FakeSSLObject())
    handshaker = FakeHandshaker(writer)

    result = asyncio.run(
        collect_verified_leaf(
            "example.com",
            overall_timeout=1.0,
            resolver=resolver,
            connector=connector,
            tls_handshaker=handshaker,
        )
    )

    assert result == VerifiedLeafCertificate(
        target=ValidatedTarget(hostname="example.com", port=443),
        connected_ip=connector.addresses[0].ip,
        certificate_der=LEAF_DER,
        certificate_sha256=hashlib.sha256(LEAF_DER).hexdigest(),
    )
    assert len(resolver.calls) == 1
    assert connector.addresses[0].sockaddr == ("8.8.8.8", 443)
    assert handshaker.calls[0][1].hostname == "example.com"
    assert writer.closed is True
    assert writer.waited_closed is True


def test_address_attempts_share_one_deadline() -> None:
    resolver = FakeResolver(
        [ipv4_record("8.8.8.8"), ipv4_record("1.1.1.1")]
    )
    connector = FakeConnector(failures_before_success=1)

    result = asyncio.run(
        collect_verified_leaf(
            "example.com",
            overall_timeout=1.0,
            resolver=resolver,
            connector=connector,
            tls_handshaker=FakeHandshaker(),
        )
    )

    assert isinstance(result, VerifiedLeafCertificate)
    assert len(connector.deadlines) == 2
    assert connector.deadlines[0] == connector.deadlines[1]


def test_outer_deadline_takes_precedence_over_prior_connect_failure() -> None:
    result = asyncio.run(
        collect_verified_leaf(
            "example.com",
            overall_timeout=0.02,
            resolver=FakeResolver(
                [ipv4_record("8.8.8.8"), ipv4_record("1.1.1.1")]
            ),
            connector=NeverConnectingConnector(),
            tls_handshaker=FakeHandshaker(),
        )
    )

    assert isinstance(result, TlsCollectionFailure)
    assert result.stage is FailureStage.CONNECT
    assert result.code is FailureCode.OVERALL_TIMEOUT


def test_dns_wait_expiring_outer_deadline_is_overall_timeout() -> None:
    result = asyncio.run(
        collect_verified_leaf(
            "example.com",
            overall_timeout=0.02,
            resolver=SlowResolver(),
            connector=FakeConnector(),
            tls_handshaker=FakeHandshaker(),
        )
    )

    assert isinstance(result, TlsCollectionFailure)
    assert result.stage is FailureStage.DNS
    assert result.code is FailureCode.OVERALL_TIMEOUT


def test_invalid_addrinfo_maps_to_stable_dns_failure() -> None:
    connector = FakeConnector()
    result = asyncio.run(
        collect_verified_leaf(
            "example.com",
            overall_timeout=1.0,
            resolver=FakeResolver(
                [
                    (
                        socket.AF_INET,
                        socket.SOCK_STREAM,
                        socket.IPPROTO_TCP,
                        "",
                        ("2606:4700:4700::1111", 443),
                    )
                ]
            ),
            connector=connector,
            tls_handshaker=FakeHandshaker(),
        )
    )

    assert isinstance(result, TlsCollectionFailure)
    assert result.stage is FailureStage.DNS
    assert result.code is FailureCode.DNS_FAILURE
    assert connector.addresses == []


def test_connector_deadline_expiration_is_overall_timeout() -> None:
    result = asyncio.run(
        collect_verified_leaf(
            "example.com",
            overall_timeout=1.0,
            resolver=FakeResolver([ipv4_record("8.8.8.8")]),
            connector=DeadlineExpiredConnector(),
            tls_handshaker=FakeHandshaker(),
        )
    )

    assert isinstance(result, TlsCollectionFailure)
    assert result.stage is FailureStage.CONNECT
    assert result.code is FailureCode.OVERALL_TIMEOUT


def test_handshaker_deadline_expiration_is_overall_timeout() -> None:
    result = asyncio.run(
        collect_verified_leaf(
            "example.com",
            overall_timeout=1.0,
            resolver=FakeResolver([ipv4_record("8.8.8.8")]),
            connector=FakeConnector(),
            tls_handshaker=FakeHandshaker(error=TimeoutError()),
        )
    )

    assert isinstance(result, TlsCollectionFailure)
    assert result.stage is FailureStage.TLS_HANDSHAKE
    assert result.code is FailureCode.OVERALL_TIMEOUT


def test_elapsed_deadline_precedes_connect_operation_failure() -> None:
    result = asyncio.run(
        collect_verified_leaf(
            "example.com",
            overall_timeout=0.01,
            resolver=FakeResolver([ipv4_record("8.8.8.8")]),
            connector=FailureAfterDeadlineConnector(),
            tls_handshaker=FakeHandshaker(),
        )
    )

    assert isinstance(result, TlsCollectionFailure)
    assert result.stage is FailureStage.CONNECT
    assert result.code is FailureCode.OVERALL_TIMEOUT


def test_verification_failure_has_stable_code() -> None:
    result = asyncio.run(
        collect_verified_leaf(
            "example.com",
            overall_timeout=1.0,
            resolver=FakeResolver([ipv4_record("8.8.8.8")]),
            connector=FakeConnector(),
            tls_handshaker=FakeHandshaker(
                error=ssl.SSLCertVerificationError(
                    1,
                    "controlled verification failure",
                )
            ),
        )
    )

    assert isinstance(result, TlsCollectionFailure)
    assert result.stage is FailureStage.TLS_HANDSHAKE
    assert result.code is FailureCode.TLS_VERIFICATION_FAILED


def test_missing_public_ssl_object_closes_stream() -> None:
    writer = FakeWriter(ssl_object=None)

    result = asyncio.run(
        collect_verified_leaf(
            "example.com",
            overall_timeout=1.0,
            resolver=FakeResolver([ipv4_record("8.8.8.8")]),
            connector=FakeConnector(),
            tls_handshaker=FakeHandshaker(writer=writer),
        )
    )

    assert isinstance(result, TlsCollectionFailure)
    assert result.stage is FailureStage.CERTIFICATE
    assert result.code is FailureCode.MISSING_PEER_CERTIFICATE
    assert writer.closed is True
    assert writer.waited_closed is True


def test_default_context_requires_certificate_and_hostname_verification() -> None:
    context = create_default_ssl_context()

    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True


@pytest.mark.parametrize(
    ("maximum_attempts", "expected_attempts"),
    [(None, 3), (2, 2)],
)
def test_address_attempt_count_is_bounded_and_configurable(
    maximum_attempts: int | None,
    expected_attempts: int,
) -> None:
    connector = FakeConnector(failures_before_success=10)
    options = (
        {}
        if maximum_attempts is None
        else {"max_address_attempts": maximum_attempts}
    )

    result = asyncio.run(
        collect_verified_leaf(
            "example.com",
            overall_timeout=1.0,
            resolver=FakeResolver(
                [
                    ipv4_record("8.8.8.8"),
                    ipv4_record("1.1.1.1"),
                    ipv4_record("9.9.9.9"),
                    ipv4_record("8.8.4.4"),
                ]
            ),
            connector=connector,
            tls_handshaker=FakeHandshaker(),
            **options,
        )
    )

    assert isinstance(result, TlsCollectionFailure)
    assert result.stage is FailureStage.CONNECT
    assert result.code is FailureCode.CONNECT_FAILURE
    assert len(connector.addresses) == expected_attempts


def test_local_tls_fixture_is_verified_via_san_and_test_ca() -> None:
    async def run_test() -> VerifiedLeafCertificate | TlsCollectionFailure:
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(
            certfile=FIXTURE_DIR / "server.pem",
            keyfile=FIXTURE_DIR / "server-key.pem",
        )

        async def close_client(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            del reader
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(
            close_client,
            host="127.0.0.1",
            port=0,
            ssl=server_context,
        )
        port = server.sockets[0].getsockname()[1]

        class TestOnlyLoopbackConnector:
            async def connect(
                self,
                address: ApprovedAddress,
                *,
                deadline: float,
            ) -> socket.socket:
                assert str(address.ip) == "8.8.8.8"
                raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_socket.setblocking(False)
                try:
                    async with asyncio.timeout_at(deadline):
                        await asyncio.get_running_loop().sock_connect(
                            raw_socket,
                            ("127.0.0.1", port),
                        )
                except BaseException:
                    raw_socket.close()
                    raise
                return raw_socket

        test_context = ssl.create_default_context(
            cafile=FIXTURE_DIR / "test-ca.pem"
        )

        try:
            return await collect_verified_leaf(
                "tls.test",
                overall_timeout=1.0,
                resolver=FakeResolver([ipv4_record("8.8.8.8")]),
                connector=TestOnlyLoopbackConnector(),
                tls_handshaker=AsyncioTlsHandshaker(
                    context_factory=lambda: test_context
                ),
            )
        finally:
            server.close()
            await server.wait_closed()

    result = asyncio.run(run_test())

    assert isinstance(result, VerifiedLeafCertificate)
    assert result.target.hostname == "tls.test"
    assert result.connected_ip.compressed == "8.8.8.8"
    assert result.certificate_der
    assert len(result.certificate_sha256) == 64
