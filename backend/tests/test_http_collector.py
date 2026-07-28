import asyncio
import ipaddress
import socket
import ssl

import pytest

from backend.http_collector import (
    HttpsHeaderTransport,
    HttpConnectError,
    MalformedHttpResponseError,
    RawHttpResponse,
    collect_http_security_headers,
)
from backend.http_models import (
    HttpCollectionFailureCode,
    HttpCollectionStage,
    HttpHeaderCollectionFailure,
    HttpResponseObservation,
)
from backend.tls_models import ApprovedAddress, ValidatedTarget


def ipv4_record(address: str) -> tuple:
    return (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        (address, 443),
    )


class MappingResolver:
    def __init__(self, records: dict[str, list[tuple]]) -> None:
        self.records = records
        self.calls: list[ValidatedTarget] = []

    async def resolve(self, target: ValidatedTarget) -> list[tuple]:
        self.calls.append(target)
        return self.records[target.hostname]


class SlowResolver:
    async def resolve(self, target: ValidatedTarget) -> list[tuple]:
        del target
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


class SequencedResolver:
    def __init__(self, records: list[list[tuple]]) -> None:
        self.records = records
        self.calls: list[ValidatedTarget] = []

    async def resolve(self, target: ValidatedTarget) -> list[tuple]:
        self.calls.append(target)
        return self.records.pop(0)


class FakeTransport:
    def __init__(
        self,
        outcomes: list[RawHttpResponse | BaseException],
    ) -> None:
        self.outcomes = outcomes
        self.calls: list[
            tuple[ApprovedAddress, ValidatedTarget, str, float, int]
        ] = []

    async def request(
        self,
        address: ApprovedAddress,
        target: ValidatedTarget,
        request_target: str,
        *,
        deadline: float,
        max_header_bytes: int,
    ) -> RawHttpResponse:
        self.calls.append(
            (
                address,
                target,
                request_target,
                deadline,
                max_header_bytes,
            )
        )
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def response(
    status_code: int = 200,
    *headers: tuple[str, str],
) -> RawHttpResponse:
    return RawHttpResponse(status_code=status_code, headers=headers)


def test_collects_final_response_metadata_from_validated_numeric_address() -> None:
    resolver = MappingResolver({"example.com": [ipv4_record("8.8.8.8")]})
    transport = FakeTransport(
        [response(200, ("X-Content-Type-Options", "nosniff"))]
    )

    result = asyncio.run(
        collect_http_security_headers(
            "EXAMPLE.COM.",
            overall_timeout=1.0,
            resolver=resolver,
            transport=transport,
        )
    )

    assert result == HttpResponseObservation(
        requested_hostname="example.com",
        connected_ip=ipaddress.ip_address("8.8.8.8"),
        final_url="https://example.com/",
        final_hostname="example.com",
        http_status_code=200,
        headers=(("X-Content-Type-Options", "nosniff"),),
        redirect_count=0,
    )
    assert resolver.calls == [ValidatedTarget("example.com")]
    assert transport.calls[0][0].sockaddr == ("8.8.8.8", 443)
    assert transport.calls[0][1] == ValidatedTarget("example.com")
    assert transport.calls[0][2] == "/"


def test_public_redirect_is_revalidated_and_connected_by_numeric_ip() -> None:
    resolver = MappingResolver(
        {
            "example.com": [ipv4_record("8.8.8.8")],
            "www.example.com": [ipv4_record("1.1.1.1")],
        }
    )
    transport = FakeTransport(
        [
            response(
                302,
                ("Location", "https://www.example.com/security?source=test"),
            ),
            response(200, ("Content-Security-Policy", "default-src 'self'")),
        ]
    )

    result = asyncio.run(
        collect_http_security_headers(
            "example.com",
            overall_timeout=1.0,
            resolver=resolver,
            transport=transport,
        )
    )

    assert isinstance(result, HttpResponseObservation)
    assert result.final_url == "https://www.example.com/security?source=test"
    assert result.final_hostname == "www.example.com"
    assert result.connected_ip == ipaddress.ip_address("1.1.1.1")
    assert result.redirect_count == 1
    assert resolver.calls == [
        ValidatedTarget("example.com"),
        ValidatedTarget("www.example.com"),
    ]
    assert [call[0].sockaddr for call in transport.calls] == [
        ("8.8.8.8", 443),
        ("1.1.1.1", 443),
    ]
    assert transport.calls[1][2] == "/security?source=test"


def test_redirect_to_blocked_destination_is_never_connected() -> None:
    resolver = MappingResolver(
        {
            "example.com": [ipv4_record("8.8.8.8")],
            "private.example": [ipv4_record("127.0.0.1")],
        }
    )
    transport = FakeTransport(
        [response(302, ("Location", "https://private.example/admin"))]
    )

    result = asyncio.run(
        collect_http_security_headers(
            "example.com",
            overall_timeout=1.0,
            resolver=resolver,
            transport=transport,
        )
    )

    assert result == HttpHeaderCollectionFailure(
        stage=HttpCollectionStage.REDIRECT,
        code=HttpCollectionFailureCode.BLOCKED_REDIRECT,
    )
    assert len(transport.calls) == 1


def test_same_host_redirect_is_resolved_again_and_rebinding_is_blocked() -> None:
    resolver = SequencedResolver(
        [
            [ipv4_record("8.8.8.8")],
            [ipv4_record("127.0.0.1")],
        ]
    )
    transport = FakeTransport([response(302, ("Location", "/next"))])

    result = asyncio.run(
        collect_http_security_headers(
            "example.com",
            overall_timeout=1.0,
            resolver=resolver,
            transport=transport,
        )
    )

    assert result == HttpHeaderCollectionFailure(
        stage=HttpCollectionStage.REDIRECT,
        code=HttpCollectionFailureCode.BLOCKED_REDIRECT,
    )
    assert resolver.calls == [
        ValidatedTarget("example.com"),
        ValidatedTarget("example.com"),
    ]
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "headers",
    [
        (),
        (("Location", "https://one.example/"), ("location", "/two")),
        (("Location", ""),),
    ],
)
def test_redirect_requires_one_nonempty_location_header(
    headers: tuple[tuple[str, str], ...],
) -> None:
    result = asyncio.run(
        collect_http_security_headers(
            "example.com",
            overall_timeout=1.0,
            resolver=MappingResolver(
                {"example.com": [ipv4_record("8.8.8.8")]}
            ),
            transport=FakeTransport([response(302, *headers)]),
        )
    )

    assert result == HttpHeaderCollectionFailure(
        stage=HttpCollectionStage.REDIRECT,
        code=HttpCollectionFailureCode.INVALID_REDIRECT,
    )


def test_redirect_loop_is_stopped_without_another_request() -> None:
    transport = FakeTransport([response(302, ("Location", "/"))])

    result = asyncio.run(
        collect_http_security_headers(
            "example.com",
            overall_timeout=1.0,
            resolver=MappingResolver(
                {"example.com": [ipv4_record("8.8.8.8")]}
            ),
            transport=transport,
        )
    )

    assert result == HttpHeaderCollectionFailure(
        stage=HttpCollectionStage.REDIRECT,
        code=HttpCollectionFailureCode.REDIRECT_LOOP,
    )
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    ("location", "expected_code"),
    [
        (
            "http://public.example/",
            HttpCollectionFailureCode.UNSUPPORTED_REDIRECT_SCHEME,
        ),
        (
            "https://user@public.example/",
            HttpCollectionFailureCode.INVALID_REDIRECT,
        ),
        (
            "https://public.example:8443/",
            HttpCollectionFailureCode.INVALID_REDIRECT,
        ),
        (
            "https://127.0.0.1/",
            HttpCollectionFailureCode.INVALID_REDIRECT,
        ),
    ],
)
def test_unsupported_or_unsafe_redirect_is_rejected_before_resolution(
    location: str,
    expected_code: HttpCollectionFailureCode,
) -> None:
    resolver = MappingResolver({"example.com": [ipv4_record("8.8.8.8")]})
    transport = FakeTransport([response(302, ("Location", location))])

    result = asyncio.run(
        collect_http_security_headers(
            "example.com",
            overall_timeout=1.0,
            resolver=resolver,
            transport=transport,
        )
    )

    assert result == HttpHeaderCollectionFailure(
        stage=HttpCollectionStage.REDIRECT,
        code=expected_code,
    )
    assert len(resolver.calls) == 1


def test_redirect_limit_is_enforced() -> None:
    resolver = MappingResolver({"example.com": [ipv4_record("8.8.8.8")]})
    transport = FakeTransport(
        [
            response(302, ("Location", f"/redirect-{index}"))
            for index in range(4)
        ]
    )

    result = asyncio.run(
        collect_http_security_headers(
            "example.com",
            overall_timeout=1.0,
            resolver=resolver,
            transport=transport,
            max_redirects=3,
        )
    )

    assert result == HttpHeaderCollectionFailure(
        stage=HttpCollectionStage.REDIRECT,
        code=HttpCollectionFailureCode.TOO_MANY_REDIRECTS,
    )
    assert len(transport.calls) == 4


def test_overall_timeout_during_dns_has_typed_failure() -> None:
    result = asyncio.run(
        collect_http_security_headers(
            "example.com",
            overall_timeout=0.01,
            resolver=SlowResolver(),
            transport=FakeTransport([]),
        )
    )

    assert result == HttpHeaderCollectionFailure(
        stage=HttpCollectionStage.DNS,
        code=HttpCollectionFailureCode.OVERALL_TIMEOUT,
    )


def test_connection_failure_has_typed_failure() -> None:
    result = asyncio.run(
        collect_http_security_headers(
            "example.com",
            overall_timeout=1.0,
            resolver=MappingResolver(
                {"example.com": [ipv4_record("8.8.8.8")]}
            ),
            transport=FakeTransport(
                [HttpConnectError("controlled connection failure")]
            ),
        )
    )

    assert result == HttpHeaderCollectionFailure(
        stage=HttpCollectionStage.CONNECT,
        code=HttpCollectionFailureCode.CONNECTION_FAILURE,
    )


def test_malformed_response_has_typed_failure() -> None:
    result = asyncio.run(
        collect_http_security_headers(
            "example.com",
            overall_timeout=1.0,
            resolver=MappingResolver(
                {"example.com": [ipv4_record("8.8.8.8")]}
            ),
            transport=FakeTransport(
                [MalformedHttpResponseError("controlled malformed response")]
            ),
        )
    )

    assert result == HttpHeaderCollectionFailure(
        stage=HttpCollectionStage.RESPONSE,
        code=HttpCollectionFailureCode.MALFORMED_RESPONSE,
    )


class FakeRawSocket:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeConnector:
    def __init__(self, raw_socket: FakeRawSocket) -> None:
        self.raw_socket = raw_socket
        self.addresses: list[ApprovedAddress] = []

    async def connect(
        self,
        address: ApprovedAddress,
        *,
        deadline: float,
    ) -> FakeRawSocket:
        del deadline
        self.addresses.append(address)
        return self.raw_socket


class HeadersOnlyReader:
    def __init__(self, response_bytes: bytes) -> None:
        self.response_bytes = response_bytes
        self.readuntil_calls = 0
        self.body_read_calls = 0

    async def readuntil(self, separator: bytes) -> bytes:
        assert separator == b"\r\n\r\n"
        self.readuntil_calls += 1
        return self.response_bytes

    async def read(self, count: int = -1) -> bytes:
        del count
        self.body_read_calls += 1
        raise AssertionError("response body must not be read")


class OversizedHeadersReader(HeadersOnlyReader):
    async def readuntil(self, separator: bytes) -> bytes:
        del separator
        self.readuntil_calls += 1
        raise asyncio.LimitOverrunError(
            "controlled oversized response headers",
            consumed=65537,
        )


class FakeWriter:
    def __init__(self) -> None:
        self.request_bytes = b""
        self.closed = False
        self.waited_closed = False

    def write(self, data: bytes) -> None:
        self.request_bytes += data

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        self.waited_closed = True


def public_address() -> ApprovedAddress:
    return ApprovedAddress(
        ip=ipaddress.ip_address("8.8.8.8"),
        family=socket.AF_INET,
        sockaddr=("8.8.8.8", 443),
    )


def test_https_transport_preserves_host_and_sni_without_reading_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_socket = FakeRawSocket()
    connector = FakeConnector(raw_socket)
    reader = HeadersOnlyReader(
        b"HTTP/1.1 200 OK\r\n"
        b"X-Content-Type-Options: nosniff\r\n"
        b"Content-Length: 999999\r\n"
        b"\r\n"
        b"body bytes already buffered"
    )
    writer = FakeWriter()

    async def fake_open_connection(
        **kwargs: object,
    ) -> tuple[HeadersOnlyReader, FakeWriter]:
        assert kwargs["sock"] is raw_socket
        assert isinstance(kwargs["ssl"], ssl.SSLContext)
        assert kwargs["ssl"].verify_mode is ssl.CERT_REQUIRED
        assert kwargs["ssl"].check_hostname is True
        assert kwargs["server_hostname"] == "example.com"
        assert kwargs["limit"] == 65537
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    async def run_test() -> RawHttpResponse:
        loop = asyncio.get_running_loop()
        return await HttpsHeaderTransport(connector=connector).request(
            public_address(),
            ValidatedTarget("example.com"),
            "/headers?scan=1",
            deadline=loop.time() + 1.0,
            max_header_bytes=65536,
        )

    result = asyncio.run(run_test())

    assert result == RawHttpResponse(
        status_code=200,
        headers=(
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Length", "999999"),
        ),
    )
    assert connector.addresses == [public_address()]
    assert writer.request_bytes.startswith(b"GET /headers?scan=1 HTTP/1.1\r\n")
    assert b"Host: example.com\r\n" in writer.request_bytes
    assert reader.readuntil_calls == 1
    assert reader.body_read_calls == 0
    assert writer.closed is True
    assert writer.waited_closed is True


def test_https_transport_rejects_malformed_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = HeadersOnlyReader(b"not an HTTP response\r\n\r\n")
    writer = FakeWriter()

    async def fake_open_connection(
        **kwargs: object,
    ) -> tuple[HeadersOnlyReader, FakeWriter]:
        del kwargs
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    async def run_test() -> None:
        loop = asyncio.get_running_loop()
        await HttpsHeaderTransport(
            connector=FakeConnector(FakeRawSocket())
        ).request(
            public_address(),
            ValidatedTarget("example.com"),
            "/",
            deadline=loop.time() + 1.0,
            max_header_bytes=65536,
        )

    with pytest.raises(MalformedHttpResponseError):
        asyncio.run(run_test())

    assert writer.closed is True
    assert writer.waited_closed is True


def test_https_transport_rejects_oversized_response_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = OversizedHeadersReader(b"")
    writer = FakeWriter()

    async def fake_open_connection(
        **kwargs: object,
    ) -> tuple[OversizedHeadersReader, FakeWriter]:
        del kwargs
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    async def run_test() -> None:
        loop = asyncio.get_running_loop()
        await HttpsHeaderTransport(
            connector=FakeConnector(FakeRawSocket())
        ).request(
            public_address(),
            ValidatedTarget("example.com"),
            "/",
            deadline=loop.time() + 1.0,
            max_header_bytes=65536,
        )

    with pytest.raises(MalformedHttpResponseError):
        asyncio.run(run_test())

    assert reader.readuntil_calls == 1
    assert reader.body_read_calls == 0
    assert writer.closed is True
    assert writer.waited_closed is True
