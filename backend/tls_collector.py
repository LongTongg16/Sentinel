import asyncio
import hashlib
import socket
import ssl
from collections.abc import Callable
from typing import Protocol, cast

from backend.tls_models import (
    ApprovedAddress,
    FailureCode,
    FailureStage,
    TlsCollectionFailure,
    ValidatedTarget,
    VerifiedLeafCertificate,
)
from backend.tls_target import (
    BlockedAddressError,
    InvalidAddressRecordError,
    InvalidTargetError,
    NoAddressesError,
    Resolver,
    SystemResolver,
    approve_resolved_addresses,
    validate_target,
)


CollectionResult = VerifiedLeafCertificate | TlsCollectionFailure
DEFAULT_MAX_ADDRESS_ATTEMPTS = 3


class StreamWriterLike(Protocol):
    def get_extra_info(self, name: str, default: object | None = None) -> object:
        ...

    def close(self) -> None:
        ...

    async def wait_closed(self) -> None:
        ...


class PublicSslObject(Protocol):
    def getpeercert(self, binary_form: bool = False) -> bytes | dict | None:
        ...


class TcpConnector(Protocol):
    async def connect(
        self,
        address: ApprovedAddress,
        *,
        deadline: float,
    ) -> socket.socket:
        """Return a connected socket whose ownership passes to the caller."""


class TlsHandshaker(Protocol):
    async def handshake(
        self,
        raw_socket: socket.socket,
        target: ValidatedTarget,
        *,
        deadline: float,
    ) -> StreamWriterLike:
        """Consume a raw socket and transfer ownership to the returned stream."""


class AsyncioTcpConnector:
    async def connect(
        self,
        address: ApprovedAddress,
        *,
        deadline: float,
    ) -> socket.socket:
        loop = asyncio.get_running_loop()
        if loop.time() >= deadline:
            raise TimeoutError

        raw_socket = socket.socket(address.family, socket.SOCK_STREAM)
        raw_socket.setblocking(False)
        try:
            await loop.sock_connect(
                raw_socket,
                address.sockaddr,
            )
        except BaseException:
            raw_socket.close()
            raise
        return raw_socket


def create_default_ssl_context() -> ssl.SSLContext:
    return ssl.create_default_context()


class AsyncioTlsHandshaker:
    def __init__(
        self,
        context_factory: Callable[[], ssl.SSLContext] = create_default_ssl_context,
    ) -> None:
        self._context_factory = context_factory

    async def handshake(
        self,
        raw_socket: socket.socket,
        target: ValidatedTarget,
        *,
        deadline: float,
    ) -> asyncio.StreamWriter:
        """Transfer raw-socket ownership to an asyncio TLS stream.

        The handshaker consumes the collector-owned socket. It closes the
        socket if preparation fails before transfer. Calling open_connection
        transfers ownership to asyncio, including failure and cancellation
        cleanup. On success, the returned StreamWriter owns the transport.
        """

        loop = asyncio.get_running_loop()
        remaining = deadline - loop.time()
        if remaining <= 0:
            raw_socket.close()
            raise TimeoutError

        try:
            ssl_context = self._context_factory()
        except BaseException:
            raw_socket.close()
            raise

        _reader, writer = await asyncio.open_connection(
            sock=raw_socket,
            ssl=ssl_context,
            server_hostname=target.hostname,
            ssl_handshake_timeout=remaining,
            ssl_shutdown_timeout=remaining,
        )
        return writer


def _failure_with_deadline_precedence(
    loop: asyncio.AbstractEventLoop,
    deadline: float,
    stage: FailureStage,
    code: FailureCode,
) -> TlsCollectionFailure:
    if loop.time() >= deadline:
        code = FailureCode.OVERALL_TIMEOUT
    return TlsCollectionFailure(stage=stage, code=code)


async def _close_stream(writer: StreamWriterLike) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except (OSError, ssl.SSLError):
        pass


async def collect_verified_leaf(
    hostname: str,
    *,
    overall_timeout: float,
    resolver: Resolver | None = None,
    connector: TcpConnector | None = None,
    tls_handshaker: TlsHandshaker | None = None,
    max_address_attempts: int = DEFAULT_MAX_ADDRESS_ATTEMPTS,
) -> CollectionResult:
    if max_address_attempts < 1:
        raise ValueError("max_address_attempts must be at least 1")

    loop = asyncio.get_running_loop()
    deadline = loop.time() + overall_timeout
    current_stage = FailureStage.TARGET_VALIDATION

    selected_resolver = resolver or SystemResolver()
    selected_connector = connector or AsyncioTcpConnector()
    selected_handshaker = tls_handshaker or AsyncioTlsHandshaker()

    try:
        async with asyncio.timeout_at(deadline):
            try:
                target = validate_target(hostname)
            except InvalidTargetError:
                return TlsCollectionFailure(
                    stage=FailureStage.TARGET_VALIDATION,
                    code=FailureCode.INVALID_HOSTNAME,
                )

            current_stage = FailureStage.DNS
            try:
                records = await selected_resolver.resolve(target)
            except TimeoutError:
                raise
            except (socket.gaierror, OSError):
                return _failure_with_deadline_precedence(
                    loop,
                    deadline,
                    FailureStage.DNS,
                    FailureCode.DNS_FAILURE,
                )

            try:
                approved_target = approve_resolved_addresses(target, records)
            except BlockedAddressError:
                return _failure_with_deadline_precedence(
                    loop,
                    deadline,
                    FailureStage.DNS,
                    FailureCode.BLOCKED_ADDRESS,
                )
            except NoAddressesError:
                return _failure_with_deadline_precedence(
                    loop,
                    deadline,
                    FailureStage.DNS,
                    FailureCode.NO_ADDRESSES,
                )
            except InvalidAddressRecordError:
                return _failure_with_deadline_precedence(
                    loop,
                    deadline,
                    FailureStage.DNS,
                    FailureCode.DNS_FAILURE,
                )

            for address in approved_target.addresses[:max_address_attempts]:
                current_stage = FailureStage.CONNECT
                try:
                    raw_socket = await selected_connector.connect(
                        address,
                        deadline=deadline,
                    )
                except TimeoutError:
                    raise
                except OSError:
                    if loop.time() >= deadline:
                        return TlsCollectionFailure(
                            stage=FailureStage.CONNECT,
                            code=FailureCode.OVERALL_TIMEOUT,
                        )
                    continue

                current_stage = FailureStage.TLS_HANDSHAKE
                try:
                    writer = await selected_handshaker.handshake(
                        raw_socket,
                        target,
                        deadline=deadline,
                    )
                except TimeoutError:
                    raise
                except ssl.SSLCertVerificationError:
                    return _failure_with_deadline_precedence(
                        loop,
                        deadline,
                        FailureStage.TLS_HANDSHAKE,
                        FailureCode.TLS_VERIFICATION_FAILED,
                    )
                except (OSError, ssl.SSLError):
                    return _failure_with_deadline_precedence(
                        loop,
                        deadline,
                        FailureStage.TLS_HANDSHAKE,
                        FailureCode.TLS_FAILURE,
                    )

                current_stage = FailureStage.CERTIFICATE
                certificate_result: CollectionResult

                try:
                    ssl_object = writer.get_extra_info("ssl_object")

                    if ssl_object is None:
                        certificate_result = _failure_with_deadline_precedence(
                            loop,
                            deadline,
                            FailureStage.CERTIFICATE,
                            FailureCode.MISSING_PEER_CERTIFICATE,
                        )
                    else:
                        public_ssl_object = cast(PublicSslObject, ssl_object)
                        certificate_der = public_ssl_object.getpeercert(
                            binary_form=True
                        )

                        if (
                            not isinstance(certificate_der, bytes)
                            or not certificate_der
                        ):
                            certificate_result = (
                                _failure_with_deadline_precedence(
                                    loop,
                                    deadline,
                                    FailureStage.CERTIFICATE,
                                    FailureCode.MISSING_PEER_CERTIFICATE,
                                )
                            )
                        else:
                            certificate_result = VerifiedLeafCertificate(
                                target=target,
                                connected_ip=address.ip,
                                certificate_der=certificate_der,
                                certificate_sha256=hashlib.sha256(
                                    certificate_der
                                ).hexdigest(),
                            )

                except (AttributeError, ValueError, ssl.SSLError):
                    certificate_result = _failure_with_deadline_precedence(
                        loop,
                        deadline,
                        FailureStage.CERTIFICATE,
                        FailureCode.TLS_FAILURE,
                    )

                await _close_stream(writer)

                if loop.time() >= deadline:
                    return TlsCollectionFailure(
                        stage=FailureStage.CERTIFICATE,
                        code=FailureCode.OVERALL_TIMEOUT,
                    )

                return certificate_result

            return _failure_with_deadline_precedence(
                loop,
                deadline,
                FailureStage.CONNECT,
                FailureCode.CONNECT_FAILURE,
            )
    except TimeoutError:
        return TlsCollectionFailure(
            stage=current_stage,
            code=FailureCode.OVERALL_TIMEOUT,
        )
