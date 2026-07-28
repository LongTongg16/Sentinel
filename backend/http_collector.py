import asyncio
import re
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urljoin, urlsplit, urlunsplit

from backend.http_models import (
    HttpCollectionFailureCode,
    HttpCollectionStage,
    HttpHeaderCollectionFailure,
    HttpResponseObservation,
)
from backend.tls_collector import (
    AsyncioTcpConnector,
    TcpConnector,
    create_default_ssl_context,
)
from backend.tls_models import ApprovedAddress, ApprovedTarget, ValidatedTarget
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


DEFAULT_MAX_REDIRECTS = 3
DEFAULT_MAX_ADDRESS_ATTEMPTS = 3
DEFAULT_MAX_HEADER_BYTES = 64 * 1024
MAX_REDIRECT_URL_LENGTH = 2048

_REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
_STATUS_LINE = re.compile(r"^HTTP/1\.[01] ([0-9]{3})(?:[ \t].*)?$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


@dataclass(frozen=True)
class RawHttpResponse:
    status_code: int
    headers: tuple[tuple[str, str], ...]


HttpCollectionResult = HttpResponseObservation | HttpHeaderCollectionFailure


class HttpConnectError(OSError):
    pass


class HttpTlsVerificationError(ssl.SSLError):
    pass


class HttpTlsError(ssl.SSLError):
    pass


class HttpRequestError(OSError):
    pass


class MalformedHttpResponseError(ValueError):
    pass


class InvalidRedirectError(ValueError):
    pass


class UnsupportedRedirectSchemeError(ValueError):
    pass


class HttpOperationTimeout(TimeoutError):
    def __init__(self, stage: HttpCollectionStage) -> None:
        super().__init__(stage.value)
        self.stage = stage


class StreamReaderLike(Protocol):
    async def readuntil(self, separator: bytes) -> bytes:
        ...


class StreamWriterLike(Protocol):
    def write(self, data: bytes) -> None:
        ...

    async def drain(self) -> None:
        ...

    def close(self) -> None:
        ...

    async def wait_closed(self) -> None:
        ...


class HttpHeaderTransport(Protocol):
    async def request(
        self,
        address: ApprovedAddress,
        target: ValidatedTarget,
        request_target: str,
        *,
        deadline: float,
        max_header_bytes: int,
    ) -> RawHttpResponse:
        ...


def _parse_response_headers(
    response_bytes: bytes,
    *,
    max_header_bytes: int,
) -> RawHttpResponse:
    if len(response_bytes) > max_header_bytes:
        raise MalformedHttpResponseError("response headers exceeded the limit")

    header_block, separator, _unused_body = response_bytes.partition(
        b"\r\n\r\n"
    )
    if not separator:
        raise MalformedHttpResponseError("response headers were incomplete")

    try:
        lines = header_block.decode("iso-8859-1").split("\r\n")
    except UnicodeError as error:
        raise MalformedHttpResponseError(
            "response headers could not be decoded"
        ) from error

    if not lines:
        raise MalformedHttpResponseError("response status line was missing")

    status_match = _STATUS_LINE.fullmatch(lines[0])
    if status_match is None:
        raise MalformedHttpResponseError("response status line was malformed")

    status_code = int(status_match.group(1))
    if status_code < 200 or status_code > 599:
        raise MalformedHttpResponseError("response status code was unsupported")

    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line or line[0] in " \t" or ":" not in line:
            raise MalformedHttpResponseError("response header line was malformed")
        name, value = line.split(":", 1)
        if _HEADER_NAME.fullmatch(name) is None:
            raise MalformedHttpResponseError("response header name was malformed")
        if any(
            ord(character) < 32 and character != "\t" or ord(character) == 127
            for character in value
        ):
            raise MalformedHttpResponseError(
                "response header value contained a control character"
            )
        headers.append((name, value.strip(" \t")))

    return RawHttpResponse(status_code=status_code, headers=tuple(headers))


async def _close_writer(
    writer: StreamWriterLike,
    *,
    deadline: float,
) -> None:
    writer.close()
    try:
        async with asyncio.timeout_at(deadline):
            await writer.wait_closed()
    except (TimeoutError, OSError, ssl.SSLError):
        pass


class HttpsHeaderTransport:
    def __init__(
        self,
        *,
        connector: TcpConnector | None = None,
        context_factory: Callable[[], ssl.SSLContext] = create_default_ssl_context,
    ) -> None:
        self._connector = connector or AsyncioTcpConnector()
        self._context_factory = context_factory

    async def request(
        self,
        address: ApprovedAddress,
        target: ValidatedTarget,
        request_target: str,
        *,
        deadline: float,
        max_header_bytes: int,
    ) -> RawHttpResponse:
        try:
            encoded_request_target = request_target.encode("ascii")
        except UnicodeEncodeError as error:
            raise HttpRequestError("request target must be ASCII") from error
        if b"\r" in encoded_request_target or b"\n" in encoded_request_target:
            raise HttpRequestError("request target contained a line break")

        try:
            async with asyncio.timeout_at(deadline):
                raw_socket = await self._connector.connect(
                    address,
                    deadline=deadline,
                )
        except TimeoutError as error:
            raise HttpOperationTimeout(HttpCollectionStage.CONNECT) from error
        except OSError as error:
            raise HttpConnectError("connection failed") from error

        try:
            ssl_context = self._context_factory()
            if not isinstance(ssl_context, ssl.SSLContext):
                raise TypeError("context factory did not return an SSLContext")
        except BaseException as error:
            raw_socket.close()
            if isinstance(error, Exception):
                raise HttpTlsError("TLS context creation failed") from error
            raise

        try:
            async with asyncio.timeout_at(deadline):
                reader, writer = await asyncio.open_connection(
                    sock=raw_socket,
                    ssl=ssl_context,
                    server_hostname=target.hostname,
                    ssl_handshake_timeout=max(
                        deadline - asyncio.get_running_loop().time(),
                        0.001,
                    ),
                    ssl_shutdown_timeout=max(
                        deadline - asyncio.get_running_loop().time(),
                        0.001,
                    ),
                    limit=max_header_bytes + 1,
                )
        except TimeoutError as error:
            raise HttpOperationTimeout(
                HttpCollectionStage.TLS_HANDSHAKE
            ) from error
        except ssl.SSLCertVerificationError as error:
            raise HttpTlsVerificationError(
                "TLS certificate verification failed"
            ) from error
        except (OSError, ssl.SSLError) as error:
            raise HttpTlsError("TLS handshake failed") from error

        public_reader: StreamReaderLike = reader
        public_writer: StreamWriterLike = writer
        request_bytes = (
            b"GET "
            + encoded_request_target
            + b" HTTP/1.1\r\n"
            + f"Host: {target.hostname}\r\n".encode("ascii")
            + b"User-Agent: Sentinel/1.0\r\n"
            + b"Accept: */*\r\n"
            + b"Connection: close\r\n\r\n"
        )

        try:
            try:
                public_writer.write(request_bytes)
                async with asyncio.timeout_at(deadline):
                    await public_writer.drain()
            except TimeoutError as error:
                raise HttpOperationTimeout(
                    HttpCollectionStage.REQUEST
                ) from error
            except (OSError, ssl.SSLError) as error:
                raise HttpRequestError("request write failed") from error

            try:
                async with asyncio.timeout_at(deadline):
                    response_bytes = await public_reader.readuntil(
                        b"\r\n\r\n"
                    )
            except TimeoutError as error:
                raise HttpOperationTimeout(
                    HttpCollectionStage.RESPONSE
                ) from error
            except (
                asyncio.IncompleteReadError,
                asyncio.LimitOverrunError,
            ) as error:
                raise MalformedHttpResponseError(
                    "response headers were incomplete or oversized"
                ) from error
            except (OSError, ssl.SSLError) as error:
                raise HttpRequestError("response read failed") from error

            return _parse_response_headers(
                response_bytes,
                max_header_bytes=max_header_bytes,
            )
        finally:
            await _close_writer(public_writer, deadline=deadline)


def _redirect_location(response: RawHttpResponse) -> str:
    values = [
        value
        for name, value in response.headers
        if name.casefold() == "location"
    ]
    if len(values) != 1 or not values[0].strip():
        raise InvalidRedirectError(
            "redirect response must contain one Location header"
        )
    return values[0].strip()


def _redirect_target(
    current_url: str,
    location: str,
) -> tuple[str, ValidatedTarget, str]:
    if len(location) > MAX_REDIRECT_URL_LENGTH or any(
        ord(character) < 32 or ord(character) == 127 for character in location
    ):
        raise InvalidRedirectError("redirect location was invalid")

    destination = urljoin(current_url, location)
    if len(destination) > MAX_REDIRECT_URL_LENGTH:
        raise InvalidRedirectError("redirect URL exceeded the limit")

    try:
        parsed = urlsplit(destination)
        scheme = parsed.scheme.casefold()
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise InvalidRedirectError("redirect URL could not be parsed") from error

    if scheme != "https":
        raise UnsupportedRedirectSchemeError(
            "only HTTPS redirect destinations are supported"
        )
    if parsed.username is not None or parsed.password is not None:
        raise InvalidRedirectError("redirect credentials are not supported")
    if hostname is None:
        raise InvalidRedirectError("redirect hostname was missing")
    if port not in (None, 443) or parsed.netloc.endswith(":"):
        raise InvalidRedirectError("redirect port is not supported")

    try:
        target = validate_target(hostname)
    except InvalidTargetError as error:
        raise InvalidRedirectError("redirect hostname was invalid") from error

    path = parsed.path or "/"
    if not path.startswith("/"):
        raise InvalidRedirectError("redirect path was invalid")
    request_target = path
    if parsed.query:
        request_target = f"{request_target}?{parsed.query}"

    try:
        request_target.encode("ascii")
    except UnicodeEncodeError as error:
        raise InvalidRedirectError("redirect target must be ASCII") from error
    if any(
        character in request_target
        for character in ("\r", "\n", "\x00", " ")
    ):
        raise InvalidRedirectError("redirect target contained unsafe characters")

    normalized_url = urlunsplit(
        ("https", target.hostname, path, parsed.query, "")
    )
    return normalized_url, target, request_target


def _failure(
    stage: HttpCollectionStage,
    code: HttpCollectionFailureCode,
) -> HttpHeaderCollectionFailure:
    return HttpHeaderCollectionFailure(stage=stage, code=code)


async def _resolve_and_approve(
    target: ValidatedTarget,
    *,
    resolver: Resolver,
    deadline: float,
    redirect: bool,
) -> ApprovedTarget | HttpHeaderCollectionFailure:
    try:
        async with asyncio.timeout_at(deadline):
            records = await resolver.resolve(target)
    except TimeoutError:
        return _failure(
            HttpCollectionStage.DNS,
            HttpCollectionFailureCode.OVERALL_TIMEOUT,
        )
    except (socket.gaierror, OSError):
        return _failure(
            HttpCollectionStage.REDIRECT if redirect else HttpCollectionStage.DNS,
            HttpCollectionFailureCode.DNS_FAILURE,
        )

    try:
        return approve_resolved_addresses(target, records)
    except BlockedAddressError:
        return _failure(
            HttpCollectionStage.REDIRECT if redirect else HttpCollectionStage.DNS,
            (
                HttpCollectionFailureCode.BLOCKED_REDIRECT
                if redirect
                else HttpCollectionFailureCode.BLOCKED_ADDRESS
            ),
        )
    except NoAddressesError:
        return _failure(
            HttpCollectionStage.REDIRECT if redirect else HttpCollectionStage.DNS,
            HttpCollectionFailureCode.NO_ADDRESSES,
        )
    except InvalidAddressRecordError:
        return _failure(
            HttpCollectionStage.REDIRECT if redirect else HttpCollectionStage.DNS,
            HttpCollectionFailureCode.DNS_FAILURE,
        )


async def collect_http_security_headers(
    hostname: str,
    *,
    overall_timeout: float,
    resolver: Resolver | None = None,
    transport: HttpHeaderTransport | None = None,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    max_address_attempts: int = DEFAULT_MAX_ADDRESS_ATTEMPTS,
    max_header_bytes: int = DEFAULT_MAX_HEADER_BYTES,
) -> HttpCollectionResult:
    if max_redirects < 0:
        raise ValueError("max_redirects cannot be negative")
    if max_address_attempts < 1:
        raise ValueError("max_address_attempts must be at least 1")
    if max_header_bytes < 1:
        raise ValueError("max_header_bytes must be at least 1")

    try:
        target = validate_target(hostname)
    except InvalidTargetError:
        return _failure(
            HttpCollectionStage.TARGET_VALIDATION,
            HttpCollectionFailureCode.INVALID_HOSTNAME,
        )

    selected_resolver = resolver or SystemResolver()
    selected_transport = transport or HttpsHeaderTransport()
    loop = asyncio.get_running_loop()
    deadline = loop.time() + overall_timeout
    requested_hostname = target.hostname
    current_url = f"https://{target.hostname}/"
    request_target = "/"
    redirect_count = 0
    seen_urls = {current_url}

    while True:
        approved_target = await _resolve_and_approve(
            target,
            resolver=selected_resolver,
            deadline=deadline,
            redirect=redirect_count > 0,
        )
        if isinstance(approved_target, HttpHeaderCollectionFailure):
            return approved_target

        raw_response: RawHttpResponse | None = None
        connected_address: ApprovedAddress | None = None
        for address in approved_target.addresses[:max_address_attempts]:
            try:
                raw_response = await selected_transport.request(
                    address,
                    target,
                    request_target,
                    deadline=deadline,
                    max_header_bytes=max_header_bytes,
                )
            except HttpOperationTimeout as error:
                return _failure(
                    error.stage,
                    HttpCollectionFailureCode.OVERALL_TIMEOUT,
                )
            except HttpConnectError:
                continue
            except HttpTlsVerificationError:
                return _failure(
                    HttpCollectionStage.TLS_HANDSHAKE,
                    HttpCollectionFailureCode.TLS_VERIFICATION_FAILED,
                )
            except HttpTlsError:
                return _failure(
                    HttpCollectionStage.TLS_HANDSHAKE,
                    HttpCollectionFailureCode.TLS_FAILURE,
                )
            except HttpRequestError:
                return _failure(
                    HttpCollectionStage.REQUEST,
                    HttpCollectionFailureCode.REQUEST_FAILURE,
                )
            except MalformedHttpResponseError:
                return _failure(
                    HttpCollectionStage.RESPONSE,
                    HttpCollectionFailureCode.MALFORMED_RESPONSE,
                )
            except TimeoutError:
                return _failure(
                    HttpCollectionStage.RESPONSE,
                    HttpCollectionFailureCode.OVERALL_TIMEOUT,
                )
            connected_address = address
            break

        if raw_response is None or connected_address is None:
            return _failure(
                HttpCollectionStage.CONNECT,
                HttpCollectionFailureCode.CONNECTION_FAILURE,
            )

        if raw_response.status_code not in _REDIRECT_STATUS_CODES:
            return HttpResponseObservation(
                requested_hostname=requested_hostname,
                connected_ip=connected_address.ip,
                final_url=current_url,
                final_hostname=target.hostname,
                http_status_code=raw_response.status_code,
                headers=raw_response.headers,
                redirect_count=redirect_count,
            )

        if redirect_count >= max_redirects:
            return _failure(
                HttpCollectionStage.REDIRECT,
                HttpCollectionFailureCode.TOO_MANY_REDIRECTS,
            )

        try:
            location = _redirect_location(raw_response)
            next_url, next_target, next_request_target = _redirect_target(
                current_url,
                location,
            )
        except UnsupportedRedirectSchemeError:
            return _failure(
                HttpCollectionStage.REDIRECT,
                HttpCollectionFailureCode.UNSUPPORTED_REDIRECT_SCHEME,
            )
        except InvalidRedirectError:
            return _failure(
                HttpCollectionStage.REDIRECT,
                HttpCollectionFailureCode.INVALID_REDIRECT,
            )

        if next_url in seen_urls:
            return _failure(
                HttpCollectionStage.REDIRECT,
                HttpCollectionFailureCode.REDIRECT_LOOP,
            )

        seen_urls.add(next_url)
        current_url = next_url
        target = next_target
        request_target = next_request_target
        redirect_count += 1
