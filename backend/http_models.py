from dataclasses import dataclass
from enum import Enum

from backend.tls_models import FindingSeverity, IPAddress


@dataclass(frozen=True)
class SecurityHeaderValue:
    present: bool
    value: str | None


@dataclass(frozen=True)
class NormalizedSecurityHeaders:
    strict_transport_security: SecurityHeaderValue
    content_security_policy: SecurityHeaderValue
    x_content_type_options: SecurityHeaderValue
    x_frame_options: SecurityHeaderValue
    referrer_policy: SecurityHeaderValue
    permissions_policy: SecurityHeaderValue


class HttpHeaderFindingCode(str, Enum):
    MISSING_STRICT_TRANSPORT_SECURITY = "missing_strict_transport_security"
    MISSING_CONTENT_SECURITY_POLICY = "missing_content_security_policy"
    MISSING_X_CONTENT_TYPE_OPTIONS = "missing_x_content_type_options"
    MISSING_X_FRAME_OPTIONS = "missing_x_frame_options"
    MISSING_REFERRER_POLICY = "missing_referrer_policy"
    MISSING_PERMISSIONS_POLICY = "missing_permissions_policy"
    EMPTY_STRICT_TRANSPORT_SECURITY = "empty_strict_transport_security"
    EMPTY_CONTENT_SECURITY_POLICY = "empty_content_security_policy"
    EMPTY_X_CONTENT_TYPE_OPTIONS = "empty_x_content_type_options"
    EMPTY_X_FRAME_OPTIONS = "empty_x_frame_options"
    EMPTY_REFERRER_POLICY = "empty_referrer_policy"
    EMPTY_PERMISSIONS_POLICY = "empty_permissions_policy"
    INVALID_X_CONTENT_TYPE_OPTIONS = "invalid_x_content_type_options"
    INVALID_X_FRAME_OPTIONS = "invalid_x_frame_options"


@dataclass(frozen=True)
class HttpHeaderFinding:
    code: HttpHeaderFindingCode
    severity: FindingSeverity
    message: str


@dataclass(frozen=True)
class HttpResponseObservation:
    requested_hostname: str
    connected_ip: IPAddress
    final_url: str
    final_hostname: str
    http_status_code: int
    headers: tuple[tuple[str, str], ...]
    redirect_count: int


class HttpCollectionStage(str, Enum):
    TARGET_VALIDATION = "target_validation"
    DNS = "dns"
    CONNECT = "connect"
    TLS_HANDSHAKE = "tls_handshake"
    REQUEST = "request"
    RESPONSE = "response"
    REDIRECT = "redirect"


class HttpCollectionFailureCode(str, Enum):
    INVALID_HOSTNAME = "invalid_hostname"
    DNS_FAILURE = "dns_failure"
    NO_ADDRESSES = "no_addresses"
    BLOCKED_ADDRESS = "blocked_address"
    BLOCKED_REDIRECT = "blocked_redirect"
    CONNECTION_FAILURE = "connection_failure"
    TLS_VERIFICATION_FAILED = "tls_verification_failed"
    TLS_FAILURE = "tls_failure"
    REQUEST_FAILURE = "request_failure"
    MALFORMED_RESPONSE = "malformed_response"
    INVALID_REDIRECT = "invalid_redirect"
    UNSUPPORTED_REDIRECT_SCHEME = "unsupported_redirect_scheme"
    TOO_MANY_REDIRECTS = "too_many_redirects"
    REDIRECT_LOOP = "redirect_loop"
    OVERALL_TIMEOUT = "overall_timeout"


@dataclass(frozen=True)
class HttpHeaderCollectionFailure:
    stage: HttpCollectionStage
    code: HttpCollectionFailureCode
