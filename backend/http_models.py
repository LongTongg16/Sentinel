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
    INVALID_STRICT_TRANSPORT_SECURITY = "invalid_strict_transport_security"
    STRICT_TRANSPORT_SECURITY_DISABLED = "strict_transport_security_disabled"
    STRICT_TRANSPORT_SECURITY_SHORT_MAX_AGE = (
        "strict_transport_security_short_max_age"
    )
    WEAK_CONTENT_SECURITY_POLICY = "weak_content_security_policy"
    INVALID_CONTENT_SECURITY_POLICY = "invalid_content_security_policy"
    FRAMING_NOT_PROTECTED = "framing_not_protected"
    UNSAFE_REFERRER_POLICY = "unsafe_referrer_policy"
    INVALID_REFERRER_POLICY = "invalid_referrer_policy"


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


# --- Control evaluation models -------------------------------------------
#
# These classifications go beyond "is the header present" to describe the
# actual configuration Sentinel observed. They are consumed by both
# backend.http_findings (to decide which findings to report) and
# backend.http_scoring (to decide how many points, if any, to deduct), so
# that both layers agree on a single definition of "good enough" per
# control. See backend.http_scoring for the point values associated with
# each classification and the external methodology each one mirrors.


class HstsClassification(str, Enum):
    """Strict-Transport-Security classification for a *present, non-empty*
    header. Missing/empty headers are represented directly by
    SecurityHeaderValue.present/value and are not given a variant here."""

    INVALID = "invalid"
    DISABLED = "disabled"
    SHORT_DURATION = "short_duration"
    ACCEPTABLE = "acceptable"
    STRONG = "strong"


@dataclass(frozen=True)
class HstsEvaluation:
    classification: HstsClassification
    max_age: int | None
    include_subdomains: bool


class CspClassification(str, Enum):
    """Content-Security-Policy classification for a *present, non-empty*
    header. Missing/empty headers are represented directly by
    SecurityHeaderValue.present/value and are not given a variant here."""

    INVALID = "invalid"
    WEAK = "weak"
    MEANINGFUL = "meaningful"


class CspWeakness(str, Enum):
    """Sub-reason for CspClassification.WEAK. Sentinel's public
    classification only distinguishes "weak" from "meaningful", but the
    two weak patterns below are tracked separately to support more
    specific classification, findings, and human-readable explanation
    (e.g. distinguishing an 'unsafe-eval'-only policy from one with
    unsafe/overly broad script sources). Content-Security-Policy does not
    contribute to Sentinel's numeric HTTP score at all (see
    backend.http_scoring._csp_deduction and its module docstring), so
    neither this distinction nor CspClassification itself carries or
    implies any score deduction -- both exist purely for classification,
    findings, and explanation.
    """

    UNSAFE_OR_BROAD_SOURCES = "unsafe_or_broad_sources"
    UNSAFE_EVAL_ONLY = "unsafe_eval_only"


@dataclass(frozen=True)
class CspEvaluation:
    classification: CspClassification
    weakness: CspWeakness | None


class FramingProtectionClassification(str, Enum):
    PROTECTED = "protected"
    NOT_PROTECTED = "not_protected"


@dataclass(frozen=True)
class FramingProtectionEvaluation:
    classification: FramingProtectionClassification
    via_csp_frame_ancestors: bool
    via_x_frame_options: bool


class ReferrerPolicyClassification(str, Enum):
    """Referrer-Policy classification for a *present, non-empty* header.
    Missing/empty headers are represented directly by
    SecurityHeaderValue.present/value and are not given a variant here."""

    INVALID = "invalid"
    UNSAFE = "unsafe"
    STRONG = "strong"


# --- Scoring models --------------------------------------------------------


@dataclass(frozen=True)
class HttpScoreDeduction:
    control: str
    points: int
    reason: str


@dataclass(frozen=True)
class HttpSecurityScore:
    score: int
    grade: str
    methodology: str
    deductions: tuple[HttpScoreDeduction, ...]
