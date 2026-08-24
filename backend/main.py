import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated, Literal, Protocol

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.deployment import DeploymentSettings
from backend.http_collector import (
    HttpCollectionResult,
    collect_http_security_headers,
)
from backend.http_findings import evaluate_http_header_findings
from backend.http_headers import normalize_security_headers
from backend.http_models import (
    HttpCollectionFailureCode,
    HttpCollectionStage,
    HttpHeaderCollectionFailure,
    HttpHeaderFindingCode,
    HttpSecurityScore,
    NormalizedSecurityHeaders,
    SecurityHeaderValue,
)
from backend.http_scoring import calculate_http_security_score
from backend.scan_admission import (
    ScanAdmissionController,
    ScanCapacityExceeded,
    ScanRateLimitExceeded,
)
from backend.tls_certificate import CertificateParseError, parse_leaf_certificate
from backend.tls_collector import CollectionResult, collect_verified_leaf
from backend.tls_findings import (
    calculate_days_remaining,
    evaluate_certificate_findings,
)
from backend.tls_models import (
    FailureCode,
    FailureStage,
    FindingCode,
    FindingSeverity,
    TlsCollectionFailure,
)


TLS_COLLECTION_OVERALL_TIMEOUT = 10.0
HTTP_HEADER_COLLECTION_OVERALL_TIMEOUT = 10.0

logger = logging.getLogger(__name__)
deployment_settings = DeploymentSettings.from_environment()


class TlsLeafCertificateRequest(BaseModel):
    hostname: str


class TlsLeafCertificateSuccess(BaseModel):
    status: Literal["success"] = "success"
    hostname: str
    connected_ip: str
    certificate_sha256: str
    subject: str
    issuer: str
    valid_from: datetime
    expires_at: datetime
    days_remaining: int
    dns_names: tuple[str, ...]
    serial_number: str
    signature_algorithm: str
    public_key_type: str
    public_key_size: int | None
    findings: tuple["CertificateFindingResponse", ...]


class CertificateFindingResponse(BaseModel):
    code: FindingCode
    severity: FindingSeverity
    message: str


class TlsLeafCertificateFailure(BaseModel):
    status: Literal["failure"] = "failure"
    stage: FailureStage
    code: FailureCode


TlsLeafCertificateResponse = Annotated[
    TlsLeafCertificateSuccess | TlsLeafCertificateFailure,
    Field(discriminator="status"),
]


class HttpSecurityHeadersRequest(BaseModel):
    hostname: str


class SecurityHeaderValueResponse(BaseModel):
    present: bool
    value: str | None


class NormalizedSecurityHeadersResponse(BaseModel):
    strict_transport_security: SecurityHeaderValueResponse
    content_security_policy: SecurityHeaderValueResponse
    x_content_type_options: SecurityHeaderValueResponse
    x_frame_options: SecurityHeaderValueResponse
    referrer_policy: SecurityHeaderValueResponse
    permissions_policy: SecurityHeaderValueResponse


class HttpHeaderFindingResponse(BaseModel):
    code: HttpHeaderFindingCode
    severity: FindingSeverity
    message: str


class HttpScoreDeductionResponse(BaseModel):
    control: str
    points: int
    reason: str


class HttpSecurityScoreResponse(BaseModel):
    score: int
    grade: str
    methodology: str
    deductions: tuple[HttpScoreDeductionResponse, ...]


class HttpSecurityHeadersSuccess(BaseModel):
    status: Literal["success"] = "success"
    requested_hostname: str
    connected_ip: str
    final_url: str
    final_hostname: str
    http_status_code: int
    redirect_count: int
    headers: NormalizedSecurityHeadersResponse
    findings: tuple[HttpHeaderFindingResponse, ...]
    score: HttpSecurityScoreResponse


class HttpSecurityHeadersFailure(BaseModel):
    status: Literal["failure"] = "failure"
    stage: HttpCollectionStage
    code: HttpCollectionFailureCode


HttpSecurityHeadersResponse = Annotated[
    HttpSecurityHeadersSuccess | HttpSecurityHeadersFailure,
    Field(discriminator="status"),
]


class TlsCollector(Protocol):
    async def __call__(
        self,
        hostname: str,
        *,
        overall_timeout: float,
    ) -> CollectionResult:
        ...


def get_tls_collector() -> TlsCollector:
    return collect_verified_leaf


class HttpHeaderCollector(Protocol):
    async def __call__(
        self,
        hostname: str,
        *,
        overall_timeout: float,
    ) -> HttpCollectionResult:
        ...


def get_http_header_collector() -> HttpHeaderCollector:
    return collect_http_security_headers


def get_current_time() -> datetime:
    return datetime.now(timezone.utc)


def get_scan_admission_controller(
    request: Request,
) -> ScanAdmissionController:
    return request.app.state.scan_admission_controller


async def admit_scan_request(
    controller: Annotated[
        ScanAdmissionController,
        Depends(get_scan_admission_controller),
    ],
) -> AsyncIterator[None]:
    try:
        controller.record_request()
    except ScanRateLimitExceeded as error:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "Scan request rate limit exceeded. Please try again later."
            ),
            headers={"Retry-After": str(error.retry_after_seconds)},
        ) from None

    try:
        async with controller.scan_slot():
            yield
    except ScanCapacityExceeded:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Scan capacity is temporarily unavailable. "
                "Please try again later."
            ),
        ) from None


FAILURE_HTTP_STATUS: dict[FailureCode, int] = {
    FailureCode.INVALID_HOSTNAME: status.HTTP_422_UNPROCESSABLE_CONTENT,
    FailureCode.BLOCKED_ADDRESS: status.HTTP_403_FORBIDDEN,
    FailureCode.DNS_FAILURE: status.HTTP_502_BAD_GATEWAY,
    FailureCode.NO_ADDRESSES: status.HTTP_502_BAD_GATEWAY,
    FailureCode.CONNECT_FAILURE: status.HTTP_502_BAD_GATEWAY,
    FailureCode.TLS_VERIFICATION_FAILED: status.HTTP_502_BAD_GATEWAY,
    FailureCode.TLS_FAILURE: status.HTTP_502_BAD_GATEWAY,
    FailureCode.MISSING_PEER_CERTIFICATE: status.HTTP_502_BAD_GATEWAY,
    FailureCode.CERTIFICATE_PARSE_FAILED: status.HTTP_502_BAD_GATEWAY,
    FailureCode.OVERALL_TIMEOUT: status.HTTP_504_GATEWAY_TIMEOUT,
}

HTTP_FAILURE_STATUS: dict[HttpCollectionFailureCode, int] = {
    HttpCollectionFailureCode.INVALID_HOSTNAME: (
        status.HTTP_422_UNPROCESSABLE_CONTENT
    ),
    HttpCollectionFailureCode.BLOCKED_ADDRESS: status.HTTP_403_FORBIDDEN,
    HttpCollectionFailureCode.BLOCKED_REDIRECT: status.HTTP_403_FORBIDDEN,
    HttpCollectionFailureCode.DNS_FAILURE: status.HTTP_502_BAD_GATEWAY,
    HttpCollectionFailureCode.NO_ADDRESSES: status.HTTP_502_BAD_GATEWAY,
    HttpCollectionFailureCode.CONNECTION_FAILURE: status.HTTP_502_BAD_GATEWAY,
    HttpCollectionFailureCode.TLS_VERIFICATION_FAILED: (
        status.HTTP_502_BAD_GATEWAY
    ),
    HttpCollectionFailureCode.TLS_FAILURE: status.HTTP_502_BAD_GATEWAY,
    HttpCollectionFailureCode.REQUEST_FAILURE: status.HTTP_502_BAD_GATEWAY,
    HttpCollectionFailureCode.MALFORMED_RESPONSE: status.HTTP_502_BAD_GATEWAY,
    HttpCollectionFailureCode.INVALID_REDIRECT: status.HTTP_502_BAD_GATEWAY,
    HttpCollectionFailureCode.UNSUPPORTED_REDIRECT_SCHEME: (
        status.HTTP_502_BAD_GATEWAY
    ),
    HttpCollectionFailureCode.TOO_MANY_REDIRECTS: status.HTTP_502_BAD_GATEWAY,
    HttpCollectionFailureCode.REDIRECT_LOOP: status.HTTP_502_BAD_GATEWAY,
    HttpCollectionFailureCode.OVERALL_TIMEOUT: status.HTTP_504_GATEWAY_TIMEOUT,
}


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    application.state.scan_admission_controller = ScanAdmissionController(
        max_concurrent_scans=deployment_settings.max_concurrent_scans,
        scan_queue_timeout_seconds=(
            deployment_settings.scan_queue_timeout_seconds
        ),
        rate_limit_requests=deployment_settings.rate_limit_requests,
        rate_limit_window_seconds=(
            deployment_settings.rate_limit_window_seconds
        ),
    )
    logger.info(
        (
            "Configured scan admission with concurrency=%d, "
            "queue_timeout=%.2fs, and rate=%d/%ds"
        ),
        deployment_settings.max_concurrent_scans,
        deployment_settings.scan_queue_timeout_seconds,
        deployment_settings.rate_limit_requests,
        deployment_settings.rate_limit_window_seconds,
    )
    yield


app = FastAPI(title="Sentinel Security API", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(deployment_settings.allowed_origins),
    allow_credentials=False,
    allow_methods=["POST"],
    allow_headers=["Content-Type"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def root() -> dict[str, str]:
    return {"status": "API is running"}


@app.post(
    "/api/v1/tls/leaf-certificate",
    response_model=TlsLeafCertificateResponse,
)
async def collect_tls_leaf_certificate(
    request: TlsLeafCertificateRequest,
    response: Response,
    _admission: Annotated[None, Depends(admit_scan_request)],
    collector: Annotated[TlsCollector, Depends(get_tls_collector)],
    current_time: Annotated[datetime, Depends(get_current_time)],
) -> TlsLeafCertificateResponse:
    result = await collector(
        request.hostname,
        overall_timeout=TLS_COLLECTION_OVERALL_TIMEOUT,
    )

    if isinstance(result, TlsCollectionFailure):
        response.status_code = FAILURE_HTTP_STATUS[result.code]
        return TlsLeafCertificateFailure(
            stage=result.stage,
            code=result.code,
        )

    try:
        certificate = parse_leaf_certificate(result.certificate_der)
    except CertificateParseError:
        response.status_code = status.HTTP_502_BAD_GATEWAY
        return TlsLeafCertificateFailure(
            stage=FailureStage.CERTIFICATE,
            code=FailureCode.CERTIFICATE_PARSE_FAILED,
        )

    findings = evaluate_certificate_findings(
        certificate,
        hostname=result.target.hostname,
        now=current_time,
    )

    return TlsLeafCertificateSuccess(
        hostname=result.target.hostname,
        connected_ip=str(result.connected_ip),
        certificate_sha256=result.certificate_sha256,
        subject=certificate.subject,
        issuer=certificate.issuer,
        valid_from=certificate.valid_from,
        expires_at=certificate.expires_at,
        days_remaining=calculate_days_remaining(
            certificate.expires_at,
            now=current_time,
        ),
        dns_names=certificate.dns_names,
        serial_number=certificate.serial_number,
        signature_algorithm=certificate.signature_algorithm,
        public_key_type=certificate.public_key_type,
        public_key_size=certificate.public_key_size,
        findings=tuple(
            CertificateFindingResponse(
                code=finding.code,
                severity=finding.severity,
                message=finding.message,
            )
            for finding in findings
        ),
    )


def _header_value_response(
    header: SecurityHeaderValue,
) -> SecurityHeaderValueResponse:
    return SecurityHeaderValueResponse(
        present=header.present,
        value=header.value,
    )


def _headers_response(
    headers: NormalizedSecurityHeaders,
) -> NormalizedSecurityHeadersResponse:
    return NormalizedSecurityHeadersResponse(
        strict_transport_security=_header_value_response(
            headers.strict_transport_security
        ),
        content_security_policy=_header_value_response(
            headers.content_security_policy
        ),
        x_content_type_options=_header_value_response(
            headers.x_content_type_options
        ),
        x_frame_options=_header_value_response(headers.x_frame_options),
        referrer_policy=_header_value_response(headers.referrer_policy),
        permissions_policy=_header_value_response(headers.permissions_policy),
    )


def _score_response(score: HttpSecurityScore) -> HttpSecurityScoreResponse:
    return HttpSecurityScoreResponse(
        score=score.score,
        grade=score.grade,
        methodology=score.methodology,
        deductions=tuple(
            HttpScoreDeductionResponse(
                control=deduction.control,
                points=deduction.points,
                reason=deduction.reason,
            )
            for deduction in score.deductions
        ),
    )


@app.post(
    "/api/v1/http/security-headers",
    response_model=HttpSecurityHeadersResponse,
)
async def collect_http_headers(
    request: HttpSecurityHeadersRequest,
    response: Response,
    _admission: Annotated[None, Depends(admit_scan_request)],
    collector: Annotated[
        HttpHeaderCollector,
        Depends(get_http_header_collector),
    ],
) -> HttpSecurityHeadersResponse:
    result = await collector(
        request.hostname,
        overall_timeout=HTTP_HEADER_COLLECTION_OVERALL_TIMEOUT,
    )

    if isinstance(result, HttpHeaderCollectionFailure):
        response.status_code = HTTP_FAILURE_STATUS[result.code]
        return HttpSecurityHeadersFailure(
            stage=result.stage,
            code=result.code,
        )

    normalized_headers = normalize_security_headers(result.headers)
    findings = evaluate_http_header_findings(normalized_headers)
    score = calculate_http_security_score(normalized_headers)

    return HttpSecurityHeadersSuccess(
        requested_hostname=result.requested_hostname,
        connected_ip=str(result.connected_ip),
        final_url=result.final_url,
        final_hostname=result.final_hostname,
        http_status_code=result.http_status_code,
        redirect_count=result.redirect_count,
        headers=_headers_response(normalized_headers),
        findings=tuple(
            HttpHeaderFindingResponse(
                code=finding.code,
                severity=finding.severity,
                message=finding.message,
            )
            for finding in findings
        ),
        score=_score_response(score),
    )
