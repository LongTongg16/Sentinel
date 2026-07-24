from datetime import datetime, timezone
from typing import Annotated, Literal, Protocol

from fastapi import Depends, FastAPI, Response, status
from pydantic import BaseModel, Field

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


def get_current_time() -> datetime:
    return datetime.now(timezone.utc)


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

app = FastAPI(title="Sentinel Security API")


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
