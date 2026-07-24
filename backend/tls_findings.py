from datetime import datetime, timedelta

from backend.tls_models import (
    CertificateFinding,
    FindingCode,
    FindingSeverity,
    ParsedCertificate,
)


_WEAK_SIGNATURE_ALGORITHMS = {
    "md5",
    "md5withrsaencryption",
    "rsawithmd5",
    "rsawithsha1",
    "sha1",
    "sha1withrsaencryption",
}


def _require_timezone_aware(value: datetime, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


def _normalized_algorithm_name(value: str) -> str:
    return "".join(character for character in value.lower() if character.isalnum())


def calculate_days_remaining(
    expires_at: datetime,
    *,
    now: datetime,
) -> int:
    _require_timezone_aware(expires_at, "expires_at")
    _require_timezone_aware(now, "now")
    return (expires_at - now).days


def evaluate_certificate_findings(
    certificate: ParsedCertificate,
    *,
    hostname: str,
    now: datetime,
) -> tuple[CertificateFinding, ...]:
    del hostname
    _require_timezone_aware(now, "now")
    _require_timezone_aware(certificate.expires_at, "expires_at")

    findings: list[CertificateFinding] = []

    if certificate.expires_at <= now:
        findings.append(
            CertificateFinding(
                code=FindingCode.CERTIFICATE_EXPIRED,
                severity=FindingSeverity.CRITICAL,
                message="The certificate is expired.",
            )
        )
    elif certificate.expires_at < now + timedelta(days=7):
        findings.append(
            CertificateFinding(
                code=FindingCode.EXPIRES_WITHIN_7_DAYS,
                severity=FindingSeverity.WARNING,
                message="The certificate expires in fewer than 7 days.",
            )
        )
    elif certificate.expires_at < now + timedelta(days=30):
        findings.append(
            CertificateFinding(
                code=FindingCode.EXPIRES_WITHIN_30_DAYS,
                severity=FindingSeverity.WARNING,
                message="The certificate expires in fewer than 30 days.",
            )
        )

    if not certificate.dns_names:
        findings.append(
            CertificateFinding(
                code=FindingCode.NO_DNS_SANS,
                severity=FindingSeverity.WARNING,
                message=(
                    "The certificate does not contain any DNS subject "
                    "alternative names."
                ),
            )
        )

    normalized_signature_algorithm = _normalized_algorithm_name(
        certificate.signature_algorithm
    )
    if normalized_signature_algorithm in _WEAK_SIGNATURE_ALGORITHMS:
        findings.append(
            CertificateFinding(
                code=FindingCode.WEAK_SIGNATURE_ALGORITHM,
                severity=FindingSeverity.WARNING,
                message="The certificate uses a weak signature algorithm.",
            )
        )

    if not findings:
        findings.append(
            CertificateFinding(
                code=FindingCode.HEALTHY_CERTIFICATE,
                severity=FindingSeverity.INFO,
                message=(
                    "The certificate passed the configured certificate "
                    "health checks."
                ),
            )
        )

    return tuple(findings)
