from datetime import datetime, timedelta, timezone

import pytest

from backend.tls_findings import (
    calculate_days_remaining,
    evaluate_certificate_findings,
)
from backend.tls_models import (
    CertificateFinding,
    FindingCode,
    FindingSeverity,
    ParsedCertificate,
)


NOW = datetime(2026, 7, 24, tzinfo=timezone.utc)

EXPIRED_FINDING = CertificateFinding(
    code=FindingCode.CERTIFICATE_EXPIRED,
    severity=FindingSeverity.CRITICAL,
    message="The certificate is expired.",
)
SEVEN_DAY_FINDING = CertificateFinding(
    code=FindingCode.EXPIRES_WITHIN_7_DAYS,
    severity=FindingSeverity.WARNING,
    message="The certificate expires in fewer than 7 days.",
)
THIRTY_DAY_FINDING = CertificateFinding(
    code=FindingCode.EXPIRES_WITHIN_30_DAYS,
    severity=FindingSeverity.WARNING,
    message="The certificate expires in fewer than 30 days.",
)
NO_DNS_SANS_FINDING = CertificateFinding(
    code=FindingCode.NO_DNS_SANS,
    severity=FindingSeverity.WARNING,
    message="The certificate does not contain any DNS subject alternative names.",
)
WEAK_SIGNATURE_FINDING = CertificateFinding(
    code=FindingCode.WEAK_SIGNATURE_ALGORITHM,
    severity=FindingSeverity.WARNING,
    message="The certificate uses a weak signature algorithm.",
)
HEALTHY_FINDING = CertificateFinding(
    code=FindingCode.HEALTHY_CERTIFICATE,
    severity=FindingSeverity.INFO,
    message="The certificate passed the configured certificate health checks.",
)


def certificate(
    *,
    expires_at: datetime = NOW + timedelta(days=30),
    dns_names: tuple[str, ...] = ("example.com",),
    signature_algorithm: str = "sha256",
) -> ParsedCertificate:
    return ParsedCertificate(
        subject="CN=example.com",
        issuer="CN=Sentinel Test CA",
        valid_from=NOW - timedelta(days=30),
        expires_at=expires_at,
        dns_names=dns_names,
        serial_number="1234",
        signature_algorithm=signature_algorithm,
        public_key_type="rsa",
        public_key_size=2048,
    )


def findings_for(
    parsed_certificate: ParsedCertificate,
    *,
    now: datetime = NOW,
) -> tuple[CertificateFinding, ...]:
    return evaluate_certificate_findings(
        parsed_certificate,
        hostname="example.com",
        now=now,
    )


def test_certificate_expired_before_now() -> None:
    assert findings_for(
        certificate(expires_at=NOW - timedelta(microseconds=1))
    ) == (EXPIRED_FINDING,)


def test_certificate_expiring_exactly_at_now_is_expired() -> None:
    assert findings_for(certificate(expires_at=NOW)) == (EXPIRED_FINDING,)


def test_certificate_expiring_in_fewer_than_seven_days() -> None:
    assert findings_for(
        certificate(expires_at=NOW + timedelta(days=6, hours=23))
    ) == (SEVEN_DAY_FINDING,)


def test_certificate_expiring_in_exactly_seven_days_uses_thirty_day_warning() -> None:
    assert findings_for(
        certificate(expires_at=NOW + timedelta(days=7))
    ) == (THIRTY_DAY_FINDING,)


def test_certificate_expiring_in_fewer_than_thirty_days() -> None:
    assert findings_for(
        certificate(expires_at=NOW + timedelta(days=29, hours=23))
    ) == (THIRTY_DAY_FINDING,)


def test_certificate_expiring_in_exactly_thirty_days_has_no_expiry_warning() -> None:
    assert findings_for(
        certificate(expires_at=NOW + timedelta(days=30))
    ) == (HEALTHY_FINDING,)


def test_no_dns_sans_generates_warning() -> None:
    assert findings_for(certificate(dns_names=())) == (NO_DNS_SANS_FINDING,)


@pytest.mark.parametrize("signature_algorithm", ["sha1", "SHA-1", "md5", "MD5"])
def test_weak_signature_algorithms_generate_warning(
    signature_algorithm: str,
) -> None:
    assert findings_for(
        certificate(signature_algorithm=signature_algorithm)
    ) == (WEAK_SIGNATURE_FINDING,)


def test_sha256_signature_is_not_weak() -> None:
    assert findings_for(certificate(signature_algorithm="sha256")) == (
        HEALTHY_FINDING,
    )


def test_healthy_certificate_has_info_finding() -> None:
    assert findings_for(certificate()) == (HEALTHY_FINDING,)


def test_healthy_finding_is_omitted_when_warning_exists() -> None:
    result = findings_for(certificate(dns_names=()))

    assert HEALTHY_FINDING not in result


def test_naive_now_is_rejected() -> None:
    with pytest.raises(ValueError, match="now must be timezone-aware"):
        findings_for(certificate(), now=NOW.replace(tzinfo=None))


def test_naive_expires_at_is_rejected() -> None:
    with pytest.raises(ValueError, match="expires_at must be timezone-aware"):
        calculate_days_remaining(
            NOW.replace(tzinfo=None),
            now=NOW,
        )


def test_findings_have_stable_order_and_exact_messages() -> None:
    result = findings_for(
        certificate(
            expires_at=NOW,
            dns_names=(),
            signature_algorithm="sha1",
        )
    )

    assert result == (
        EXPIRED_FINDING,
        NO_DNS_SANS_FINDING,
        WEAK_SIGNATURE_FINDING,
    )
