from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import hashes

from backend.tests.fixtures.certificate_factory import create_certificate_der
from backend.tls_certificate import CertificateParseError, parse_leaf_certificate


VALID_FROM = datetime(2026, 7, 1, tzinfo=timezone.utc)
EXPIRES_AT = datetime(2026, 8, 31, tzinfo=timezone.utc)


def test_parse_leaf_certificate_normalizes_certificate_fields() -> None:
    certificate_der = create_certificate_der(
        subject_common_name="service.example.com",
        issuer_common_name="Sentinel Test CA",
        valid_from=VALID_FROM,
        expires_at=EXPIRES_AT,
        dns_names=("service.example.com", "www.example.com"),
        signature_hash_algorithm=hashes.SHA256(),
        serial_number=0x1234ABCD,
    )

    parsed = parse_leaf_certificate(certificate_der)

    assert parsed.subject == "CN=service.example.com"
    assert parsed.issuer == "CN=Sentinel Test CA"
    assert parsed.valid_from == VALID_FROM
    assert parsed.expires_at == EXPIRES_AT
    assert parsed.valid_from.tzinfo is timezone.utc
    assert parsed.expires_at.tzinfo is timezone.utc
    assert parsed.dns_names == (
        "service.example.com",
        "www.example.com",
    )
    assert parsed.serial_number == "1234abcd"
    assert parsed.signature_algorithm == "sha256"
    assert parsed.public_key_type == "rsa"
    assert parsed.public_key_size == 2048


def test_parse_leaf_certificate_returns_empty_tuple_without_san() -> None:
    certificate_der = create_certificate_der(
        valid_from=VALID_FROM,
        expires_at=EXPIRES_AT,
        dns_names=None,
    )

    parsed = parse_leaf_certificate(certificate_der)

    assert parsed.dns_names == ()


def test_parse_leaf_certificate_identifies_ec_public_key() -> None:
    certificate_der = create_certificate_der(
        valid_from=VALID_FROM,
        expires_at=EXPIRES_AT,
        key_type="ec",
    )

    parsed = parse_leaf_certificate(certificate_der)

    assert parsed.public_key_type == "ec"
    assert parsed.public_key_size == 256


def test_malformed_der_raises_certificate_parse_error() -> None:
    with pytest.raises(CertificateParseError):
        parse_leaf_certificate(b"not a DER certificate")


def test_certificate_parse_error_preserves_original_cause() -> None:
    with pytest.raises(CertificateParseError) as error_info:
        parse_leaf_certificate(b"not a DER certificate")

    assert isinstance(error_info.value.__cause__, ValueError)
