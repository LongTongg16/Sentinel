from datetime import timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    ed448,
    rsa,
)
from cryptography.x509.oid import SignatureAlgorithmOID

from backend.tls_models import ParsedCertificate


class CertificateParseError(ValueError):
    pass


def _dns_names(certificate: x509.Certificate) -> tuple[str, ...]:
    try:
        extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
    except x509.ExtensionNotFound:
        return ()

    return tuple(extension.value.get_values_for_type(x509.DNSName))


def _signature_algorithm(certificate: x509.Certificate) -> str:
    signature_hash_algorithm = certificate.signature_hash_algorithm
    if signature_hash_algorithm is not None:
        return signature_hash_algorithm.name.lower()

    signature_oid = certificate.signature_algorithm_oid
    if signature_oid == SignatureAlgorithmOID.ED25519:
        return "ed25519"
    if signature_oid == SignatureAlgorithmOID.ED448:
        return "ed448"
    return signature_oid.dotted_string.lower()


def _public_key_details(certificate: x509.Certificate) -> tuple[str, int | None]:
    public_key = certificate.public_key()

    if isinstance(public_key, rsa.RSAPublicKey):
        return "rsa", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ec", public_key.key_size
    if isinstance(public_key, dsa.DSAPublicKey):
        return "dsa", public_key.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "ed25519", None
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "ed448", None
    return "unknown", None


def parse_leaf_certificate(certificate_der: bytes) -> ParsedCertificate:
    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
    except ValueError as error:
        raise CertificateParseError("certificate DER could not be parsed") from error

    public_key_type, public_key_size = _public_key_details(certificate)

    return ParsedCertificate(
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        valid_from=certificate.not_valid_before_utc.astimezone(timezone.utc),
        expires_at=certificate.not_valid_after_utc.astimezone(timezone.utc),
        dns_names=_dns_names(certificate),
        serial_number=format(certificate.serial_number, "x"),
        signature_algorithm=_signature_algorithm(certificate),
        public_key_type=public_key_type,
        public_key_size=public_key_size,
    )
