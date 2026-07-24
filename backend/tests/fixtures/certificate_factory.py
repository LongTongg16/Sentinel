from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    ed448,
    rsa,
)
from cryptography.x509.oid import NameOID


def create_certificate_der(
    *,
    subject_common_name: str = "example.com",
    issuer_common_name: str | None = None,
    valid_from: datetime,
    expires_at: datetime,
    dns_names: tuple[str, ...] | None = ("example.com",),
    signature_hash_algorithm: hashes.HashAlgorithm | None = None,
    serial_number: int = 1,
    key_type: str = "rsa",
    key_size: int = 2048,
) -> bytes:
    if valid_from.tzinfo is None or valid_from.utcoffset() is None:
        raise ValueError("valid_from must be timezone-aware")
    if expires_at.tzinfo is None or expires_at.utcoffset() is None:
        raise ValueError("expires_at must be timezone-aware")

    if key_type == "rsa":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
    elif key_type == "ec":
        private_key = ec.generate_private_key(ec.SECP256R1())
    elif key_type == "dsa":
        private_key = dsa.generate_private_key(key_size=key_size)
    elif key_type == "ed25519":
        private_key = ed25519.Ed25519PrivateKey.generate()
    elif key_type == "ed448":
        private_key = ed448.Ed448PrivateKey.generate()
    else:
        raise ValueError(f"unsupported key type: {key_type}")

    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, subject_common_name)]
    )
    issuer = x509.Name(
        [
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                issuer_common_name or subject_common_name,
            )
        ]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(serial_number)
        .not_valid_before(valid_from)
        .not_valid_after(expires_at)
    )

    if dns_names is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in dns_names]
            ),
            critical=False,
        )

    signing_algorithm = signature_hash_algorithm
    if signing_algorithm is None and key_type not in {"ed25519", "ed448"}:
        signing_algorithm = hashes.SHA256()

    certificate = builder.sign(
        private_key=private_key,
        algorithm=signing_algorithm,
    )
    return certificate.public_bytes(serialization.Encoding.DER)
