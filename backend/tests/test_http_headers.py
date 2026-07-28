from backend.http_headers import normalize_security_headers
from backend.http_models import SecurityHeaderValue


def test_security_header_names_are_case_insensitive() -> None:
    normalized = normalize_security_headers(
        (
            ("STRICT-TRANSPORT-SECURITY", "max-age=31536000"),
            ("content-SECURITY-policy", "default-src 'self'"),
            ("X-content-TYPE-options", "nosniff"),
            ("x-FRAME-options", "DENY"),
            ("REFERRER-policy", "strict-origin"),
            ("permissions-POLICY", "camera=()"),
        )
    )

    assert normalized.strict_transport_security == SecurityHeaderValue(
        present=True,
        value="max-age=31536000",
    )
    assert normalized.content_security_policy == SecurityHeaderValue(
        present=True,
        value="default-src 'self'",
    )
    assert normalized.x_content_type_options == SecurityHeaderValue(
        present=True,
        value="nosniff",
    )
    assert normalized.x_frame_options == SecurityHeaderValue(
        present=True,
        value="DENY",
    )
    assert normalized.referrer_policy == SecurityHeaderValue(
        present=True,
        value="strict-origin",
    )
    assert normalized.permissions_policy == SecurityHeaderValue(
        present=True,
        value="camera=()",
    )


def test_missing_and_empty_headers_remain_distinct() -> None:
    normalized = normalize_security_headers(
        (("X-Content-Type-Options", " \t "),)
    )

    assert normalized.x_content_type_options == SecurityHeaderValue(
        present=True,
        value="",
    )
    assert normalized.x_frame_options == SecurityHeaderValue(
        present=False,
        value=None,
    )


def test_repeated_header_values_are_preserved_in_order() -> None:
    normalized = normalize_security_headers(
        (
            ("X-Frame-Options", "DENY"),
            ("x-frame-options", "SAMEORIGIN"),
        )
    )

    assert normalized.x_frame_options == SecurityHeaderValue(
        present=True,
        value="DENY, SAMEORIGIN",
    )
