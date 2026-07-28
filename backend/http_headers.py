from collections.abc import Iterable

from backend.http_models import (
    NormalizedSecurityHeaders,
    SecurityHeaderValue,
)


def normalize_security_headers(
    headers: Iterable[tuple[str, str]],
) -> NormalizedSecurityHeaders:
    values_by_name: dict[str, list[str]] = {}

    for name, value in headers:
        normalized_name = name.casefold()
        values_by_name.setdefault(normalized_name, []).append(
            value.strip(" \t")
        )

    def header_value(header_name: str) -> SecurityHeaderValue:
        values = values_by_name.get(header_name)
        return SecurityHeaderValue(
            present=values is not None,
            value=", ".join(values) if values is not None else None,
        )

    return NormalizedSecurityHeaders(
        strict_transport_security=header_value("strict-transport-security"),
        content_security_policy=header_value("content-security-policy"),
        x_content_type_options=header_value("x-content-type-options"),
        x_frame_options=header_value("x-frame-options"),
        referrer_policy=header_value("referrer-policy"),
        permissions_policy=header_value("permissions-policy"),
    )
