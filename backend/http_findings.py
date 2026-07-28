from backend.http_models import (
    HttpHeaderFinding,
    HttpHeaderFindingCode,
    NormalizedSecurityHeaders,
    SecurityHeaderValue,
)
from backend.tls_models import FindingSeverity


def _missing_or_empty_finding(
    header: SecurityHeaderValue,
    *,
    missing_code: HttpHeaderFindingCode,
    empty_code: HttpHeaderFindingCode,
    severity: FindingSeverity,
    missing_message: str,
    empty_message: str,
) -> HttpHeaderFinding | None:
    if not header.present:
        return HttpHeaderFinding(
            code=missing_code,
            severity=severity,
            message=missing_message,
        )
    if header.value == "":
        return HttpHeaderFinding(
            code=empty_code,
            severity=severity,
            message=empty_message,
        )
    return None


def evaluate_http_header_findings(
    headers: NormalizedSecurityHeaders,
) -> tuple[HttpHeaderFinding, ...]:
    checks = (
        (
            headers.strict_transport_security,
            HttpHeaderFindingCode.MISSING_STRICT_TRANSPORT_SECURITY,
            HttpHeaderFindingCode.EMPTY_STRICT_TRANSPORT_SECURITY,
            FindingSeverity.WARNING,
            (
                "The response did not include Strict-Transport-Security, so "
                "no HSTS policy was observed."
            ),
            (
                "The response included an empty Strict-Transport-Security "
                "header, so no usable HSTS policy was observed."
            ),
        ),
        (
            headers.content_security_policy,
            HttpHeaderFindingCode.MISSING_CONTENT_SECURITY_POLICY,
            HttpHeaderFindingCode.EMPTY_CONTENT_SECURITY_POLICY,
            FindingSeverity.WARNING,
            (
                "The response did not include Content-Security-Policy, so no "
                "content security policy was observed."
            ),
            (
                "The response included an empty Content-Security-Policy "
                "header, so no usable content security policy was observed."
            ),
        ),
        (
            headers.x_content_type_options,
            HttpHeaderFindingCode.MISSING_X_CONTENT_TYPE_OPTIONS,
            HttpHeaderFindingCode.EMPTY_X_CONTENT_TYPE_OPTIONS,
            FindingSeverity.WARNING,
            (
                "The response did not include X-Content-Type-Options, so the "
                "nosniff directive was not observed."
            ),
            (
                "The response included an empty X-Content-Type-Options "
                "header, so the nosniff directive was not observed."
            ),
        ),
        (
            headers.x_frame_options,
            HttpHeaderFindingCode.MISSING_X_FRAME_OPTIONS,
            HttpHeaderFindingCode.EMPTY_X_FRAME_OPTIONS,
            FindingSeverity.WARNING,
            (
                "The response did not include X-Frame-Options. This "
                "observation alone does not determine whether a CSP "
                "frame-ancestors directive restricts framing."
            ),
            (
                "The response included an empty X-Frame-Options header. This "
                "observation alone does not determine whether a CSP "
                "frame-ancestors directive restricts framing."
            ),
        ),
        (
            headers.referrer_policy,
            HttpHeaderFindingCode.MISSING_REFERRER_POLICY,
            HttpHeaderFindingCode.EMPTY_REFERRER_POLICY,
            FindingSeverity.INFO,
            (
                "The response did not include a Referrer-Policy header, so no "
                "explicit referrer policy was observed."
            ),
            (
                "The response included an empty Referrer-Policy header, so no "
                "explicit referrer policy was observed."
            ),
        ),
        (
            headers.permissions_policy,
            HttpHeaderFindingCode.MISSING_PERMISSIONS_POLICY,
            HttpHeaderFindingCode.EMPTY_PERMISSIONS_POLICY,
            FindingSeverity.INFO,
            (
                "The response did not include a Permissions-Policy header, "
                "so no permissions policy was observed."
            ),
            (
                "The response included an empty Permissions-Policy header, "
                "so no permissions policy was observed."
            ),
        ),
    )

    findings: list[HttpHeaderFinding] = []
    for (
        header,
        missing_code,
        empty_code,
        severity,
        missing_message,
        empty_message,
    ) in checks:
        finding = _missing_or_empty_finding(
            header,
            missing_code=missing_code,
            empty_code=empty_code,
            severity=severity,
            missing_message=missing_message,
            empty_message=empty_message,
        )
        if finding is not None:
            findings.append(finding)

    content_type_options = headers.x_content_type_options
    if (
        content_type_options.present
        and content_type_options.value
        and content_type_options.value.casefold() != "nosniff"
    ):
        findings.append(
            HttpHeaderFinding(
                code=HttpHeaderFindingCode.INVALID_X_CONTENT_TYPE_OPTIONS,
                severity=FindingSeverity.WARNING,
                message=(
                    "X-Content-Type-Options was present but its value was not "
                    "the supported nosniff directive."
                ),
            )
        )

    frame_options = headers.x_frame_options
    if (
        frame_options.present
        and frame_options.value
        and frame_options.value.casefold() not in {"deny", "sameorigin"}
    ):
        findings.append(
            HttpHeaderFinding(
                code=HttpHeaderFindingCode.INVALID_X_FRAME_OPTIONS,
                severity=FindingSeverity.WARNING,
                message=(
                    "X-Frame-Options was present but its value was not DENY "
                    "or SAMEORIGIN."
                ),
            )
        )

    return tuple(findings)
