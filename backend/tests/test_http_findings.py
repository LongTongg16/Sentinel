import pytest

from backend.http_findings import evaluate_http_header_findings
from backend.http_headers import normalize_security_headers
from backend.http_models import HttpHeaderFinding, HttpHeaderFindingCode


COMPLETE_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin",
    "permissions-policy": "camera=()",
}

MISSING_CODES = {
    "strict-transport-security": (
        HttpHeaderFindingCode.MISSING_STRICT_TRANSPORT_SECURITY
    ),
    "content-security-policy": (
        HttpHeaderFindingCode.MISSING_CONTENT_SECURITY_POLICY
    ),
    "x-content-type-options": (
        HttpHeaderFindingCode.MISSING_X_CONTENT_TYPE_OPTIONS
    ),
    "x-frame-options": HttpHeaderFindingCode.MISSING_X_FRAME_OPTIONS,
    "referrer-policy": HttpHeaderFindingCode.MISSING_REFERRER_POLICY,
    "permissions-policy": HttpHeaderFindingCode.MISSING_PERMISSIONS_POLICY,
}

EMPTY_CODES = {
    "strict-transport-security": (
        HttpHeaderFindingCode.EMPTY_STRICT_TRANSPORT_SECURITY
    ),
    "content-security-policy": (
        HttpHeaderFindingCode.EMPTY_CONTENT_SECURITY_POLICY
    ),
    "x-content-type-options": (
        HttpHeaderFindingCode.EMPTY_X_CONTENT_TYPE_OPTIONS
    ),
    "x-frame-options": HttpHeaderFindingCode.EMPTY_X_FRAME_OPTIONS,
    "referrer-policy": HttpHeaderFindingCode.EMPTY_REFERRER_POLICY,
    "permissions-policy": HttpHeaderFindingCode.EMPTY_PERMISSIONS_POLICY,
}


def findings_for(
    headers: dict[str, str],
) -> tuple[HttpHeaderFinding, ...]:
    normalized = normalize_security_headers(tuple(headers.items()))
    return evaluate_http_header_findings(normalized)


def test_all_six_supported_headers_present_has_no_findings() -> None:
    assert findings_for(COMPLETE_HEADERS) == ()


@pytest.mark.parametrize(
    ("missing_header", "expected_code"),
    MISSING_CODES.items(),
)
def test_each_missing_supported_header_has_a_deterministic_finding(
    missing_header: str,
    expected_code: HttpHeaderFindingCode,
) -> None:
    headers = COMPLETE_HEADERS.copy()
    del headers[missing_header]

    result = findings_for(headers)

    assert tuple(finding.code for finding in result) == (expected_code,)


@pytest.mark.parametrize(
    ("empty_header", "expected_code"),
    EMPTY_CODES.items(),
)
def test_empty_values_are_distinct_from_missing_headers(
    empty_header: str,
    expected_code: HttpHeaderFindingCode,
) -> None:
    headers = COMPLETE_HEADERS.copy()
    headers[empty_header] = " \t "

    result = findings_for(headers)

    assert tuple(finding.code for finding in result) == (expected_code,)


@pytest.mark.parametrize("value", ["sniff", "nosniff, nosniff", "none"])
def test_invalid_x_content_type_options_value_has_a_finding(
    value: str,
) -> None:
    headers = COMPLETE_HEADERS.copy()
    headers["x-content-type-options"] = value

    result = findings_for(headers)

    assert tuple(finding.code for finding in result) == (
        HttpHeaderFindingCode.INVALID_X_CONTENT_TYPE_OPTIONS,
    )


@pytest.mark.parametrize("value", ["nosniff", "NoSnIfF", " nosniff "])
def test_nosniff_is_accepted_case_insensitively(value: str) -> None:
    headers = COMPLETE_HEADERS.copy()
    headers["x-content-type-options"] = value

    assert findings_for(headers) == ()


@pytest.mark.parametrize("value", ["DENY", "sameorigin", " SAMEORIGIN "])
def test_valid_x_frame_options_values_are_accepted(value: str) -> None:
    headers = COMPLETE_HEADERS.copy()
    headers["x-frame-options"] = value

    assert findings_for(headers) == ()


@pytest.mark.parametrize(
    "value",
    ["ALLOW-FROM https://example.com", "DENY, SAMEORIGIN", "none"],
)
def test_invalid_x_frame_options_value_has_a_finding(value: str) -> None:
    headers = COMPLETE_HEADERS.copy()
    headers["x-frame-options"] = value

    result = findings_for(headers)

    assert tuple(finding.code for finding in result) == (
        HttpHeaderFindingCode.INVALID_X_FRAME_OPTIONS,
    )


def test_findings_have_stable_header_order() -> None:
    result = findings_for({})

    assert tuple(finding.code for finding in result) == tuple(
        MISSING_CODES.values()
    )
