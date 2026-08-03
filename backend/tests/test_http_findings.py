import pytest

from backend.http_findings import (
    classify_content_security_policy,
    classify_referrer_policy,
    classify_strict_transport_security,
    evaluate_framing_protection,
    evaluate_http_header_findings,
)
from backend.http_headers import normalize_security_headers
from backend.http_models import (
    CspClassification,
    CspWeakness,
    FramingProtectionClassification,
    FramingProtectionEvaluation,
    HstsClassification,
    HttpHeaderFinding,
    HttpHeaderFindingCode,
    ReferrerPolicyClassification,
)


COMPLETE_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin",
    "permissions-policy": "camera=()",
}

# Expected finding codes per header when that header is missing/empty.
# x-frame-options produces a second finding because "framing not protected"
# is a combined control (X-Frame-Options and/or CSP frame-ancestors): with
# CSP left at its COMPLETE_HEADERS value ("default-src 'self'", which has
# no frame-ancestors directive), a missing/empty/invalid X-Frame-Options
# header means framing protection is not confirmed either. This is the
# intended behavior of the combined framing-protection control (see
# evaluate_framing_protection) and is not a regression.
MISSING_CODES = {
    "strict-transport-security": (
        HttpHeaderFindingCode.MISSING_STRICT_TRANSPORT_SECURITY,
    ),
    "content-security-policy": (
        HttpHeaderFindingCode.MISSING_CONTENT_SECURITY_POLICY,
    ),
    "x-content-type-options": (
        HttpHeaderFindingCode.MISSING_X_CONTENT_TYPE_OPTIONS,
    ),
    "x-frame-options": (
        HttpHeaderFindingCode.MISSING_X_FRAME_OPTIONS,
        HttpHeaderFindingCode.FRAMING_NOT_PROTECTED,
    ),
    "referrer-policy": (HttpHeaderFindingCode.MISSING_REFERRER_POLICY,),
    "permissions-policy": (HttpHeaderFindingCode.MISSING_PERMISSIONS_POLICY,),
}

EMPTY_CODES = {
    "strict-transport-security": (
        HttpHeaderFindingCode.EMPTY_STRICT_TRANSPORT_SECURITY,
    ),
    "content-security-policy": (
        HttpHeaderFindingCode.EMPTY_CONTENT_SECURITY_POLICY,
    ),
    "x-content-type-options": (
        HttpHeaderFindingCode.EMPTY_X_CONTENT_TYPE_OPTIONS,
    ),
    "x-frame-options": (
        HttpHeaderFindingCode.EMPTY_X_FRAME_OPTIONS,
        HttpHeaderFindingCode.FRAMING_NOT_PROTECTED,
    ),
    "referrer-policy": (HttpHeaderFindingCode.EMPTY_REFERRER_POLICY,),
    "permissions-policy": (HttpHeaderFindingCode.EMPTY_PERMISSIONS_POLICY,),
}


def findings_for(
    headers: dict[str, str],
) -> tuple[HttpHeaderFinding, ...]:
    normalized = normalize_security_headers(tuple(headers.items()))
    return evaluate_http_header_findings(normalized)


def test_all_six_supported_headers_present_has_no_findings() -> None:
    assert findings_for(COMPLETE_HEADERS) == ()


@pytest.mark.parametrize(
    ("missing_header", "expected_codes"),
    MISSING_CODES.items(),
)
def test_each_missing_supported_header_has_a_deterministic_finding(
    missing_header: str,
    expected_codes: tuple[HttpHeaderFindingCode, ...],
) -> None:
    headers = COMPLETE_HEADERS.copy()
    del headers[missing_header]

    result = findings_for(headers)

    assert tuple(finding.code for finding in result) == expected_codes


@pytest.mark.parametrize(
    ("empty_header", "expected_codes"),
    EMPTY_CODES.items(),
)
def test_empty_values_are_distinct_from_missing_headers(
    empty_header: str,
    expected_codes: tuple[HttpHeaderFindingCode, ...],
) -> None:
    headers = COMPLETE_HEADERS.copy()
    headers[empty_header] = " \t "

    result = findings_for(headers)

    assert tuple(finding.code for finding in result) == expected_codes


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

    # Also produces framing_not_protected: an invalid X-Frame-Options value
    # provides no protection, and COMPLETE_HEADERS' CSP has no
    # frame-ancestors directive, so the combined control is not satisfied
    # either. See the module-level comment on MISSING_CODES.
    assert tuple(finding.code for finding in result) == (
        HttpHeaderFindingCode.INVALID_X_FRAME_OPTIONS,
        HttpHeaderFindingCode.FRAMING_NOT_PROTECTED,
    )


def test_findings_have_stable_header_order() -> None:
    result = findings_for({})

    # The six per-header "missing" findings are reported first, in header
    # order. The combined framing-protection finding is evaluated last
    # (after the per-header missing/empty and invalid-value checks), and
    # fires exactly once here even though it relates to both
    # x-frame-options and content-security-policy being missing.
    expected = (
        HttpHeaderFindingCode.MISSING_STRICT_TRANSPORT_SECURITY,
        HttpHeaderFindingCode.MISSING_CONTENT_SECURITY_POLICY,
        HttpHeaderFindingCode.MISSING_X_CONTENT_TYPE_OPTIONS,
        HttpHeaderFindingCode.MISSING_X_FRAME_OPTIONS,
        HttpHeaderFindingCode.MISSING_REFERRER_POLICY,
        HttpHeaderFindingCode.MISSING_PERMISSIONS_POLICY,
        HttpHeaderFindingCode.FRAMING_NOT_PROTECTED,
    )

    assert tuple(finding.code for finding in result) == expected


# --- Strict-Transport-Security classification -------------------------------


def _hsts_header(value: str | None):
    from backend.http_models import SecurityHeaderValue

    if value is None:
        return SecurityHeaderValue(present=False, value=None)
    return SecurityHeaderValue(present=True, value=value)


def test_classify_hsts_returns_none_for_missing_header() -> None:
    assert classify_strict_transport_security(_hsts_header(None)) is None


def test_classify_hsts_returns_none_for_empty_header() -> None:
    assert classify_strict_transport_security(_hsts_header("")) is None


def test_classify_hsts_max_age_zero_is_disabled() -> None:
    result = classify_strict_transport_security(_hsts_header("max-age=0"))
    assert result is not None
    assert result.classification is HstsClassification.DISABLED
    assert result.max_age == 0


@pytest.mark.parametrize(
    "value",
    ["includeSubDomains", "max-age=abc", "max-age=", "max-age=-5"],
)
def test_classify_hsts_invalid_max_age(value: str) -> None:
    result = classify_strict_transport_security(_hsts_header(value))
    assert result is not None
    assert result.classification is HstsClassification.INVALID


@pytest.mark.parametrize(
    "value",
    [
        "max-age=15_552_000",  # underscore digit-group separator (Python-ism)
        "max-age=-1",  # negative sign
        "max-age=100garbage",  # trailing non-digit characters
        "max-age=１００",  # fullwidth Unicode digits ("100")
        "max-age=١٠٠",  # Arabic-Indic Unicode digits ("100")
    ],
)
def test_classify_hsts_rejects_non_ascii_digit_max_age(value: str) -> None:
    # Sentinel-specific stricter parsing: HTTP's delta-seconds grammar is
    # ASCII digits only. Python's int() would otherwise silently accept
    # all of the above.
    result = classify_strict_transport_security(_hsts_header(value))
    assert result is not None
    assert result.classification is HstsClassification.INVALID


def test_classify_hsts_duplicate_max_age_within_one_policy_is_invalid() -> (
    None
):
    # Sentinel-specific stricter parsing: Observatory's runtime analyzer
    # silently keeps the last max-age value when a header contains the
    # directive twice; Sentinel treats this as invalid instead.
    result = classify_strict_transport_security(
        _hsts_header("max-age=31536000; max-age=100")
    )
    assert result is not None
    assert result.classification is HstsClassification.INVALID


def test_classify_hsts_oversized_max_age_is_invalid_not_a_crash() -> None:
    # Regression test: Python's int() enforces a maximum digit-string
    # length (sys.set_int_max_str_digits, default 4300) and raises
    # ValueError past that length. A max-age value with many more digits
    # than that -- still well within the collector's overall HTTP
    # header-size limit -- must be treated as invalid HSTS, not raise.
    oversized_max_age = "9" * 5000
    result = classify_strict_transport_security(
        _hsts_header(f"max-age={oversized_max_age}")
    )
    assert result is not None
    assert result.classification is HstsClassification.INVALID
    assert result.max_age is None


def test_oversized_hsts_max_age_produces_the_normal_invalid_finding() -> None:
    # End-to-end confirmation through the full findings pipeline (not just
    # the classifier in isolation): an oversized max-age must surface as
    # the ordinary invalid-HSTS finding rather than raise.
    oversized_max_age = "9" * 5000
    headers = COMPLETE_HEADERS.copy()
    headers["strict-transport-security"] = f"max-age={oversized_max_age}"

    result = findings_for(headers)

    assert tuple(finding.code for finding in result) == (
        HttpHeaderFindingCode.INVALID_STRICT_TRANSPORT_SECURITY,
    )


def test_classify_hsts_short_max_age() -> None:
    result = classify_strict_transport_security(
        _hsts_header("max-age=86400")
    )
    assert result is not None
    assert result.classification is HstsClassification.SHORT_DURATION
    assert result.max_age == 86400


def test_classify_hsts_passing_max_age_at_six_months_is_acceptable() -> None:
    # Sentinel follows MDN HTTP Observatory's actual runtime analyzer
    # threshold (15,552,000 seconds / 180 days), not the 15,768,000 seconds
    # mentioned in Observatory's own published score-table description
    # text -- see HSTS_SIX_MONTHS_SECONDS in backend.http_findings.
    result = classify_strict_transport_security(
        _hsts_header("max-age=15552000")
    )
    assert result is not None
    assert result.classification is HstsClassification.ACCEPTABLE


def test_classify_hsts_max_age_one_second_below_six_months_is_short() -> None:
    result = classify_strict_transport_security(
        _hsts_header("max-age=15551999")
    )
    assert result is not None
    assert result.classification is HstsClassification.SHORT_DURATION


def test_classify_hsts_max_age_at_one_year_is_strong() -> None:
    result = classify_strict_transport_security(
        _hsts_header("max-age=31536000")
    )
    assert result is not None
    assert result.classification is HstsClassification.STRONG


def test_classify_hsts_parses_include_subdomains() -> None:
    result = classify_strict_transport_security(
        _hsts_header("max-age=31536000; includeSubDomains")
    )
    assert result is not None
    assert result.include_subdomains is True


def test_classify_hsts_defaults_include_subdomains_to_false() -> None:
    result = classify_strict_transport_security(
        _hsts_header("max-age=31536000")
    )
    assert result is not None
    assert result.include_subdomains is False


def test_classify_hsts_repeated_header_is_invalid() -> None:
    # normalize_security_headers joins repeated header instances with ", ".
    normalized = normalize_security_headers(
        (
            ("strict-transport-security", "max-age=31536000"),
            ("strict-transport-security", "max-age=60"),
        )
    )
    result = classify_strict_transport_security(
        normalized.strict_transport_security
    )
    assert result is not None
    assert result.classification is HstsClassification.INVALID


# --- Content-Security-Policy classification ---------------------------------


def _csp_header(value: str | None):
    from backend.http_models import SecurityHeaderValue

    if value is None:
        return SecurityHeaderValue(present=False, value=None)
    return SecurityHeaderValue(present=True, value=value)


def test_classify_csp_returns_none_for_missing_header() -> None:
    assert classify_content_security_policy(_csp_header(None)) is None


def test_classify_csp_returns_none_for_empty_header() -> None:
    assert classify_content_security_policy(_csp_header("")) is None


def test_classify_csp_unparseable_value_is_invalid() -> None:
    result = classify_content_security_policy(_csp_header(";;;"))
    assert result is not None
    assert result.classification is CspClassification.INVALID


@pytest.mark.parametrize(
    "value",
    [
        "default-src *",
        "script-src *",
        "default-src 'unsafe-inline'",
        "script-src 'self' data:",
    ],
)
def test_classify_csp_obviously_weak_wildcard_policy(value: str) -> None:
    result = classify_content_security_policy(_csp_header(value))
    assert result is not None
    assert result.classification is CspClassification.WEAK
    assert result.weakness is CspWeakness.UNSAFE_OR_BROAD_SOURCES


def test_classify_csp_unsafe_eval_only_is_weak_with_distinct_reason() -> None:
    result = classify_content_security_policy(
        _csp_header("default-src 'self'; script-src 'self' 'unsafe-eval'")
    )
    assert result is not None
    assert result.classification is CspClassification.WEAK
    assert result.weakness is CspWeakness.UNSAFE_EVAL_ONLY


def test_classify_csp_meaningful_restrictive_policy() -> None:
    result = classify_content_security_policy(
        _csp_header("default-src 'self'; object-src 'none'")
    )
    assert result is not None
    assert result.classification is CspClassification.MEANINGFUL


def test_classify_csp_no_object_src_or_default_src_falls_back_to_wildcard() -> (
    None
):
    # Only script-src is set; object-src has no default-src to fall back
    # on either, so it defaults to "*" and is therefore weak.
    result = classify_content_security_policy(_csp_header("script-src 'self'"))
    assert result is not None
    assert result.classification is CspClassification.WEAK


def test_classify_csp_repeated_header_instances_parse_as_separate_policies() -> (
    None
):
    # Regression test: normalize_security_headers joins repeated header
    # instances with ", ". Before this fix, a value like
    # "default-src *, frame-ancestors 'none'" was parsed as one directive
    # stream, which corrupted default-src's source list with stray tokens
    # ("*," / "frame-ancestors" / "'none'"). It must instead be parsed as
    # two separate enforced policies. (frame-ancestors extraction itself
    # is no longer part of this general classification -- see the
    # dedicated framing-protection tests below, which cover it per-policy
    # via evaluate_framing_protection instead of through CspEvaluation.)
    normalized = normalize_security_headers(
        (
            ("content-security-policy", "default-src *"),
            ("content-security-policy", "frame-ancestors 'none'"),
        )
    )
    result = classify_content_security_policy(
        normalized.content_security_policy
    )

    assert result is not None
    assert result.classification is CspClassification.WEAK
    assert result.weakness is CspWeakness.UNSAFE_OR_BROAD_SOURCES


def test_classify_csp_same_directive_across_policies_is_unioned() -> None:
    normalized = normalize_security_headers(
        (
            ("content-security-policy", "script-src 'self'"),
            ("content-security-policy", "script-src 'unsafe-inline'"),
        )
    )
    result = classify_content_security_policy(
        normalized.content_security_policy
    )

    assert result is not None
    # The union includes the unsafe source from the second policy, so this
    # is correctly flagged as weak even though the first policy alone
    # would have been meaningful.
    assert result.classification is CspClassification.WEAK


# --- Framing protection (combined X-Frame-Options / CSP frame-ancestors) ----


def _headers_with(**overrides: str) -> dict:
    headers = COMPLETE_HEADERS.copy()
    headers.update(overrides)
    return headers


def _framing_result(headers: dict) -> FramingProtectionClassification:
    normalized = normalize_security_headers(tuple(headers.items()))
    return evaluate_framing_protection(normalized).classification


def test_framing_protection_valid_x_frame_options_only() -> None:
    headers = _headers_with(**{
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
    })
    assert (
        _framing_result(headers) is FramingProtectionClassification.PROTECTED
    )


def test_framing_protection_valid_frame_ancestors_only() -> None:
    headers = _headers_with(**{
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    })
    del headers["x-frame-options"]
    assert (
        _framing_result(headers) is FramingProtectionClassification.PROTECTED
    )


def test_framing_protection_both_present_is_protected() -> None:
    headers = _headers_with(**{
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-frame-options": "DENY",
    })
    assert (
        _framing_result(headers) is FramingProtectionClassification.PROTECTED
    )


def test_framing_protection_neither_present_is_not_protected() -> None:
    headers = _headers_with(**{
        "content-security-policy": "default-src 'self'",
    })
    del headers["x-frame-options"]
    assert (
        _framing_result(headers)
        is FramingProtectionClassification.NOT_PROTECTED
    )


def test_framing_protection_invalid_x_frame_options_is_not_protected() -> None:
    headers = _headers_with(**{
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "ALLOW-FROM https://example.com",
    })
    assert (
        _framing_result(headers)
        is FramingProtectionClassification.NOT_PROTECTED
    )


def test_framing_protection_wildcard_frame_ancestors_does_not_protect() -> None:
    headers = _headers_with(**{
        "content-security-policy": "default-src 'self'; frame-ancestors *",
    })
    del headers["x-frame-options"]
    assert (
        _framing_result(headers)
        is FramingProtectionClassification.NOT_PROTECTED
    )


def _framing_result_from_repeated_csp(
    *csp_values: str,
    x_frame_options: str | None = None,
) -> FramingProtectionEvaluation:
    header_tuples = tuple(
        ("content-security-policy", value) for value in csp_values
    )
    if x_frame_options is not None:
        header_tuples += (("x-frame-options", x_frame_options),)
    normalized = normalize_security_headers(header_tuples)
    return evaluate_framing_protection(normalized)


def test_framing_protection_one_restrictive_and_one_wildcard_policy_is_protected() -> (
    None
):
    # Regression test: each Content-Security-Policy header field line is a
    # separately enforced policy. A resource must satisfy ALL of them, so
    # if any single policy restricts frame-ancestors, that restriction is
    # real regardless of what a sibling policy allows. Unioning
    # ("'none'", "*") into one set (the earlier bug) would have
    # incorrectly concluded framing was unprotected.
    result = _framing_result_from_repeated_csp(
        "frame-ancestors 'none'", "frame-ancestors *"
    )
    assert result.classification is FramingProtectionClassification.PROTECTED
    assert result.via_csp_frame_ancestors is True


def test_framing_protection_wildcard_only_frame_ancestors_is_not_protected() -> (
    None
):
    result = _framing_result_from_repeated_csp("frame-ancestors *")
    assert (
        result.classification is FramingProtectionClassification.NOT_PROTECTED
    )


def test_framing_protection_single_restrictive_policy_is_protected() -> None:
    result = _framing_result_from_repeated_csp("frame-ancestors 'none'")
    assert result.classification is FramingProtectionClassification.PROTECTED
    assert result.via_csp_frame_ancestors is True


def test_framing_protection_multiple_policies_no_frame_ancestors_falls_back_to_valid_xfo() -> (
    None
):
    result = _framing_result_from_repeated_csp(
        "default-src 'self'",
        "script-src 'self'",
        x_frame_options="DENY",
    )
    assert result.classification is FramingProtectionClassification.PROTECTED
    assert result.via_x_frame_options is True
    assert result.via_csp_frame_ancestors is False


def test_framing_protection_multiple_policies_no_protection_is_not_protected() -> (
    None
):
    result = _framing_result_from_repeated_csp(
        "default-src 'self'", "script-src 'self'"
    )
    assert (
        result.classification is FramingProtectionClassification.NOT_PROTECTED
    )


def test_x_frame_options_allow_from_is_documented_sentinel_divergence() -> (
    None
):
    # MDN HTTP Observatory gives ALLOW-FROM a neutral, non-penalized
    # outcome (XFrameOptionsAllowFromOrigin, 0-point modifier). Sentinel
    # intentionally diverges and does not treat ALLOW-FROM as providing
    # framing protection, because it is obsolete and ignored by all
    # current major browsers -- see
    # backend.http_findings._is_valid_x_frame_options. This also means
    # ALLOW-FROM still produces the ordinary INVALID_X_FRAME_OPTIONS
    # finding, same as any other unrecognized value.
    headers = _headers_with(**{
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "ALLOW-FROM https://example.com",
    })

    assert (
        _framing_result(headers)
        is FramingProtectionClassification.NOT_PROTECTED
    )

    result = findings_for(headers)
    assert tuple(finding.code for finding in result) == (
        HttpHeaderFindingCode.INVALID_X_FRAME_OPTIONS,
        HttpHeaderFindingCode.FRAMING_NOT_PROTECTED,
    )


# --- Referrer-Policy classification ------------------------------------------


def _referrer_header(value: str | None):
    from backend.http_models import SecurityHeaderValue

    if value is None:
        return SecurityHeaderValue(present=False, value=None)
    return SecurityHeaderValue(present=True, value=value)


def test_classify_referrer_policy_returns_none_for_missing_header() -> None:
    assert classify_referrer_policy(_referrer_header(None)) is None


def test_classify_referrer_policy_returns_none_for_empty_header() -> None:
    assert classify_referrer_policy(_referrer_header("")) is None


@pytest.mark.parametrize(
    "value",
    [
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    ],
)
def test_classify_referrer_policy_strong_values(value: str) -> None:
    assert (
        classify_referrer_policy(_referrer_header(value))
        is ReferrerPolicyClassification.STRONG
    )


def test_classify_referrer_policy_unsafe_url() -> None:
    assert (
        classify_referrer_policy(_referrer_header("unsafe-url"))
        is ReferrerPolicyClassification.UNSAFE
    )


@pytest.mark.parametrize(
    "value",
    ["origin", "origin-when-cross-origin", "no-referrer-when-downgrade"],
)
def test_classify_referrer_policy_other_unsafe_values(value: str) -> None:
    assert (
        classify_referrer_policy(_referrer_header(value))
        is ReferrerPolicyClassification.UNSAFE
    )


def test_classify_referrer_policy_unrecognized_value_is_invalid() -> None:
    assert (
        classify_referrer_policy(_referrer_header("not-a-real-policy"))
        is ReferrerPolicyClassification.INVALID
    )


def test_classify_referrer_policy_uses_last_recognized_token() -> None:
    # Mirrors browser behavior of preferring the last recognized policy in
    # a comma-separated list (e.g. from repeated headers being joined).
    result = classify_referrer_policy(
        _referrer_header("unsafe-url, strict-origin")
    )
    assert result is ReferrerPolicyClassification.STRONG
