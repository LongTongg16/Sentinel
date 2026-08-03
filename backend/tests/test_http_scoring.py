import pytest

from backend.http_headers import normalize_security_headers
from backend.http_scoring import (
    BASE_SCORE,
    MINIMUM_SCORE,
    _clamp_score,
    calculate_grade,
    calculate_http_security_score,
)


COMPLETE_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin",
    "permissions-policy": "camera=()",
}


def _score_for(headers: dict[str, str]):
    normalized = normalize_security_headers(tuple(headers.items()))
    return calculate_http_security_score(normalized)


def _score_for_repeated_csp(
    *csp_values: str,
    x_frame_options: str | None = None,
):
    header_tuples = tuple(
        ("content-security-policy", value) for value in csp_values
    )
    if x_frame_options is not None:
        header_tuples += (("x-frame-options", x_frame_options),)
    normalized = normalize_security_headers(header_tuples)
    return calculate_http_security_score(normalized)


def test_perfect_headers_score_100_with_no_deductions() -> None:
    result = _score_for(COMPLETE_HEADERS)

    assert result.score == 100
    assert result.grade == "A+"
    assert result.deductions == ()


def test_methodology_is_present_and_not_official_observatory_score() -> None:
    result = _score_for(COMPLETE_HEADERS)

    assert "Sentinel" in result.methodology
    assert "not" in result.methodology.lower()
    assert "Observatory" in result.methodology


def test_single_missing_control_produces_one_deduction() -> None:
    headers = COMPLETE_HEADERS.copy()
    del headers["strict-transport-security"]

    result = _score_for(headers)

    assert len(result.deductions) == 1
    deduction = result.deductions[0]
    assert deduction.control == "strict-transport-security"
    assert deduction.points == 20
    assert deduction.reason
    assert result.score == BASE_SCORE - 20


def test_multiple_missing_controls_produce_multiple_deductions() -> None:
    headers = COMPLETE_HEADERS.copy()
    del headers["strict-transport-security"]
    del headers["content-security-policy"]
    del headers["x-content-type-options"]

    result = _score_for(headers)

    # content-security-policy is deliberately absent from the expected set:
    # CSP is excluded from the numeric score entirely (see PRIORITY 1 /
    # backend.http_scoring._csp_deduction), so a missing CSP header still
    # produces a finding but never a score deduction.
    controls = {deduction.control for deduction in result.deductions}
    assert controls == {
        "strict-transport-security",
        "x-content-type-options",
    }
    assert result.score == BASE_SCORE - 20 - 5


def test_all_controls_missing_reaches_expected_floor() -> None:
    result = _score_for({})

    # HSTS -20, framing -20 (no CSP frame-ancestors, no X-Frame-Options),
    # XCTO -5; CSP itself contributes 0 (excluded from scoring, see
    # PRIORITY 1); referrer-policy missing is not penalized (matches MDN
    # HTTP Observatory's ReferrerPolicyNotImplemented, modifier 0);
    # permissions-policy is excluded from scoring entirely.
    assert result.score == 100 - 20 - 20 - 5
    assert result.grade == calculate_grade(result.score)


def test_csp_findings_never_affect_numeric_score() -> None:
    baseline = _score_for(COMPLETE_HEADERS)

    for csp_value in (
        None,
        "",
        "default-src *",  # obviously weak wildcard
        "script-src 'self' 'unsafe-eval'",  # weak, unsafe-eval
        ";;;",  # unparseable / invalid
    ):
        headers = COMPLETE_HEADERS.copy()
        if csp_value is None:
            del headers["content-security-policy"]
        else:
            headers["content-security-policy"] = csp_value

        result = _score_for(headers)

        assert result.score == baseline.score, csp_value
        assert all(
            deduction.control != "content-security-policy"
            for deduction in result.deductions
        ), csp_value


@pytest.mark.parametrize(
    ("x_frame_options", "csp"),
    [
        ("DENY", "default-src 'self'"),
        (None, "default-src 'self'; frame-ancestors 'none'"),
        ("DENY", "default-src 'self'; frame-ancestors 'none'"),
    ],
)
def test_framing_protection_never_produces_more_than_one_deduction_entry(
    x_frame_options: str | None,
    csp: str,
) -> None:
    headers = COMPLETE_HEADERS.copy()
    headers["content-security-policy"] = csp
    if x_frame_options is None:
        del headers["x-frame-options"]
    else:
        headers["x-frame-options"] = x_frame_options

    result = _score_for(headers)

    framing_deductions = [
        deduction
        for deduction in result.deductions
        if deduction.control == "framing-protection"
    ]
    # Protected by at least one mechanism in every case above, so there
    # should be no framing-protection deduction at all -- and never more
    # than one even when both mechanisms would otherwise qualify.
    assert framing_deductions == []


def test_framing_protection_not_protected_is_a_single_deduction() -> None:
    headers = COMPLETE_HEADERS.copy()
    headers["content-security-policy"] = "default-src 'self'"
    del headers["x-frame-options"]

    result = _score_for(headers)

    framing_deductions = [
        deduction
        for deduction in result.deductions
        if deduction.control == "framing-protection"
    ]
    assert len(framing_deductions) == 1
    assert framing_deductions[0].points == 20


def test_framing_protection_scoring_one_restrictive_and_one_wildcard_policy() -> (
    None
):
    # Regression test at the scoring layer: a restrictive policy must
    # still protect (and avoid the deduction) even when a sibling
    # separately-enforced policy is a wildcard. Unioning frame-ancestors
    # tokens across policies (the earlier bug) would have incorrectly
    # applied the -20 deduction here.
    result = _score_for_repeated_csp(
        "frame-ancestors 'none'", "frame-ancestors *"
    )
    assert all(
        d.control != "framing-protection" for d in result.deductions
    )


def test_framing_protection_scoring_multiple_policies_no_protection_deducts() -> (
    None
):
    result = _score_for_repeated_csp("default-src 'self'", "script-src 'self'")
    framing_deductions = [
        d for d in result.deductions if d.control == "framing-protection"
    ]
    assert len(framing_deductions) == 1
    assert framing_deductions[0].points == 20


@pytest.mark.parametrize(
    "permissions_policy_value",
    [None, "", "camera=(), microphone=()", "garbage-not-a-real-directive"],
)
def test_permissions_policy_never_affects_numeric_score(
    permissions_policy_value: str | None,
) -> None:
    baseline = _score_for(COMPLETE_HEADERS)

    headers = COMPLETE_HEADERS.copy()
    if permissions_policy_value is None:
        del headers["permissions-policy"]
    else:
        headers["permissions-policy"] = permissions_policy_value

    result = _score_for(headers)

    assert result.score == baseline.score
    assert all(
        deduction.control != "permissions-policy"
        for deduction in result.deductions
    )


@pytest.mark.parametrize(
    ("score", "expected_grade"),
    [
        (100, "A+"),
        (90, "A"),
        (89, "A-"),
        (85, "A-"),
        (84, "B+"),
        (80, "B+"),
        (79, "B"),
        (70, "B"),
        (69, "B-"),
        (65, "B-"),
        (64, "C+"),
        (60, "C+"),
        (59, "C"),
        (50, "C"),
        (49, "C-"),
        (45, "C-"),
        (44, "D+"),
        (40, "D+"),
        (39, "D"),
        (30, "D"),
        (29, "D-"),
        (25, "D-"),
        (24, "F"),
        (0, "F"),
    ],
)
def test_grade_boundaries(score: int, expected_grade: str) -> None:
    assert calculate_grade(score) == expected_grade


def test_calculate_grade_accepts_score_above_100() -> None:
    # calculate_grade is a general-purpose mapping function and does not
    # assume its input is bounded to [0, 100]; anything at or above 100
    # maps to A+. Sentinel's own scoring path never actually produces a
    # score above 100 (it awards no positive bonuses -- see METHODOLOGY),
    # but the function itself makes no such assumption.
    assert calculate_grade(100) == "A+"
    assert calculate_grade(150) == "A+"


@pytest.mark.parametrize(
    ("max_age", "expected_classification_is_short"),
    [(15_551_999, True), (15_552_000, False)],
)
def test_hsts_scoring_boundary_matches_runtime_analyzer_threshold(
    max_age: int,
    expected_classification_is_short: bool,
) -> None:
    headers = COMPLETE_HEADERS.copy()
    headers["strict-transport-security"] = f"max-age={max_age}"

    result = _score_for(headers)

    hsts_deductions = [
        d for d in result.deductions if d.control == "strict-transport-security"
    ]
    if expected_classification_is_short:
        assert len(hsts_deductions) == 1
        assert hsts_deductions[0].points == 10
    else:
        assert hsts_deductions == []


def test_oversized_hsts_max_age_scores_as_invalid_not_a_crash() -> None:
    # End-to-end regression test through the full scoring path: an
    # oversized max-age (more digits than Python's int() conversion limit
    # allows) must be scored as ordinary invalid HSTS rather than raise.
    headers = COMPLETE_HEADERS.copy()
    headers["strict-transport-security"] = f"max-age={'9' * 5000}"

    result = _score_for(headers)

    hsts_deductions = [
        d for d in result.deductions if d.control == "strict-transport-security"
    ]
    assert len(hsts_deductions) == 1
    assert hsts_deductions[0].points == 20


def test_x_frame_options_allow_from_scoring_consequence() -> None:
    # Documented Sentinel/Observatory divergence: Observatory scores
    # ALLOW-FROM neutrally (0 points); Sentinel treats it as not
    # protecting, since it is obsolete and ignored by modern browsers, so
    # it contributes to the framing-protection deduction here (no CSP
    # frame-ancestors is present to protect instead).
    headers = COMPLETE_HEADERS.copy()
    headers["content-security-policy"] = "default-src 'self'"
    headers["x-frame-options"] = "ALLOW-FROM https://example.com"

    result = _score_for(headers)

    framing_deductions = [
        d for d in result.deductions if d.control == "framing-protection"
    ]
    assert len(framing_deductions) == 1
    assert framing_deductions[0].points == 20


def test_clamp_score_floors_at_minimum_through_controlled_aggregation() -> (
    None
):
    # Sentinel's current control set cannot mathematically produce a raw
    # score below 0 (see test_score_never_goes_below_zero for the
    # realistic floor), so the clamp is exercised directly here via a
    # synthetic raw score, independent of header parsing.
    assert _clamp_score(BASE_SCORE - 1000) == MINIMUM_SCORE
    assert _clamp_score(-1) == MINIMUM_SCORE
    assert _clamp_score(BASE_SCORE) == BASE_SCORE


@pytest.mark.parametrize(
    "headers_overrides",
    [
        {},
        {"strict-transport-security": "max-age=0"},
        {"content-security-policy": "default-src *"},
        {
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "none",
        },
        {"referrer-policy": "unsafe-url"},
        {"x-content-type-options": "sniff"},
    ],
)
def test_deduction_breakdown_matches_final_score(
    headers_overrides: dict[str, str],
) -> None:
    headers = COMPLETE_HEADERS.copy()
    headers.update(headers_overrides)

    result = _score_for(headers)

    reconciled = max(
        BASE_SCORE - sum(d.points for d in result.deductions), 0
    )
    assert result.score == reconciled


def test_score_never_goes_below_zero() -> None:
    # Even with every scored control at its worst case, the current control
    # set cannot mathematically go below 0, but the score is still clamped
    # defensively.
    result = _score_for({})
    assert result.score >= 0
