"""HTTP Security Configuration Score.

Sentinel's HTTP Security Configuration Score is a Sentinel-specific
assessment. It is NOT an official MDN HTTP Observatory score, it does NOT
claim exact parity with Observatory, and it is NOT an overall measure of a
website's security (it is not a "percent secure" figure). This module scores
the subset of HTTP response header controls Sentinel currently evaluates in
backend.http_findings with enough fidelity to assign a defensible point
value:

- Strict-Transport-Security (HSTS)
- a combined framing-protection control (X-Frame-Options and/or CSP
  frame-ancestors -- see backend.http_findings.evaluate_framing_protection)
- Referrer-Policy
- X-Content-Type-Options

Content-Security-Policy is evaluated and reported as findings (see
backend.http_findings.classify_content_security_policy), but is
INTENTIONALLY EXCLUDED FROM THE NUMERIC SCORE. Sentinel's CSP evaluator does
not yet faithfully reproduce enough of MDN HTTP Observatory's CSP analyzer to
assign a defensible score contribution -- specifically it does not handle
nonce/hash sources making 'unsafe-inline' ineffective, 'strict-dynamic'
semantics, per-directive (rather than blanket) data: handling, style-src
'unsafe-eval', or scheme-based active-content checks. Rather than leave a
partially-faithful CSP score in place, CSP's score contribution is always 0.
See _csp_deduction below.

Permissions-Policy is observed and reported as a Sentinel finding (see
backend.http_findings.evaluate_http_header_findings), but is excluded from
the numeric score: there is no corresponding test in MDN HTTP Observatory to
base a defensible point value on. Cookies, CORS, Cross-Origin-Resource-
Policy, Subresource-Integrity, and redirect behavior are not evaluated by
Sentinel at all (no collection, no findings), so they are excluded entirely
from this score rather than silently treated as passing. TLS certificate
health is assessed separately elsewhere in Sentinel and is never combined
into this numeric score.

A high score reflects the presence of a subset of recommended HTTP security
controls. It is not proof that a website is free of vulnerabilities.

Methodology, point values, and documented divergences
-------------------------------------------------------
Every point value below is taken from MDN HTTP Observatory's publicly
published grading rules (github.com/mdn/mdn-http-observatory,
src/grader/charts.js SCORE_TABLE, as published), for the specific
Observatory "Expectation" noted in each comment. Where Sentinel's evaluator
cannot faithfully distinguish something Observatory checks (for example,
Observatory's positive bonus tiers that require checking the HSTS preload
list, or inspecting CSP's form-action/style-src directives), that control's
best case is capped at a 0-point deduction instead of guessing a bonus
value, so this score never exceeds 100. No point value in this module was
invented; every one is either a direct Observatory modifier or an explicit,
documented decision to omit one.

Sentinel intentionally diverges from Observatory in the following ways;
none of these are bugs, and none claim exact Observatory parity:

1. CSP is excluded from the numeric score entirely (see above).
2. HSTS's "six months" threshold uses 15,552,000 seconds, matching
   Observatory's actual runtime analyzer behavior, rather than the
   15,768,000 seconds mentioned in Observatory's own published score-table
   description text (the two published pieces of Observatory's own project
   disagree with each other; Sentinel follows the code that actually runs
   -- see backend.http_findings.HSTS_SIX_MONTHS_SECONDS).
3. Sentinel parses HSTS max-age strictly (ASCII digits only; no negative
   signs, underscores, or non-ASCII Unicode digits; a repeated max-age
   directive within one policy is invalid) rather than mirroring permissive
   JavaScript Number.parseInt behavior -- see
   backend.http_findings._parse_hsts_max_age.
4. Sentinel treats an X-Frame-Options ALLOW-FROM value as not providing
   framing protection, contributing to the framing-protection deduction if
   no CSP frame-ancestors directive protects instead. Observatory gives
   ALLOW-FROM a neutral 0-point modifier. ALLOW-FROM is obsolete and
   ignored by all current major browsers, so Sentinel treats it as
   providing no real protection rather than matching Observatory's neutral
   treatment of an effectively obsolete mechanism -- see
   backend.http_findings._is_valid_x_frame_options.
"""

from dataclasses import dataclass

from backend.http_findings import (
    classify_referrer_policy,
    classify_strict_transport_security,
    evaluate_framing_protection,
)
from backend.http_models import (
    FramingProtectionClassification,
    HstsClassification,
    HttpScoreDeduction,
    HttpSecurityScore,
    NormalizedSecurityHeaders,
    ReferrerPolicyClassification,
)


BASE_SCORE = 100
MINIMUM_SCORE = 0

METHODOLOGY = (
    "Sentinel HTTP Security Configuration Score. This is a Sentinel-"
    "specific assessment, not an official MDN HTTP Observatory score, and "
    "not an overall measure of website security -- it is not a percentage "
    "of how secure a site is. It applies a documented subset of MDN HTTP "
    "Observatory-style point deductions to the HTTP response header "
    "controls Sentinel can currently evaluate with enough fidelity to "
    "score defensibly: Strict-Transport-Security (HSTS), a combined "
    "framing-protection control (X-Frame-Options and/or CSP "
    "frame-ancestors), Referrer-Policy, and X-Content-Type-Options. "
    "Content-Security-Policy is evaluated and reported as findings, but is "
    "intentionally excluded from this numeric score: Sentinel's CSP "
    "evaluator does not yet faithfully reproduce enough of MDN HTTP "
    "Observatory's CSP analyzer (nonce/hash and 'strict-dynamic' "
    "interaction with 'unsafe-inline', per-directive data: handling, "
    "style-src 'unsafe-eval', scheme-based active-content checks) to "
    "assign a defensible CSP point value, so its score contribution is "
    "always 0. Permissions-Policy is observed and reported as a Sentinel "
    "finding but is excluded from the numeric score, since there is no "
    "corresponding Observatory test to base a point value on. Cookies, "
    "CORS, Cross-Origin-Resource-Policy, Subresource-Integrity, and "
    "redirect behavior are not evaluated by Sentinel at all and are "
    "excluded from this score rather than silently treated as passing. "
    "Sentinel does not award "
    "Observatory's positive bonus modifiers (for example HSTS preloading, "
    "or a Referrer-Policy/framing-protection pass), so this score never "
    "exceeds 100. TLS certificate health is assessed separately and is "
    "never combined into this numeric score. This score does not claim "
    "exact parity with MDN HTTP Observatory: Sentinel's HSTS six-month "
    "threshold follows Observatory's current runtime analyzer behavior "
    "(15,552,000 seconds) rather than its published score-table "
    "description (15,768,000 seconds), Sentinel parses HSTS max-age "
    "stricter than permissive JavaScript number parsing, and Sentinel "
    "treats an obsolete X-Frame-Options ALLOW-FROM value as not providing "
    "framing protection, stricter than Observatory's neutral treatment, "
    "because ALLOW-FROM is unsupported by modern browsers. A high score "
    "reflects the presence of a subset of recommended HTTP security "
    "controls; it is not proof that a website is free of vulnerabilities."
)

_GRADE_BANDS: tuple[tuple[int, str], ...] = (
    (100, "A+"),
    (90, "A"),
    (85, "A-"),
    (80, "B+"),
    (70, "B"),
    (65, "B-"),
    (60, "C+"),
    (50, "C"),
    (45, "C-"),
    (40, "D+"),
    (30, "D"),
    (25, "D-"),
)


def calculate_grade(score: int) -> str:
    """Map a numeric score to a letter grade using the project's adopted
    grade bands. Accepts any integer: scores at or above 100 map to A+
    (Sentinel's scoring never actually produces a score above 100, since
    it awards no positive bonuses, but this function does not assume
    that -- see MINIMUM_SCORE/BASE_SCORE and _clamp_score for where the
    scoring path itself enforces bounds)."""
    for threshold, grade in _GRADE_BANDS:
        if score >= threshold:
            return grade
    return "F"


def _clamp_score(raw_score: int) -> int:
    """Clamp an aggregated raw score to Sentinel's valid range. Kept as a
    standalone function so the aggregation/clamping step is testable in
    isolation from header parsing."""
    return max(raw_score, MINIMUM_SCORE)


@dataclass(frozen=True)
class _ControlDeduction:
    control: str
    points: int
    reason: str


def _hsts_deduction(
    headers: NormalizedSecurityHeaders,
) -> _ControlDeduction | None:
    header = headers.strict_transport_security
    control = "strict-transport-security"

    if not header.present:
        # Observatory: HstsNotImplemented (-20)
        return _ControlDeduction(
            control, 20, "Strict-Transport-Security header is missing."
        )
    if not header.value:
        # Observatory: HstsHeaderInvalid (-20). An empty header cannot
        # carry a max-age directive, so it is treated the same as an
        # unparseable one.
        return _ControlDeduction(
            control,
            20,
            "Strict-Transport-Security header is present but empty.",
        )

    evaluation = classify_strict_transport_security(header)
    assert evaluation is not None  # header is present and non-empty here

    if evaluation.classification is HstsClassification.INVALID:
        # Observatory: HstsHeaderInvalid (-20)
        return _ControlDeduction(
            control,
            20,
            "Strict-Transport-Security header could not be parsed.",
        )
    if evaluation.classification is HstsClassification.DISABLED:
        # Observatory has no dedicated "disabled" modifier: max-age=0 falls
        # into its "less than six months" bucket, HstsImplementedMaxAge
        # LessThanSixMonths (-10). Sentinel keeps the same point value but
        # reports a more specific reason for explainability.
        return _ControlDeduction(
            control,
            10,
            "Strict-Transport-Security max-age is set to 0, disabling "
            "HSTS.",
        )
    if evaluation.classification is HstsClassification.SHORT_DURATION:
        # Observatory: HstsImplementedMaxAgeLessThanSixMonths (-10)
        return _ControlDeduction(
            control,
            10,
            f"Strict-Transport-Security max-age of {evaluation.max_age} "
            "seconds is below the six-month threshold.",
        )
    # ACCEPTABLE and STRONG both match Observatory's
    # HstsImplementedMaxAgeAtLeastSixMonths (0). Sentinel does not check
    # the HSTS preload list, so it does not award Observatory's separate
    # +5 preload bonus, and it does not invent an extra bonus for
    # exceeding six months.
    return None


def _csp_deduction() -> _ControlDeduction | None:
    """Content-Security-Policy's numeric score contribution.

    Always returns None (no deduction, regardless of the CSP finding or
    classification): CSP is intentionally excluded from Sentinel's numeric
    score. See the module docstring / METHODOLOGY for the full rationale.
    Sentinel still evaluates and reports CSP findings/classification (see
    backend.http_findings.classify_content_security_policy) -- CSP
    analysis is not removed from Sentinel, only from the score.
    """
    return None


def _framing_protection_deduction(
    headers: NormalizedSecurityHeaders,
) -> _ControlDeduction | None:
    control = "framing-protection"
    evaluation = evaluate_framing_protection(headers)
    if (
        evaluation.classification
        is FramingProtectionClassification.NOT_PROTECTED
    ):
        # Observatory: XFrameOptionsNotImplemented (-20). Sentinel awards
        # this single deduction regardless of whether the failure is due
        # to a missing/invalid/ALLOW-FROM X-Frame-Options header, a
        # missing CSP, or a CSP without a restrictive frame-ancestors
        # directive, so the two mechanisms are never double-counted in
        # either direction. See backend.http_findings
        # ._is_valid_x_frame_options for the documented ALLOW-FROM
        # divergence from Observatory's neutral treatment.
        return _ControlDeduction(
            control,
            20,
            "Neither a restrictive CSP frame-ancestors directive nor a "
            "valid X-Frame-Options value (DENY or SAMEORIGIN) was "
            "observed.",
        )
    # Observatory awards a +5 bonus for XFrameOptionsSameoriginOrDeny /
    # XFrameOptionsImplementedViaCsp. Sentinel does not award this bonus
    # (see module docstring on capping the score at 100).
    return None


def _referrer_policy_deduction(
    headers: NormalizedSecurityHeaders,
) -> _ControlDeduction | None:
    header = headers.referrer_policy
    control = "referrer-policy"

    if not header.present:
        # Observatory: ReferrerPolicyNotImplemented (0) -- a missing
        # Referrer-Policy is not penalized.
        return None
    if not header.value:
        # Observatory: ReferrerPolicyHeaderInvalid (-5)
        return _ControlDeduction(
            control, 5, "Referrer-Policy header is present but empty."
        )

    classification = classify_referrer_policy(header)
    if classification is ReferrerPolicyClassification.UNSAFE:
        # Observatory: ReferrerPolicyUnsafe (-5)
        return _ControlDeduction(
            control,
            5,
            "Referrer-Policy is set to a value that shares the full "
            "referrer URL across origins or on downgrade.",
        )
    if classification is ReferrerPolicyClassification.INVALID:
        # Observatory: ReferrerPolicyHeaderInvalid (-5)
        return _ControlDeduction(
            control, 5, "Referrer-Policy value is not recognized."
        )
    # STRONG matches Observatory's ReferrerPolicyPrivate, which is a +5
    # bonus there. Sentinel does not award this bonus (see module
    # docstring on capping the score at 100).
    return None


def _x_content_type_options_deduction(
    headers: NormalizedSecurityHeaders,
) -> _ControlDeduction | None:
    header = headers.x_content_type_options
    control = "x-content-type-options"

    if not header.present:
        # Observatory: XContentTypeOptionsNotImplemented (-5)
        return _ControlDeduction(
            control, 5, "X-Content-Type-Options header is missing."
        )
    if not header.value or header.value.casefold() != "nosniff":
        # Observatory: XContentTypeOptionsHeaderInvalid (-5). This also
        # covers an empty header value, which cannot be "nosniff".
        return _ControlDeduction(
            control,
            5,
            "X-Content-Type-Options is not set to nosniff.",
        )
    # Observatory: XContentTypeOptionsNosniff (0)
    return None


def calculate_http_security_score(
    headers: NormalizedSecurityHeaders,
) -> HttpSecurityScore:
    """Compute Sentinel's HTTP Security Configuration Score for a set of
    normalized security headers. Deterministic and side-effect free."""
    control_deductions = (
        _hsts_deduction(headers),
        _csp_deduction(),
        _framing_protection_deduction(headers),
        _referrer_policy_deduction(headers),
        _x_content_type_options_deduction(headers),
    )

    deductions = tuple(
        HttpScoreDeduction(
            control=deduction.control,
            points=deduction.points,
            reason=deduction.reason,
        )
        for deduction in control_deductions
        if deduction is not None
    )

    raw_score = BASE_SCORE - sum(deduction.points for deduction in deductions)
    score = _clamp_score(raw_score)

    return HttpSecurityScore(
        score=score,
        grade=calculate_grade(score),
        methodology=METHODOLOGY,
        deductions=deductions,
    )
