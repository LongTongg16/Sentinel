from backend.http_models import (
    CspClassification,
    CspEvaluation,
    CspWeakness,
    FramingProtectionClassification,
    FramingProtectionEvaluation,
    HstsClassification,
    HstsEvaluation,
    HttpHeaderFinding,
    HttpHeaderFindingCode,
    NormalizedSecurityHeaders,
    ReferrerPolicyClassification,
    SecurityHeaderValue,
)
from backend.tls_models import FindingSeverity


# Six months, in seconds. MDN HTTP Observatory's own source is internally
# inconsistent about this number: its published score-table description
# text says "15768000" (the calendar-precise 365.25/2 days), but its actual
# runtime analyzer (src/analyzer/tests/strict-transport-security.js) checks
# against 15_552_000 (180 days) instead, with a source comment explicitly
# calling 15768000 a stricter value than what "a lot of sites use". Sentinel
# follows the runtime analyzer's behavior -- 15_552_000 -- since that is
# what the tool actually enforces, not the description text. This is a
# documented Sentinel methodology choice, not a claim that Sentinel's
# threshold matches every part of Observatory's own documentation.
HSTS_SIX_MONTHS_SECONDS = 15_552_000
# One year, in seconds. A max-age at least this long is classified as
# "strong" rather than merely "acceptable". This is Sentinel-specific
# extra granularity: MDN HTTP Observatory does not award additional score
# credit beyond its six-month threshold (short of HSTS preloading, which
# Sentinel does not check), so "strong" carries the same 0-point modifier
# as "acceptable" -- see backend.http_scoring.
HSTS_ONE_YEAR_SECONDS = 31_536_000

# Wildcard/broad CSP sources that make a directive meaningless, and the
# unsafe-inline-equivalent sources, taken from MDN HTTP Observatory's CSP
# analyzer (src/analyzer/tests/csp.js: DANGEROUSLY_BROAD / UNSAFE_INLINE).
_CSP_DANGEROUSLY_BROAD_SOURCES = frozenset(
    {
        "ftp:",
        "http:",
        "https:",
        "*",
        "http://*",
        "http://*.*",
        "https://*",
        "https://*.*",
    }
)
_CSP_UNSAFE_INLINE_SOURCES = frozenset({"'unsafe-inline'", "data:"})
_CSP_DANGEROUSLY_BROAD_OR_UNSAFE_INLINE = (
    _CSP_DANGEROUSLY_BROAD_SOURCES | _CSP_UNSAFE_INLINE_SOURCES
)

_REFERRER_POLICY_STRONG_VALUES = frozenset(
    {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
)
_REFERRER_POLICY_UNSAFE_VALUES = frozenset(
    {
        "origin",
        "origin-when-cross-origin",
        "unsafe-url",
        "no-referrer-when-downgrade",
    }
)
_REFERRER_POLICY_KNOWN_VALUES = (
    _REFERRER_POLICY_STRONG_VALUES | _REFERRER_POLICY_UNSAFE_VALUES
)

_VALID_X_FRAME_OPTIONS_VALUES = frozenset({"deny", "sameorigin"})


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


def _parse_hsts_max_age(raw_value: str) -> int | None:
    """Parse an HSTS max-age value strictly, per HTTP's delta-seconds
    grammar (1*DIGIT, ASCII digits only). This deliberately rejects things
    Python's int() would otherwise silently accept, none of which are
    valid in this grammar: a leading sign (so "-5" is rejected as invalid
    rather than parsed as -5), underscore digit-group separators (e.g.
    "15_552_000"), and non-ASCII Unicode decimal digits (e.g. fullwidth or
    Arabic-Indic digits, which str.isdigit() alone would accept). This is
    a Sentinel-specific stricter parsing choice: Sentinel does not attempt
    to mirror Observatory's more permissive JavaScript Number.parseInt
    behavior, since being lenient here would accept header values no real
    HTTP client should ever produce or honor.

    A max-age value with an implausibly large number of digits (still
    well within the overall HTTP header-size limit Sentinel's collector
    already enforces) is treated as invalid HSTS, the same as any other
    unparseable value, rather than raised as an exception: Python's int()
    enforces its own maximum digit-string length (see
    sys.set_int_max_str_digits, default 4300) to avoid quadratic-time
    integer parsing, and raises ValueError past that length. Without
    catching it here, a single oversized max-age header would crash the
    request instead of simply scoring as invalid.
    """
    if not raw_value or not raw_value.isascii() or not raw_value.isdigit():
        return None
    try:
        return int(raw_value)
    except ValueError:
        return None


def classify_strict_transport_security(
    header: SecurityHeaderValue,
) -> HstsEvaluation | None:
    """Classify a present, non-empty Strict-Transport-Security header.

    Returns None if the header is missing or empty; callers already handle
    those cases via _missing_or_empty_finding and should not double-report
    them.
    """
    if not header.present or not header.value:
        return None

    value = header.value

    # normalize_security_headers joins repeated header instances with ", ".
    # A comma anywhere therefore means the header was sent more than once,
    # which HSTS treats as invalid (mirrors MDN HTTP Observatory's explicit
    # "Header set multiple times" check).
    if "," in value:
        return HstsEvaluation(HstsClassification.INVALID, None, False)

    max_age: int | None = None
    max_age_seen = False
    include_subdomains = False
    for part in value.split(";"):
        token = part.strip()
        if not token:
            continue
        lowered = token.casefold()
        if lowered.startswith("max-age="):
            # Sentinel-specific stricter parsing: a repeated max-age
            # directive within a single policy is treated as invalid
            # rather than silently keeping the last value (which is what
            # Observatory's runtime analyzer does).
            if max_age_seen:
                return HstsEvaluation(
                    HstsClassification.INVALID, None, include_subdomains
                )
            max_age_seen = True
            raw_number = token[len("max-age=") :].strip()
            max_age = _parse_hsts_max_age(raw_number)
            if max_age is None:
                return HstsEvaluation(
                    HstsClassification.INVALID, None, include_subdomains
                )
        elif lowered == "includesubdomains":
            include_subdomains = True
        # "preload" and any other directive are observed but not acted on:
        # Sentinel does not check the HSTS preload list.

    if max_age is None:
        return HstsEvaluation(
            HstsClassification.INVALID, None, include_subdomains
        )
    if max_age == 0:
        return HstsEvaluation(
            HstsClassification.DISABLED, max_age, include_subdomains
        )
    if max_age < HSTS_SIX_MONTHS_SECONDS:
        return HstsEvaluation(
            HstsClassification.SHORT_DURATION, max_age, include_subdomains
        )
    if max_age < HSTS_ONE_YEAR_SECONDS:
        return HstsEvaluation(
            HstsClassification.ACCEPTABLE, max_age, include_subdomains
        )
    return HstsEvaluation(
        HstsClassification.STRONG, max_age, include_subdomains
    )


def _split_csp_policies(value: str) -> list[str]:
    """Split a raw (possibly-normalized) CSP header value into individual
    enforced policies.

    Per RFC 9110 5.3, multiple Content-Security-Policy header field lines
    are combined into one field value by concatenating with ", " --
    backend.http_headers.normalize_security_headers does exactly this. Per
    CSP3 2.2.1, a comma is not valid within a single directive's source
    grammar, so splitting a combined value on "," unambiguously recovers
    the original per-policy boundaries. This mirrors MDN HTTP Observatory's
    own splitCspHeaders helper (src/analyzer/tests/csp.js).

    Without this split, a value like "default-src *, frame-ancestors
    'none'" (two separate enforced policies joined by normalization) would
    otherwise be parsed as a single directive stream, corrupting both
    directives -- frame-ancestors would never be recognized, and
    default-src's source list would be contaminated with stray tokens.
    """
    return [policy.strip() for policy in value.split(",") if policy.strip()]


def _parse_csp_directives(value: str) -> dict[str, tuple[str, ...]]:
    """Parse a single CSP policy (already split from any sibling policies
    by _split_csp_policies) into directive name -> source tokens.

    This is intentionally small and does not implement the full CSP
    grammar (no nonce/hash/strict-dynamic handling, no report-uri
    parsing). Only the first occurrence of a directive name within this
    one policy is kept, matching common browser behavior of ignoring
    duplicates.
    """
    directives: dict[str, tuple[str, ...]] = {}
    for segment in value.split(";"):
        tokens = segment.split()
        if not tokens:
            continue
        name = tokens[0].casefold()
        if name in directives:
            continue
        directives[name] = tuple(tokens[1:])
    return directives


def _parse_csp_policies(value: str) -> dict[str, tuple[str, ...]]:
    """Parse a raw (possibly multi-policy) CSP header value into one
    merged directive map, for use by the general CSP classification
    (missing/invalid/weak/meaningful) only.

    When the same directive name appears in more than one comma-separated
    policy, Sentinel takes the union of their source tokens rather than
    keeping only the first policy's value. Enforcing multiple CSP
    policies simultaneously is at least as strict as any one of them (a
    resource must satisfy all policies at once); taking the union when
    checking for weak/dangerous patterns is a deliberately conservative
    choice so Sentinel does not under-report a weakness that exists in at
    least one of the policies.

    This union is NOT valid for frame-ancestors: unlike a weak script-src
    source (where "present in any policy" is the right question), framing
    protection is genuinely provided if ANY single separately-enforced
    policy restricts it, regardless of what any other policy allows --
    unioning "'none'" from one policy with "*" from another would
    incorrectly conclude framing is unprotected. Framing protection
    therefore evaluates frame-ancestors per policy directly (see
    _csp_frame_ancestors_protects) instead of reading it from this merged
    map, and the merged map returned here no longer carries a
    frame-ancestors entry that anything relies on for that purpose.
    """
    merged: dict[str, list[str]] = {}
    for policy in _split_csp_policies(value):
        for name, tokens in _parse_csp_directives(policy).items():
            merged.setdefault(name, []).extend(tokens)
    return {name: tuple(tokens) for name, tokens in merged.items()}


def _csp_sources_for(
    directives: dict[str, tuple[str, ...]], name: str
) -> tuple[str, ...]:
    """Resolve a directive's effective source list, falling back to
    default-src and then to a wildcard when neither is specified -- the
    same fallback CSP itself defines and that MDN HTTP Observatory relies
    on for its script-src/object-src checks."""
    if name in directives:
        return directives[name]
    if "default-src" in directives:
        return directives["default-src"]
    return ("*",)


def classify_content_security_policy(
    header: SecurityHeaderValue,
) -> CspEvaluation | None:
    """Classify a present, non-empty Content-Security-Policy header.

    Returns None if the header is missing or empty; callers already handle
    those cases via _missing_or_empty_finding and should not double-report
    them.
    """
    if not header.present or not header.value:
        return None

    directives = _parse_csp_policies(header.value)
    if not directives:
        return CspEvaluation(CspClassification.INVALID, None)

    script_src = _csp_sources_for(directives, "script-src")
    object_src = _csp_sources_for(directives, "object-src")

    broad_or_unsafe = any(
        token.casefold() in _CSP_DANGEROUSLY_BROAD_OR_UNSAFE_INLINE
        for token in (*script_src, *object_src)
    )
    if broad_or_unsafe:
        return CspEvaluation(
            CspClassification.WEAK,
            CspWeakness.UNSAFE_OR_BROAD_SOURCES,
        )

    unsafe_eval = any(
        token.casefold() == "'unsafe-eval'" for token in script_src
    )
    if unsafe_eval:
        return CspEvaluation(
            CspClassification.WEAK,
            CspWeakness.UNSAFE_EVAL_ONLY,
        )

    return CspEvaluation(CspClassification.MEANINGFUL, None)


def _frame_ancestors_restricts_framing(
    frame_ancestors: tuple[str, ...] | None,
) -> bool:
    if not frame_ancestors:
        return False
    return not any(
        token.casefold() in _CSP_DANGEROUSLY_BROAD_SOURCES
        for token in frame_ancestors
    )


def _policy_frame_ancestors_protects(policy: str) -> bool:
    """Whether a single enforced CSP policy's own frame-ancestors
    directive (if any) restricts framing. Operates on one already-split
    policy string (see _split_csp_policies), never a merged multi-policy
    map, so a restrictive policy is never diluted by a sibling policy's
    more permissive frame-ancestors value."""
    directives = _parse_csp_directives(policy)
    return _frame_ancestors_restricts_framing(directives.get("frame-ancestors"))


def _csp_frame_ancestors_protects(csp_header: SecurityHeaderValue) -> bool:
    """Whether framing is protected by CSP frame-ancestors, considering
    each separately enforced policy on its own terms.

    Each Content-Security-Policy header field line is an independently
    enforced policy; multiple field lines are combined into one field
    value (comma-joined) by normalize_security_headers. A browser must
    satisfy all enforced policies simultaneously, so if any single policy
    restricts frame-ancestors, that restriction is real and enforced
    regardless of what a sibling policy allows -- e.g. one policy with
    "frame-ancestors 'none'" and another with "frame-ancestors *" still
    results in framing being blocked. This is why frame-ancestors is
    evaluated per policy here rather than through the general merged CSP
    classification (see _parse_csp_policies), which is not valid for this
    directive.
    """
    if not csp_header.present or not csp_header.value:
        return False
    return any(
        _policy_frame_ancestors_protects(policy)
        for policy in _split_csp_policies(csp_header.value)
    )


def _is_valid_x_frame_options(value: str) -> bool:
    """Return whether an X-Frame-Options value provides real framing
    protection in current browsers.

    Sentinel-specific divergence from MDN HTTP Observatory: Observatory
    recognizes ALLOW-FROM as a distinct, syntactically-valid outcome
    (XFrameOptionsAllowFromOrigin) with a neutral 0-point score modifier.
    ALLOW-FROM is obsolete and ignored by all current major browsers, so
    it provides no actual framing protection today. Sentinel deliberately
    treats it the same as any other invalid X-Frame-Options value (not
    protecting, and contributing to the framing-protection deduction if
    no CSP frame-ancestors directive protects instead) rather than
    matching Observatory's neutral treatment of an effectively obsolete
    mechanism. This is not a claim of exact Observatory parity.
    """
    return value.strip().casefold() in _VALID_X_FRAME_OPTIONS_VALUES


def evaluate_framing_protection(
    headers: NormalizedSecurityHeaders,
) -> FramingProtectionEvaluation:
    """Combine X-Frame-Options and CSP frame-ancestors into a single
    framing-protection control, per the project's decision not to score
    X-Frame-Options in isolation or double-count both mechanisms.

    Deliberately does not take a CspEvaluation: frame-ancestors is
    consumed here, and only here, directly from the raw
    Content-Security-Policy header via _csp_frame_ancestors_protects,
    which evaluates each separately enforced policy on its own terms
    rather than through the general CSP classification's merged
    directives (not valid for this directive -- see
    _csp_frame_ancestors_protects).
    """
    via_csp = _csp_frame_ancestors_protects(headers.content_security_policy)

    frame_options = headers.x_frame_options
    via_xfo = bool(
        frame_options.present
        and frame_options.value
        and _is_valid_x_frame_options(frame_options.value)
    )

    protected = via_csp or via_xfo
    return FramingProtectionEvaluation(
        classification=(
            FramingProtectionClassification.PROTECTED
            if protected
            else FramingProtectionClassification.NOT_PROTECTED
        ),
        via_csp_frame_ancestors=via_csp,
        via_x_frame_options=via_xfo,
    )


def classify_referrer_policy(
    header: SecurityHeaderValue,
) -> ReferrerPolicyClassification | None:
    """Classify a present, non-empty Referrer-Policy header.

    Returns None if the header is missing or empty; callers already handle
    those cases via _missing_or_empty_finding and should not double-report
    them.
    """
    if not header.present or not header.value:
        return None

    # A single header can list multiple tokens, and normalize_security_headers
    # joins repeated header instances with ", ". Browsers apply the last
    # recognized token in that combined list, so Sentinel does the same.
    candidates = [part.strip().casefold() for part in header.value.split(",")]
    recognized = [
        value for value in candidates if value in _REFERRER_POLICY_KNOWN_VALUES
    ]
    if not recognized:
        return ReferrerPolicyClassification.INVALID

    last = recognized[-1]
    if last in _REFERRER_POLICY_STRONG_VALUES:
        return ReferrerPolicyClassification.STRONG
    return ReferrerPolicyClassification.UNSAFE


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

    hsts_evaluation = classify_strict_transport_security(
        headers.strict_transport_security
    )
    if hsts_evaluation is not None:
        if hsts_evaluation.classification is HstsClassification.INVALID:
            findings.append(
                HttpHeaderFinding(
                    code=HttpHeaderFindingCode.INVALID_STRICT_TRANSPORT_SECURITY,
                    severity=FindingSeverity.WARNING,
                    message=(
                        "Strict-Transport-Security was present but could not "
                        "be parsed as a valid max-age directive."
                    ),
                )
            )
        elif hsts_evaluation.classification is HstsClassification.DISABLED:
            findings.append(
                HttpHeaderFinding(
                    code=HttpHeaderFindingCode.STRICT_TRANSPORT_SECURITY_DISABLED,
                    severity=FindingSeverity.WARNING,
                    message=(
                        "Strict-Transport-Security was present with "
                        "max-age=0, which disables HSTS for future visits."
                    ),
                )
            )
        elif hsts_evaluation.classification is HstsClassification.SHORT_DURATION:
            findings.append(
                HttpHeaderFinding(
                    code=(
                        HttpHeaderFindingCode.STRICT_TRANSPORT_SECURITY_SHORT_MAX_AGE
                    ),
                    severity=FindingSeverity.WARNING,
                    message=(
                        f"Strict-Transport-Security's max-age of "
                        f"{hsts_evaluation.max_age} seconds is below the "
                        f"{HSTS_SIX_MONTHS_SECONDS}-second (about six "
                        "month) threshold generally recommended for a "
                        "meaningful HSTS policy."
                    ),
                )
            )

    csp_evaluation = classify_content_security_policy(
        headers.content_security_policy
    )
    if csp_evaluation is not None:
        if csp_evaluation.classification is CspClassification.INVALID:
            findings.append(
                HttpHeaderFinding(
                    code=HttpHeaderFindingCode.INVALID_CONTENT_SECURITY_POLICY,
                    severity=FindingSeverity.WARNING,
                    message=(
                        "Content-Security-Policy was present but did not "
                        "contain any recognizable directives."
                    ),
                )
            )
        elif csp_evaluation.classification is CspClassification.WEAK:
            if csp_evaluation.weakness is CspWeakness.UNSAFE_EVAL_ONLY:
                message = (
                    "Content-Security-Policy allows 'unsafe-eval' in "
                    "script-src, which weakens protection against script "
                    "injection."
                )
            else:
                message = (
                    "Content-Security-Policy allows an overly broad or "
                    "unsafe-inline/data: source in script-src or "
                    "object-src, which substantially weakens the policy."
                )
            findings.append(
                HttpHeaderFinding(
                    code=HttpHeaderFindingCode.WEAK_CONTENT_SECURITY_POLICY,
                    severity=FindingSeverity.WARNING,
                    message=message,
                )
            )

    framing_evaluation = evaluate_framing_protection(headers)
    if (
        framing_evaluation.classification
        is FramingProtectionClassification.NOT_PROTECTED
    ):
        findings.append(
            HttpHeaderFinding(
                code=HttpHeaderFindingCode.FRAMING_NOT_PROTECTED,
                severity=FindingSeverity.WARNING,
                message=(
                    "Neither a restrictive CSP frame-ancestors directive "
                    "nor a valid X-Frame-Options value (DENY or "
                    "SAMEORIGIN) was observed, so framing protection was "
                    "not confirmed."
                ),
            )
        )

    referrer_classification = classify_referrer_policy(headers.referrer_policy)
    if referrer_classification is ReferrerPolicyClassification.UNSAFE:
        findings.append(
            HttpHeaderFinding(
                code=HttpHeaderFindingCode.UNSAFE_REFERRER_POLICY,
                severity=FindingSeverity.INFO,
                message=(
                    "Referrer-Policy was set to a value that shares the "
                    "full referrer URL across origins or on downgrade, "
                    "which is considered unsafe."
                ),
            )
        )
    elif referrer_classification is ReferrerPolicyClassification.INVALID:
        findings.append(
            HttpHeaderFinding(
                code=HttpHeaderFindingCode.INVALID_REFERRER_POLICY,
                severity=FindingSeverity.INFO,
                message=(
                    "Referrer-Policy was present but its value was not "
                    "recognized."
                ),
            )
        )

    return tuple(findings)
