# Sentinel

**A passive website security configuration checker for TLS certificates and HTTP security controls.**

Sentinel analyzes publicly observable website security configuration without exploiting, authenticating to, or actively attacking the target.

Given a hostname, Sentinel performs SSRF-aware network collection, establishes a verified TLS connection, analyzes the site's X.509 leaf certificate and HTTP security headers, and presents structured findings through a React interface.

It also produces an explainable **HTTP Security Configuration Score** based on a deliberately limited set of controls that Sentinel can evaluate reliably.

---

## Why I Built Sentinel

Security scanners often produce findings without making it obvious how those findings were derived.

I built Sentinel to explore a different approach: collect observable security configuration, separate the evidence from the evaluation logic, and make each result explainable.

The project has also been a practical way for me to develop deeper experience with:

- secure network programming
- TLS and X.509 certificates
- HTTP security controls
- SSRF mitigation
- defensive input handling
- API architecture
- automated testing
- full-stack security tooling

Sentinel is intentionally narrow in scope. It is a **security configuration checker**, not a vulnerability scanner or penetration-testing tool.

---

## What Sentinel Analyzes

### TLS & X.509

Sentinel establishes a verified TLS connection and analyzes the site's leaf certificate.

Currently implemented analysis includes:

- certificate subject
- certificate issuer
- validity period
- expiration status
- DNS Subject Alternative Names
- serial number
- signature algorithm
- public-key type
- public-key size
- SHA-256 certificate fingerprint
- weak MD5/SHA-1 signature detection

Certificate expiration findings distinguish between:

- expired certificates
- certificates expiring within 7 days
- certificates expiring within 30 days

Sentinel relies on the verified TLS handshake for hostname verification rather than attempting to reproduce certificate wildcard matching with custom string logic.

---

### HTTP Security Controls

Sentinel collects and evaluates selected HTTP response security headers.

Currently analyzed controls include:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options`
- CSP `frame-ancestors`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

The HTTP collector also handles:

- redirects
- redirect destination revalidation
- redirect loops
- bounded redirect counts
- overall request deadlines
- response-header size limits

Sentinel intentionally does not store or analyze response bodies as part of the current MVP.

---

## HTTP Security Configuration Score

Sentinel provides an explainable **0–100 HTTP Security Configuration Score** with a letter grade.

Rather than treating the score as an overall measure of whether a website is "secure," it represents only the HTTP configuration controls Sentinel currently evaluates.

Each deduction includes:

- the affected control
- points deducted
- the reason for the deduction

Currently scored controls are:

- HSTS
- framing protection
- Referrer-Policy
- X-Content-Type-Options

CSP and Permissions-Policy currently produce findings but are **not numerically scored**.

This is intentional.

During development, I found that simplified CSP scoring could create misleading deductions for valid modern policies. I chose to remove CSP from the numeric score until the evaluator can model its semantics with sufficient fidelity.

Sentinel's scoring methodology is Sentinel-specific and inspired by a documented subset of MDN HTTP Observatory-style deductions. It is **not** an official MDN Observatory score.

---

## Security-First Network Design

Because Sentinel accepts user-controlled hostnames and makes outbound network connections, the scanner itself creates an SSRF risk.

The network collection pipeline is therefore designed around explicit target validation.

```text
User hostname
      │
      ▼
Hostname validation
      │
      ▼
DNS resolution
      │
      ▼
IP address policy validation
      │
      ▼
Approved numeric IP
      │
      ▼
Network connection
```

Sentinel validates resolved addresses before connecting and rejects unsafe destination classes.

Connections are then made to the approved **numeric IP address** rather than allowing the networking layer to blindly resolve the hostname again.

For HTTPS connections, the original validated hostname is preserved for:

- Server Name Indication (SNI)
- certificate hostname verification

Redirect destinations are resolved and validated again before Sentinel follows them.

This design reduces exposure to DNS re-resolution and rebinding-style SSRF behavior while preserving correct TLS identity verification.

---

## Architecture

Sentinel separates network collection from security evaluation.

### TLS Pipeline

```text
hostname
   ↓
validation + DNS resolution
   ↓
approved numeric IP
   ↓
TCP/TLS connection
   ↓
verified TLS handshake
   ↓
leaf certificate DER
   ↓
X.509 parsing
   ↓
certificate findings
   ↓
FastAPI response
   ↓
React presentation
```

### HTTP Pipeline

```text
hostname
   ↓
validation + DNS resolution
   ↓
HTTP collection
   ↓
redirect validation
   ↓
normalized security headers
   ↓
security evaluation
   ↓
findings
   ↓
HTTP configuration score
   ↓
FastAPI response
   ↓
React presentation
```

The broader design follows the separation:

```text
Collection
    ↓
Normalization / Parsing
    ↓
Evaluation
    ↓
Findings
    ↓
Scoring (where applicable)
    ↓
Presentation
```

This keeps network behavior, parsing, security policy, scoring, and UI presentation from becoming tightly coupled.

TLS and HTTP analyses are also independent. If one analysis fails, Sentinel can still return and display results from the other.

---

## Tech Stack

### Backend

- Python
- FastAPI
- asyncio
- socket
- Python `ssl`
- `cryptography`
- Pydantic
- pytest

### Frontend

- JavaScript
- React
- Vite
- Tailwind CSS

### Engineering

- Git
- GitHub
- feature branches
- pull-request workflow
- automated backend testing

---

## API

Sentinel currently exposes two primary analysis endpoints.

### TLS Certificate Analysis

```text
POST /api/v1/tls/leaf-certificate
```

Performs validated TLS collection and returns structured certificate information and findings.

### HTTP Security Analysis

```text
POST /api/v1/http/security-headers
```

Collects HTTP security configuration and returns normalized security information, findings, and the HTTP configuration score.

---

## Testing

Sentinel currently has **257 passing backend tests**.

Run the backend test suite with:

```bash
python -m pytest backend/tests/
```

The test suite covers areas including:

- hostname validation
- SSRF address policies
- IPv4 and IPv6 handling
- 6to4 IPv6 edge cases
- DNS failures
- connection failures
- TLS verification failures
- network timeouts
- cancellation behavior
- socket ownership and cleanup
- certificate collection
- malformed certificate DER
- certificate expiration boundaries
- SAN extraction
- HTTP redirects
- redirect loops
- malformed HTTP responses
- HSTS parsing
- CSP policy parsing
- framing protection
- Referrer-Policy
- scoring boundaries
- deduction reconciliation
- API error mappings

TLS tests use static local certificate fixtures as well as certificates generated programmatically with `cryptography` for controlled test cases.

### Frontend Validation

The frontend is currently verified through:

- manual browser testing
- responsive rendering checks
- `npm run lint`
- `npm run build`
- partial TLS/HTTP failure testing
- malformed API response testing
- rescanning
- long header-value testing
- score and deduction rendering
- request timeout testing

Automated frontend testing is not yet implemented.

---

## Interesting Engineering Problems

Building Sentinel exposed several security and reliability edge cases that were easy to miss initially.

### 6to4 IPv6 and SSRF

A 6to4 IPv6 address can embed an IPv4 destination.

Initially, validating only the outer IPv6 representation could allow the embedded IPv4 policy to be overlooked.

Sentinel's address policy was updated so 6to4 handling also considers the embedded IPv4 address.

---

### TLS Resource Ownership

Async TLS collection required careful handling of socket ownership, stream cleanup, cancellation, and timeout precedence.

This reinforced an important lesson from the project:

> Resource cleanup is part of security and reliability, not just code hygiene.

---

### CSP Scoring

Early scoring logic attempted to numerically evaluate CSP.

That turned out to be misleading because modern CSP behavior includes semantics that a simplified evaluator cannot accurately represent.

Rather than preserve a more impressive-looking score, CSP was removed from numeric scoring while remaining available as a security finding.

---

### Defensive HSTS Parsing

Remote security headers are untrusted input.

An extremely large `max-age` value could exceed Python's integer-conversion limits.

Sentinel handles the resulting failure and treats the value as invalid instead of allowing malformed remote input to disrupt analysis.

---

### Multiple CSP Policies

Separately enforced CSP policies cannot always be safely treated as one merged policy.

Framing analysis was updated to evaluate repeated policies appropriately rather than producing an incorrect deduction from a merged representation.

---

## Current Limitations

Sentinel is a portfolio security-engineering project and should not be treated as a comprehensive security assessment platform.

The current MVP does **not** provide:

- vulnerability scanning
- exploitation
- penetration testing
- authenticated assessment
- cookie security analysis
- TLS protocol-version analysis
- cipher-suite analysis
- key-exchange analysis
- complete CSP semantic analysis
- CORS/CORP/SRI evaluation
- full certificate-chain analysis beyond standard TLS verification
- malware or phishing analysis
- user authentication
- persistent scan history
- database storage
- automated frontend tests
- production deployment
- verified CI/CD

The HTTP score also does **not** represent the overall security of a website.

These boundaries are deliberate. Sentinel reports only what it can support with observable evidence and implemented evaluation logic.

---

## Roadmap

The next areas I would like to explore include:

- deeper TLS protocol and cipher-suite analysis
- richer CSP evaluation
- automated frontend testing
- CI/CD
- production deployment

Future features will continue to follow the same principle:

**Prefer narrow, explainable, testable security analysis over broad claims that cannot be justified reliably.**

---

## Development Approach

Sentinel has been developed with substantial AI-assisted implementation using tools including Claude Code and Codex.

I use these tools as part of an engineering workflow that includes defining architecture and requirements, reviewing generated implementations, testing behavior, investigating failures, debugging security edge cases, and iterating on design decisions.

The goal of the project is not to demonstrate how many lines of code I can manually type. It is to develop and demonstrate my ability to understand security problems, reason about engineering tradeoffs, validate implementations, and build security software whose behavior I can explain.

---

## Project Status

**Working MVP**

Implemented:

- SSRF-aware target handling
- TLS certificate collection
- X.509 analysis
- HTTP security-header analysis
- explainable HTTP configuration scoring
- FastAPI backend
- React frontend
- backend automated testing
- architecture and methodology documentation

Currently improving:

- test coverage across the full stack
- security-analysis depth
- deployment and engineering workflow

---

## Disclaimer

Sentinel is intended for educational, defensive, and authorized security analysis.

It performs passive inspection of publicly observable website configuration and does not attempt exploitation or authenticated access.

A Sentinel result should not be interpreted as proof that a website is secure or insecure. Security configuration is only one part of a broader security assessment.
