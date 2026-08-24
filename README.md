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
- automated backend and frontend testing

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

Sentinel has deterministic backend and frontend test suites.

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

Frontend tooling requires Node.js 22.13 or newer. GitHub Actions and the Render
Blueprint use Node.js 24.

Install the exact locked dependencies and run the automated frontend checks with:

```bash
cd frontend
npm ci
npm run test
npm run lint
npm run build
```

The Vitest and React Testing Library suite covers form validation, independent
TLS/HTTP outcomes, malformed API responses, rescanning, timeout classification,
accessibility semantics, and high-value rendering edge cases. Manual browser
and responsive checks remain useful for behavior outside jsdom.

---

## Render Deployment Configuration

Sentinel includes a [`render.yaml`](render.yaml) Blueprint for a small public
portfolio deployment with two services:

- `sentinel-api`: a Python 3.12.14 Render Web Service
- `sentinel-web`: a Node.js 24 Render Static Site built from `frontend/`

The backend starts from the repository root with:

```bash
uvicorn backend.main:app --host 0.0.0.0 --port $PORT
```

The static site installs the committed lockfile with `npm ci`, runs
`npm run build`, and publishes `frontend/dist`.

### Required deployment environment

Set these values to the exact public HTTPS origins assigned by Render. They are
public configuration, not secrets, and should not contain paths:

- Backend `SENTINEL_ALLOWED_ORIGINS`: comma-separated frontend origins, such as
  `https://<frontend-service>.onrender.com`. Wildcards and credential-bearing or
  path-bearing URLs are rejected.
- Frontend `VITE_API_BASE_URL`: the backend origin, such as
  `https://<backend-service>.onrender.com`. Trailing slashes are normalized.

The Blueprint also declares these non-secret defaults:

- `SENTINEL_MAX_CONCURRENT_SCANS=4`
- `SENTINEL_SCAN_QUEUE_TIMEOUT_SECONDS=1`
- `SENTINEL_RATE_LIMIT_REQUESTS=30`
- `SENTINEL_RATE_LIMIT_WINDOW_SECONDS=60`

Locally, leave `VITE_API_BASE_URL` unset. The frontend then calls the existing
relative `/api/v1/...` routes and the Vite development proxy forwards `/api` to
`http://127.0.0.1:8000`. When the backend CORS variable is unset, only
`http://localhost:5173` and `http://127.0.0.1:5173` are allowed by default.

### Deployment sequence

1. In Render, create a new Blueprint from this repository and review the two
   free-plan services before applying it.
2. Supply the exact frontend HTTPS origin for `SENTINEL_ALLOWED_ORIGINS` and the
   exact backend HTTPS origin for `VITE_API_BASE_URL` when prompted. Do not use
   `*` for CORS.
3. Confirm the backend health check path is `/health`, then apply the Blueprint.
4. If Render assigns a different service URL than expected, update the two
   cross-origin variables in the service dashboards and redeploy both services.
   Vite variables are embedded at frontend build time, so changing
   `VITE_API_BASE_URL` requires a new static-site build.
5. Verify `GET https://<backend-service>.onrender.com/health` returns only
   `{"status":"ok"}`, then submit a controlled hostname through the frontend.

The scan request budget is deliberately global and in-memory per backend
process. One frontend scan uses two requests (TLS and HTTP). Counts reset when a
process restarts and are not shared if the service is scaled to multiple
instances. Sentinel does not derive identity from `X-Forwarded-For`; this avoids
trusting a caller-controlled proxy chain, but means the limiter is not a
per-client fairness control. The concurrency cap is also per process. A request
that cannot obtain a shared TLS/HTTP scan permit within the configured one-second
queue timeout receives `503 Service Unavailable` before collection starts.
These are basic portfolio-deployment safeguards, not a substitute for
platform-level abuse monitoring or a distributed limiter.

On Render's free tier, an idle web service spins down and its next request can
incur a cold start. Free services are also subject to Render's service and
outbound-traffic limits. Blueprint environment variables declared with
`sync: false` are not copied into preview environments, so each preview needs
its own `SENTINEL_ALLOWED_ORIGINS` and `VITE_API_BASE_URL` values.

The unauthenticated `GET /health` route is excluded from scan admission and does
not perform DNS or network collection. Added application logging reports only
the configured admission limits at startup; it does not include target values,
headers, bodies, secrets, or tracebacks.

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
- a verified live public deployment
- distributed or durable abuse controls

The HTTP score also does **not** represent the overall security of a website.

These boundaries are deliberate. Sentinel reports only what it can support with observable evidence and implemented evaluation logic.

---

## Roadmap

The next areas I would like to explore include:

- deeper TLS protocol and cipher-suite analysis
- richer CSP evaluation
- deployment monitoring and live-environment validation

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
- frontend automated testing
- GitHub Actions CI
- Render deployment configuration
- architecture and methodology documentation

Currently improving:

- live deployment validation and monitoring
- security-analysis depth
- deployment and engineering workflow

---

## Disclaimer

Sentinel is intended for educational, defensive, and authorized security analysis.

It performs passive inspection of publicly observable website configuration and does not attempt exploitation or authenticated access.

A Sentinel result should not be interpreted as proof that a website is secure or insecure. Security configuration is only one part of a broader security assessment.
