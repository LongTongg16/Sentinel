export function makeTlsFinding(overrides = {}) {
  return {
    code: 'healthy_certificate',
    severity: 'info',
    message: 'The certificate passed the configured checks.',
    ...overrides,
  }
}

export function makeTlsSuccess(overrides = {}) {
  return {
    status: 'success',
    hostname: 'example.com',
    connected_ip: '203.0.113.10',
    certificate_sha256: 'AA:BB:CC:DD',
    subject: 'CN=example.com',
    issuer: 'CN=Example Test CA',
    valid_from: '2026-01-01T00:00:00Z',
    expires_at: '2027-01-01T00:00:00Z',
    days_remaining: 134,
    dns_names: ['example.com', 'www.example.com'],
    serial_number: '01ABCDEF',
    signature_algorithm: 'sha256WithRSAEncryption',
    public_key_type: 'RSA',
    public_key_size: 2048,
    findings: [makeTlsFinding()],
    ...overrides,
  }
}

export function makeHttpHeaders(overrides = {}) {
  return {
    strict_transport_security: {
      present: true,
      value: 'max-age=31536000',
    },
    content_security_policy: {
      present: true,
      value: "default-src 'self'",
    },
    x_content_type_options: { present: true, value: 'nosniff' },
    x_frame_options: { present: true, value: 'DENY' },
    referrer_policy: {
      present: true,
      value: 'strict-origin-when-cross-origin',
    },
    permissions_policy: { present: true, value: 'geolocation=()' },
    ...overrides,
  }
}

export function makeHttpScore(overrides = {}) {
  return {
    score: 100,
    grade: 'A+',
    methodology: 'A deterministic test methodology.',
    deductions: [],
    ...overrides,
  }
}

export function makeHttpSuccess(overrides = {}) {
  return {
    status: 'success',
    requested_hostname: 'example.com',
    connected_ip: '203.0.113.10',
    final_url: 'https://example.com/',
    final_hostname: 'example.com',
    http_status_code: 200,
    redirect_count: 0,
    headers: makeHttpHeaders(),
    findings: [],
    score: makeHttpScore(),
    ...overrides,
  }
}

export function makeTlsFailure(overrides = {}) {
  return {
    status: 'failure',
    stage: 'connect',
    code: 'connect_failure',
    ...overrides,
  }
}

export function makeHttpFailure(overrides = {}) {
  return {
    status: 'failure',
    stage: 'request',
    code: 'request_failure',
    ...overrides,
  }
}

export function successOutcome(result) {
  return { result, error: '' }
}

export function errorOutcome(error) {
  return { result: null, error }
}
