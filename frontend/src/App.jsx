import { useState } from 'react'

const API_BASE_URL = '/api/v1'
const TLS_LEAF_CERTIFICATE_ENDPOINT = `${API_BASE_URL}/tls/leaf-certificate`
const HTTP_SECURITY_HEADERS_ENDPOINT = `${API_BASE_URL}/http/security-headers`
const SCAN_REQUEST_TIMEOUT_MS = 15000

const TLS_SUCCESS_STRING_FIELDS = [
  'hostname',
  'connected_ip',
  'certificate_sha256',
  'subject',
  'issuer',
  'valid_from',
  'expires_at',
  'serial_number',
  'signature_algorithm',
  'public_key_type',
]

const HTTP_SUCCESS_STRING_FIELDS = [
  'requested_hostname',
  'connected_ip',
  'final_url',
  'final_hostname',
]

const HTTP_HEADER_FIELDS = [
  { key: 'strict_transport_security', label: 'Strict-Transport-Security' },
  { key: 'content_security_policy', label: 'Content-Security-Policy' },
  { key: 'x_content_type_options', label: 'X-Content-Type-Options' },
  { key: 'x_frame_options', label: 'X-Frame-Options' },
  { key: 'referrer_policy', label: 'Referrer-Policy' },
  { key: 'permissions_policy', label: 'Permissions-Policy' },
]

function isFinding(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    typeof value.code === 'string' &&
    typeof value.severity === 'string' &&
    typeof value.message === 'string'
  )
}

function isTlsSuccessResponse(value) {
  return (
    value?.status === 'success' &&
    TLS_SUCCESS_STRING_FIELDS.every(
      (field) => typeof value[field] === 'string',
    ) &&
    Number.isInteger(value.days_remaining) &&
    Array.isArray(value.dns_names) &&
    value.dns_names.every((dnsName) => typeof dnsName === 'string') &&
    (value.public_key_size === null ||
      Number.isInteger(value.public_key_size)) &&
    Array.isArray(value.findings) &&
    value.findings.every(isFinding)
  )
}

function isSecurityHeaderValue(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    typeof value.present === 'boolean' &&
    (value.value === null || typeof value.value === 'string')
  )
}

function isNormalizedHeaders(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    HTTP_HEADER_FIELDS.every(({ key }) => isSecurityHeaderValue(value[key]))
  )
}

function isHttpSuccessResponse(value) {
  return (
    value?.status === 'success' &&
    HTTP_SUCCESS_STRING_FIELDS.every(
      (field) => typeof value[field] === 'string',
    ) &&
    Number.isInteger(value.http_status_code) &&
    Number.isInteger(value.redirect_count) &&
    isNormalizedHeaders(value.headers) &&
    Array.isArray(value.findings) &&
    value.findings.every(isFinding)
  )
}

function isFailureResponse(value) {
  return (
    value?.status === 'failure' &&
    typeof value.stage === 'string' &&
    typeof value.code === 'string'
  )
}

function displayText(value, fallback = 'Not available') {
  return typeof value === 'string' && value.trim() ? value : fallback
}

function formatDate(value) {
  if (typeof value !== 'string' || !value.trim()) {
    return 'Not available'
  }

  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return 'Not available'
  }

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date)
}

function formatDaysRemaining(value) {
  if (!Number.isInteger(value)) {
    return 'Not available'
  }

  return `${value} ${Math.abs(value) === 1 ? 'day' : 'days'}`
}

function formatPublicKey(type, size) {
  const displayType = displayText(type, '')
  const normalizedType = displayType ? displayType.toUpperCase() : ''

  if (Number.isInteger(size)) {
    return normalizedType
      ? `${normalizedType} — ${size} bits`
      : `${size} bits`
  }

  return normalizedType || 'Not applicable'
}

function severityPresentation(severity) {
  if (severity === 'critical') {
    return {
      label: 'Critical',
      symbol: '!',
      container:
        'border-rose-800 bg-rose-950/50 text-rose-100',
      badge: 'border-rose-700 bg-rose-900/70 text-rose-100',
    }
  }

  if (severity === 'warning') {
    return {
      label: 'Warning',
      symbol: '▲',
      container:
        'border-amber-700 bg-amber-950/40 text-amber-100',
      badge: 'border-amber-600 bg-amber-900/70 text-amber-100',
    }
  }

  if (severity === 'info') {
    return {
      label: 'Info',
      symbol: 'i',
      container:
        'border-emerald-800 bg-emerald-950/35 text-emerald-100',
      badge: 'border-emerald-700 bg-emerald-900/60 text-emerald-100',
    }
  }

  return {
    label: 'Unknown',
    symbol: '?',
    container: 'border-slate-700 bg-slate-900 text-slate-100',
    badge: 'border-slate-600 bg-slate-800 text-slate-200',
  }
}

function getSummarySeverity(findings) {
  if (findings.some((finding) => finding.severity === 'critical')) {
    return 'critical'
  }

  if (findings.some((finding) => finding.severity === 'warning')) {
    return 'warning'
  }

  if (findings.some((finding) => finding.severity === 'info')) {
    return 'info'
  }

  return 'unknown'
}

function MetadataItem({ label, children, monospace = false }) {
  return (
    <div className="min-w-0 rounded-lg border border-slate-800 bg-slate-950/50 p-4">
      <dt className="text-sm font-medium text-slate-400">{label}</dt>
      <dd
        className={`mt-2 min-w-0 text-sm text-slate-100 [overflow-wrap:anywhere] ${
          monospace ? 'font-mono' : ''
        }`}
      >
        {children}
      </dd>
    </div>
  )
}

function ScanSummary({ result }) {
  const summarySeverity = getSummarySeverity(result.findings)
  const presentation = severityPresentation(summarySeverity)

  return (
    <section
      className={`rounded-xl border p-5 sm:p-6 ${presentation.container}`}
      aria-labelledby="scan-summary-heading"
    >
      <p className="sr-only" role="status">
        Scan complete for {displayText(result.hostname)}. Certificate status:{' '}
        {presentation.label}.
      </p>
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <p className="text-sm font-semibold uppercase tracking-[0.16em] opacity-80">
            Scan complete
          </p>
          <h2
            className="mt-1 break-words text-xl font-semibold [overflow-wrap:anywhere]"
            id="scan-summary-heading"
          >
            {displayText(result.hostname)}
          </h2>
        </div>
        <span
          className={`inline-flex w-fit items-center gap-2 rounded-full border px-3 py-1.5 text-sm font-semibold ${presentation.badge}`}
        >
          <span
            aria-hidden="true"
            className="inline-flex size-5 items-center justify-center rounded-full border border-current text-xs"
          >
            {presentation.symbol}
          </span>
          Status: {presentation.label}
        </span>
      </div>

      <dl className="mt-5 grid gap-4 border-t border-current/20 pt-5 sm:grid-cols-2">
        <div className="min-w-0">
          <dt className="text-sm opacity-75">Connected IP</dt>
          <dd className="mt-1 break-all font-mono text-sm font-semibold">
            {displayText(result.connected_ip)}
          </dd>
        </div>
        <div>
          <dt className="text-sm opacity-75">Days remaining</dt>
          <dd className="mt-1 font-semibold">
            {formatDaysRemaining(result.days_remaining)}
          </dd>
        </div>
      </dl>
    </section>
  )
}

function CertificateDetails({ result }) {
  const dnsNames = result.dns_names.filter((dnsName) => dnsName.trim())

  return (
    <section
      className="rounded-xl border border-slate-800 bg-slate-900 p-5 sm:p-6"
      aria-labelledby="certificate-details-heading"
    >
      <h2
        className="text-xl font-semibold text-slate-100"
        id="certificate-details-heading"
      >
        Certificate details
      </h2>
      <p className="mt-2 text-sm text-slate-400">
        Factual metadata returned by the certificate scan.
      </p>

      <dl className="mt-5 grid min-w-0 gap-3 sm:grid-cols-2">
        <MetadataItem label="Hostname">
          {displayText(result.hostname)}
        </MetadataItem>
        <MetadataItem label="Connected IP" monospace>
          {displayText(result.connected_ip)}
        </MetadataItem>
        <MetadataItem label="Subject">
          {displayText(result.subject)}
        </MetadataItem>
        <MetadataItem label="Issuer">
          {displayText(result.issuer)}
        </MetadataItem>
        <MetadataItem label="Valid from">
          <time dateTime={result.valid_from || undefined}>
            {formatDate(result.valid_from)}
          </time>
        </MetadataItem>
        <MetadataItem label="Expires at">
          <time dateTime={result.expires_at || undefined}>
            {formatDate(result.expires_at)}
          </time>
        </MetadataItem>
        <MetadataItem label="Days remaining">
          {formatDaysRemaining(result.days_remaining)}
        </MetadataItem>
        <MetadataItem label="Public key">
          {formatPublicKey(result.public_key_type, result.public_key_size)}
        </MetadataItem>
        <MetadataItem label="Signature algorithm">
          {displayText(result.signature_algorithm)}
        </MetadataItem>
        <MetadataItem label="Serial number" monospace>
          {displayText(result.serial_number)}
        </MetadataItem>
        <div className="min-w-0 sm:col-span-2">
          <MetadataItem label="DNS SANs">
            {dnsNames.length > 0 ? (
              <ul className="flex min-w-0 flex-wrap gap-2" role="list">
                {dnsNames.map((dnsName, index) => (
                  <li
                    className="max-w-full rounded-md bg-slate-800 px-2.5 py-1 font-mono text-xs [overflow-wrap:anywhere]"
                    key={`${dnsName}-${index}`}
                  >
                    {dnsName}
                  </li>
                ))}
              </ul>
            ) : (
              'No DNS SAN entries'
            )}
          </MetadataItem>
        </div>
        <div className="min-w-0 sm:col-span-2">
          <MetadataItem label="SHA-256 fingerprint" monospace>
            <span className="break-all">
              {displayText(result.certificate_sha256)}
            </span>
          </MetadataItem>
        </div>
      </dl>
    </section>
  )
}

function FindingCard({ finding }) {
  const presentation = severityPresentation(finding.severity)

  return (
    <li
      className={`min-w-0 rounded-lg border p-4 ${presentation.container}`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span
          className={`inline-flex items-center gap-2 rounded-full border px-2.5 py-1 text-xs font-semibold uppercase tracking-wide ${presentation.badge}`}
        >
          <span
            aria-hidden="true"
            className="inline-flex size-4 items-center justify-center rounded-full border border-current text-[0.65rem]"
          >
            {presentation.symbol}
          </span>
          {presentation.label}
        </span>
        <code className="min-w-0 rounded bg-black/20 px-2 py-1 text-xs [overflow-wrap:anywhere]">
          {displayText(finding.code)}
        </code>
      </div>
      <p className="mt-3 break-words text-sm leading-6 [overflow-wrap:anywhere]">
        {displayText(finding.message)}
      </p>
    </li>
  )
}

function FindingsList({ findings, title, description, emptyMessage, headingId }) {
  return (
    <section
      className="rounded-xl border border-slate-800 bg-slate-900 p-5 sm:p-6"
      aria-labelledby={headingId}
    >
      <h2
        className="text-xl font-semibold text-slate-100"
        id={headingId}
      >
        {title}
      </h2>
      <p className="mt-2 text-sm text-slate-400">{description}</p>

      {findings.length > 0 ? (
        <ul className="mt-5 grid gap-3" role="list">
          {findings.map((finding, index) => (
            <FindingCard
              finding={finding}
              key={`${finding.code}-${index}`}
            />
          ))}
        </ul>
      ) : (
        <p className="mt-5 rounded-lg border border-slate-700 bg-slate-950/50 p-4 text-sm text-slate-300">
          {emptyMessage}
        </p>
      )}
    </section>
  )
}

function HeaderPresenceBadge({ present }) {
  return (
    <span
      className={`inline-flex w-fit shrink-0 items-center rounded-full border px-2.5 py-1 text-xs font-semibold uppercase tracking-wide ${
        present
          ? 'border-emerald-700 bg-emerald-900/60 text-emerald-100'
          : 'border-slate-600 bg-slate-800 text-slate-300'
      }`}
    >
      {present ? 'Present' : 'Missing'}
    </span>
  )
}

function HeaderRow({ header, label }) {
  const isPresent = header?.present === true
  const value = typeof header?.value === 'string' ? header.value : null
  const hasValue = value !== null && value.trim() !== ''

  return (
    <div className="min-w-0 rounded-lg border border-slate-800 bg-slate-950/50 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="min-w-0 break-words font-mono text-sm font-semibold text-slate-100 [overflow-wrap:anywhere]">
          {label}
        </span>
        <HeaderPresenceBadge present={isPresent} />
      </div>

      {isPresent && (
        <p className="mt-3 min-w-0 break-all text-sm text-slate-300 [overflow-wrap:anywhere]">
          {hasValue ? (
            <span className="font-mono text-slate-100">{value}</span>
          ) : (
            <span className="italic text-slate-400">
              Present with an empty value
            </span>
          )}
        </p>
      )}
    </div>
  )
}

function SecurityHeadersList({ headers, finalUrl }) {
  const hasFinalUrl = typeof finalUrl === 'string' && finalUrl.trim() !== ''

  return (
    <section
      className="rounded-xl border border-slate-800 bg-slate-900 p-5 sm:p-6"
      aria-labelledby="http-headers-heading"
    >
      <h2
        className="text-xl font-semibold text-slate-100"
        id="http-headers-heading"
      >
        HTTP security headers
      </h2>
      <p className="mt-2 min-w-0 break-words text-sm text-slate-400 [overflow-wrap:anywhere]">
        {hasFinalUrl
          ? `Header values observed in the final response at ${finalUrl}.`
          : 'Header values observed in the final HTTP response.'}
      </p>

      <div className="mt-5 grid min-w-0 items-start gap-3 sm:grid-cols-2">
        {HTTP_HEADER_FIELDS.map(({ key, label }) => (
          <HeaderRow header={headers[key]} key={key} label={label} />
        ))}
      </div>
    </section>
  )
}

function CollectionFailureNotice({ result, title }) {
  return (
    <section className="rounded-xl border border-amber-900 bg-amber-950/30 p-6">
      <p className="sr-only" role="status">
        {title}. Stage: {result.stage}. Code: {result.code}.
      </p>
      <h2 className="text-lg font-semibold text-amber-300">{title}</h2>
      <dl className="mt-5 grid gap-5 sm:grid-cols-2">
        <div className="min-w-0">
          <dt className="text-sm text-slate-400">Stage</dt>
          <dd className="mt-1 break-words font-mono text-sm [overflow-wrap:anywhere]">
            {result.stage}
          </dd>
        </div>
        <div className="min-w-0">
          <dt className="text-sm text-slate-400">Code</dt>
          <dd className="mt-1 break-words font-mono text-sm [overflow-wrap:anywhere]">
            {result.code}
          </dd>
        </div>
      </dl>
    </section>
  )
}

function GenericErrorNotice({ headingId, message, title }) {
  return (
    <div
      aria-labelledby={headingId}
      className="rounded-xl border border-rose-900 bg-rose-950/60 p-4 text-rose-200"
      role="alert"
    >
      <h2
        className="text-sm font-semibold uppercase tracking-wide"
        id={headingId}
      >
        {title}
      </h2>
      <p className="mt-1">{message}</p>
    </div>
  )
}

async function requestScanResult(endpoint, hostname, isSuccessResponse) {
  const controller = new AbortController()
  const timeoutId = setTimeout(
    () => controller.abort(),
    SCAN_REQUEST_TIMEOUT_MS,
  )

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ hostname }),
      signal: controller.signal,
    })

    let responseBody
    try {
      responseBody = await response.json()
    } catch (error) {
      if (error?.name === 'AbortError') {
        throw error
      }
      return {
        result: null,
        error: 'Sentinel returned an unexpected response. Please try again.',
      }
    }

    if (!response.ok) {
      if (isFailureResponse(responseBody)) {
        return { result: responseBody, error: '' }
      }
      return {
        result: null,
        error: 'The scan request failed unexpectedly. Please try again.',
      }
    }

    if (isSuccessResponse(responseBody) || isFailureResponse(responseBody)) {
      return { result: responseBody, error: '' }
    }

    return {
      result: null,
      error: 'Sentinel returned an unexpected response. Please try again.',
    }
  } catch (error) {
    if (error?.name === 'AbortError') {
      return {
        result: null,
        error: 'The scan timed out. Please try again.',
      }
    }
    return {
      result: null,
      error:
        'Unable to reach the Sentinel API. Check that the backend is running.',
    }
  } finally {
    clearTimeout(timeoutId)
  }
}

function App() {
  const [hostname, setHostname] = useState('')
  const [formError, setFormError] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [tlsResult, setTlsResult] = useState(null)
  const [tlsError, setTlsError] = useState('')
  const [httpResult, setHttpResult] = useState(null)
  const [httpError, setHttpError] = useState('')

  async function handleSubmit(event) {
    event.preventDefault()

    const trimmedHostname = hostname.trim()

    setTlsResult(null)
    setTlsError('')
    setHttpResult(null)
    setHttpError('')

    if (!trimmedHostname) {
      setFormError('Enter a hostname to scan.')
      return
    }

    setFormError('')
    setIsLoading(true)

    const [tlsOutcome, httpOutcome] = await Promise.all([
      requestScanResult(
        TLS_LEAF_CERTIFICATE_ENDPOINT,
        trimmedHostname,
        isTlsSuccessResponse,
      ),
      requestScanResult(
        HTTP_SECURITY_HEADERS_ENDPOINT,
        trimmedHostname,
        isHttpSuccessResponse,
      ),
    ])

    setTlsResult(tlsOutcome.result)
    setTlsError(tlsOutcome.error)
    setHttpResult(httpOutcome.result)
    setHttpError(httpOutcome.error)
    setIsLoading(false)
  }

  return (
    <main className="min-h-screen bg-slate-950 px-5 py-16 text-slate-100">
      <div className="mx-auto w-full max-w-3xl">
        <header className="mb-10">
          <p className="mb-3 text-sm font-semibold uppercase tracking-[0.2em] text-emerald-400">
            Sentinel
          </p>
          <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">
            Hostname security scan
          </h1>
          <p className="mt-4 max-w-2xl text-slate-400">
            Check the publicly observable TLS certificate and HTTP security
            headers presented for a hostname.
          </p>
        </header>

        <section className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-xl shadow-black/20 sm:p-8">
          <form onSubmit={handleSubmit}>
            <label
              className="block text-sm font-medium text-slate-200"
              htmlFor="hostname"
            >
              Hostname
            </label>
            <p className="mt-1 text-sm text-slate-400" id="hostname-help">
              Enter a hostname only, without a URL scheme or path.
            </p>

            <div className="mt-4 flex flex-col gap-3 sm:flex-row">
              <input
                aria-describedby="hostname-help"
                autoCapitalize="none"
                autoCorrect="off"
                className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-emerald-400 focus:ring-2 focus:ring-emerald-400/20"
                disabled={isLoading}
                id="hostname"
                name="hostname"
                onChange={(event) => setHostname(event.target.value)}
                placeholder="example.com"
                required
                spellCheck="false"
                type="text"
                value={hostname}
              />
              <button
                aria-busy={isLoading}
                className="rounded-lg bg-emerald-400 px-6 py-3 font-semibold text-slate-950 transition hover:bg-emerald-300 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
                disabled={isLoading}
                type="submit"
              >
                {isLoading ? 'Scanning…' : 'Scan'}
              </button>
            </div>
          </form>
        </section>

        <div className="mt-6 grid min-w-0 gap-5">
          {formError && (
            <p
              className="rounded-xl border border-rose-900 bg-rose-950/60 p-4 text-rose-200"
              role="alert"
            >
              {formError}
            </p>
          )}

          {tlsResult?.status === 'success' && (
            <>
              <ScanSummary result={tlsResult} />
              <CertificateDetails result={tlsResult} />
              <FindingsList
                description="Certificate observations evaluated by the Sentinel backend."
                emptyMessage="No certificate findings were returned."
                findings={tlsResult.findings}
                headingId="tls-certificate-findings-heading"
                title="TLS certificate findings"
              />
            </>
          )}

          {tlsResult?.status === 'failure' && (
            <CollectionFailureNotice
              result={tlsResult}
              title="TLS scan could not be completed"
            />
          )}

          {tlsError && (
            <GenericErrorNotice
              headingId="tls-scan-error-heading"
              message={tlsError}
              title="TLS scan error"
            />
          )}

          {httpResult?.status === 'success' && (
            <>
              <SecurityHeadersList
                finalUrl={httpResult.final_url}
                headers={httpResult.headers}
              />
              <FindingsList
                description="Header observations evaluated by the Sentinel backend."
                emptyMessage="No HTTP header findings were returned."
                findings={httpResult.findings}
                headingId="http-findings-heading"
                title="HTTP findings"
              />
            </>
          )}

          {httpResult?.status === 'failure' && (
            <CollectionFailureNotice
              result={httpResult}
              title="HTTP header scan could not be completed"
            />
          )}

          {httpError && (
            <GenericErrorNotice
              headingId="http-scan-error-heading"
              message={httpError}
              title="HTTP header scan error"
            />
          )}
        </div>
      </div>
    </main>
  )
}

export default App
