import { useState } from 'react'

const API_BASE_URL = '/api/v1'
const TLS_LEAF_CERTIFICATE_ENDPOINT = `${API_BASE_URL}/tls/leaf-certificate`

const REQUIRED_SUCCESS_STRING_FIELDS = [
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

function isFinding(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    typeof value.code === 'string' &&
    typeof value.severity === 'string' &&
    typeof value.message === 'string'
  )
}

function isSuccessResponse(value) {
  return (
    value?.status === 'success' &&
    REQUIRED_SUCCESS_STRING_FIELDS.every(
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

  return 'info'
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

function FindingsList({ findings }) {
  return (
    <section
      className="rounded-xl border border-slate-800 bg-slate-900 p-5 sm:p-6"
      aria-labelledby="security-findings-heading"
    >
      <h2
        className="text-xl font-semibold text-slate-100"
        id="security-findings-heading"
      >
        Security findings
      </h2>
      <p className="mt-2 text-sm text-slate-400">
        Certificate observations evaluated by the Sentinel backend.
      </p>

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
          No certificate findings were returned.
        </p>
      )}
    </section>
  )
}

function App() {
  const [hostname, setHostname] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)

  async function handleSubmit(event) {
    event.preventDefault()

    const trimmedHostname = hostname.trim()
    if (!trimmedHostname) {
      setResult(null)
      setError('Enter a hostname to scan.')
      return
    }

    setIsLoading(true)
    setResult(null)
    setError('')

    try {
      const response = await fetch(TLS_LEAF_CERTIFICATE_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ hostname: trimmedHostname }),
      })

      let responseBody
      try {
        responseBody = await response.json()
      } catch {
        setError('Sentinel returned an unexpected response. Please try again.')
        return
      }

      if (!response.ok) {
        if (isFailureResponse(responseBody)) {
          setResult(responseBody)
        } else {
          setError('The scan request failed unexpectedly. Please try again.')
        }
        return
      }

      if (isSuccessResponse(responseBody) || isFailureResponse(responseBody)) {
        setResult(responseBody)
      } else {
        setError('Sentinel returned an unexpected response. Please try again.')
      }
    } catch {
      setError(
        'Unable to reach the Sentinel API. Check that the backend is running.',
      )
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <main className="min-h-screen bg-slate-950 px-5 py-16 text-slate-100">
      <div className="mx-auto w-full max-w-3xl">
        <header className="mb-10">
          <p className="mb-3 text-sm font-semibold uppercase tracking-[0.2em] text-emerald-400">
            Sentinel
          </p>
          <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">
            TLS leaf certificate scan
          </h1>
          <p className="mt-4 max-w-2xl text-slate-400">
            Check the publicly observable TLS certificate presented for a
            hostname.
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

        <div className="mt-6">
          {error && (
            <p
              className="rounded-xl border border-rose-900 bg-rose-950/60 p-4 text-rose-200"
              role="alert"
            >
              {error}
            </p>
          )}

          {result?.status === 'success' && (
            <div className="grid min-w-0 gap-5">
              <ScanSummary result={result} />
              <CertificateDetails result={result} />
              <FindingsList findings={result.findings} />
            </div>
          )}

          {result?.status === 'failure' && (
            <section className="rounded-xl border border-amber-900 bg-amber-950/30 p-6">
              <p className="sr-only" role="status">
                Scan could not be completed. Stage: {result.stage}. Code:{' '}
                {result.code}.
              </p>
              <h2 className="text-lg font-semibold text-amber-300">
                Scan could not be completed
              </h2>
              <dl className="mt-5 grid gap-5 sm:grid-cols-2">
                <div>
                  <dt className="text-sm text-slate-400">Stage</dt>
                  <dd className="mt-1 font-mono text-sm">{result.stage}</dd>
                </div>
                <div>
                  <dt className="text-sm text-slate-400">Code</dt>
                  <dd className="mt-1 font-mono text-sm">{result.code}</dd>
                </div>
              </dl>
            </section>
          )}
        </div>
      </div>
    </main>
  )
}

export default App
