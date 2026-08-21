import {
  CollectionFailureNotice,
  ErrorNotice,
} from './ErrorNotice.jsx'
import { FindingsList } from './FindingsList.jsx'

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

function MetadataItem({ children, className = '', label, monospace = false }) {
  return (
    <div
      className={`min-w-0 rounded-lg border border-slate-800 bg-slate-950/55 p-4 ${className}`}
    >
      <dt className="text-xs font-semibold uppercase tracking-wide text-slate-400">
        {label}
      </dt>
      <dd
        className={`mt-2 min-w-0 break-words text-sm leading-6 text-slate-100 [overflow-wrap:anywhere] ${
          monospace ? 'font-mono' : ''
        }`}
      >
        {children}
      </dd>
    </div>
  )
}

function DetailGroup({ children, className = '', description, headingId, title }) {
  return (
    <section
      aria-labelledby={headingId}
      className={`min-w-0 rounded-xl border border-slate-800 bg-slate-900 p-5 sm:p-6 ${className}`}
    >
      <h3 className="text-lg font-semibold text-slate-100" id={headingId}>
        {title}
      </h3>
      <p className="mt-1 text-sm leading-6 text-slate-400">{description}</p>
      <dl className="mt-5 grid min-w-0 gap-3 sm:grid-cols-2">{children}</dl>
    </section>
  )
}

function CertificateDetails({ result }) {
  const dnsNames = result.dns_names.filter((dnsName) => dnsName.trim())

  return (
    <div className="grid min-w-0 gap-5 lg:grid-cols-2">
      <DetailGroup
        description="The approved target and address used for the verified connection."
        headingId="tls-connection-heading"
        title="Connection"
      >
        <MetadataItem label="Hostname">
          {displayText(result.hostname)}
        </MetadataItem>
        <MetadataItem label="Connected IP" monospace>
          {displayText(result.connected_ip)}
        </MetadataItem>
      </DetailGroup>

      <DetailGroup
        description="The certificate validity period reported by the backend."
        headingId="tls-validity-heading"
        title="Validity"
      >
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
        <MetadataItem className="sm:col-span-2" label="Days remaining">
          {formatDaysRemaining(result.days_remaining)}
        </MetadataItem>
      </DetailGroup>

      <DetailGroup
        className="lg:col-span-2"
        description="Certificate identity fields and DNS Subject Alternative Names."
        headingId="tls-identity-heading"
        title="Identity"
      >
        <MetadataItem label="Subject">
          {displayText(result.subject)}
        </MetadataItem>
        <MetadataItem label="Issuer">
          {displayText(result.issuer)}
        </MetadataItem>
        <MetadataItem className="sm:col-span-2" label="DNS SANs">
          {dnsNames.length > 0 ? (
            <ul className="flex min-w-0 flex-wrap gap-2">
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
      </DetailGroup>

      <DetailGroup
        className="lg:col-span-2"
        description="Algorithms and identifiers observed on the leaf certificate."
        headingId="tls-cryptography-heading"
        title="Cryptography"
      >
        <MetadataItem label="Public key">
          {formatPublicKey(result.public_key_type, result.public_key_size)}
        </MetadataItem>
        <MetadataItem label="Signature algorithm">
          {displayText(result.signature_algorithm)}
        </MetadataItem>
        <MetadataItem label="Serial number" monospace>
          {displayText(result.serial_number)}
        </MetadataItem>
        <MetadataItem label="SHA-256 fingerprint" monospace>
          {displayText(result.certificate_sha256)}
        </MetadataItem>
      </DetailGroup>
    </div>
  )
}

export function TlsResults({ outcome }) {
  const { error, result } = outcome

  return (
    <section aria-labelledby="tls-analysis-heading" className="min-w-0">
      <div className="mb-5 border-l-2 border-emerald-500 pl-4">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-emerald-400">
          Scanner 01
        </p>
        <h2
          className="mt-2 text-2xl font-semibold tracking-tight text-slate-100 sm:text-3xl"
          id="tls-analysis-heading"
        >
          TLS Certificate Analysis
        </h2>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
          Verified connection details, leaf-certificate metadata, and
          certificate findings remain separate from the HTTP score.
        </p>
      </div>

      <div className="grid min-w-0 gap-5">
        {result?.status === 'success' && (
          <>
            <CertificateDetails result={result} />
            <FindingsList
              description="Certificate observations evaluated by the Sentinel backend."
              emptyMessage="No issues were detected by the configured certificate checks."
              findings={result.findings}
              headingId="tls-certificate-findings-heading"
              title="TLS certificate findings"
            />
          </>
        )}

        {result?.status === 'failure' && (
          <CollectionFailureNotice
            headingId="tls-collection-failure-heading"
            result={result}
            title="TLS scan could not be completed"
          />
        )}

        {error && (
          <ErrorNotice
            headingId="tls-scan-error-heading"
            message={error}
            title="TLS scan error"
          />
        )}
      </div>
    </section>
  )
}
