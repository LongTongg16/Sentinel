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

// Level 3: a single piece of evidence. Monospace fields are boxed on a raised
// surface so collected values read differently from prose.
function MetadataItem({ children, className = '', label, monospace = false }) {
  return (
    <div className={`min-w-0 ${className}`}>
      <dt className="font-mono text-[0.62rem] uppercase tracking-[0.22em] text-ink-dim">
        {label}
      </dt>
      <dd
        className={`tech-value mt-2 text-sm leading-6 text-ink ${
          monospace
            ? 'w-fit border border-hairline bg-panel-raised px-3 py-2 font-mono text-[0.8125rem]'
            : ''
        }`}
      >
        {children}
      </dd>
    </div>
  )
}

// Level 2: an editorial sidenote column carries the group identity, the
// evidence grid sits beside it. Wide screens get the split; narrow screens
// stack, which is also what keeps long values from forcing a wide track.
function DetailGroup({ children, className = '', description, headingId, title }) {
  return (
    <section
      aria-labelledby={headingId}
      className={`min-w-0 border-t border-hairline pt-8 first:border-t-0 first:pt-0 ${className}`}
    >
      <div className="grid min-w-0 gap-6 lg:grid-cols-[minmax(0,12rem)_minmax(0,1fr)] lg:gap-12">
        <div className="min-w-0">
          <h3 className="group-heading" id={headingId}>
            {title}
          </h3>
          <p className="mt-3 text-sm leading-6 text-ink-dim">{description}</p>
        </div>
        <dl className="grid min-w-0 gap-x-8 gap-y-6 sm:grid-cols-2">
          {children}
        </dl>
      </div>
    </section>
  )
}

function CertificateDetails({ result }) {
  const dnsNames = result.dns_names.filter((dnsName) => dnsName.trim())

  return (
    <div className="grid min-w-0 gap-8">
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
          <span className="font-mono text-xl font-semibold text-ink-strong">
            {formatDaysRemaining(result.days_remaining)}
          </span>
        </MetadataItem>
      </DetailGroup>

      <DetailGroup
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
                  className="tech-value max-w-full border border-hairline bg-panel-raised px-2.5 py-1 font-mono text-xs text-ink"
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
        <MetadataItem
          className="sm:col-span-2"
          label="SHA-256 fingerprint"
          monospace
        >
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
      {/* Level 1 band */}
      <div className="flex items-center gap-4">
        <span className="font-mono text-[0.62rem] uppercase tracking-[0.3em] text-ink-dim">
          01
        </span>
        <span aria-hidden="true" className="tick-rule h-px flex-1" />
        <span className="font-mono text-[0.62rem] uppercase tracking-[0.3em] text-ink-dim">
          Scanner
        </span>
      </div>

      <h2
        className="font-display mt-8 text-3xl leading-[1.08] text-ink-strong sm:text-4xl lg:text-[2.75rem]"
        id="tls-analysis-heading"
      >
        TLS Certificate Analysis
      </h2>
      <p className="mt-4 max-w-2xl text-sm leading-6 text-ink-dim sm:text-base sm:leading-7">
        Verified connection details, leaf-certificate metadata, and certificate
        findings remain separate from the HTTP score.
      </p>

      <div className="mt-10 grid min-w-0 gap-10">
        {result?.status === 'success' && (
          <>
            <CertificateDetails result={result} />
            <div className="min-w-0 border-t border-hairline pt-10">
              <FindingsList
                description="Certificate observations evaluated by the Sentinel backend."
                emptyMessage="No issues were detected by the configured certificate checks."
                findings={result.findings}
                headingId="tls-certificate-findings-heading"
                title="TLS certificate findings"
              />
            </div>
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
