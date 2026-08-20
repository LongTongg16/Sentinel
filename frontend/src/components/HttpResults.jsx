import {
  CollectionFailureNotice,
  ErrorNotice,
} from './ErrorNotice.jsx'
import { FindingsList } from './FindingsList.jsx'

const HTTP_HEADER_FIELDS = [
  { key: 'strict_transport_security', label: 'Strict-Transport-Security' },
  { key: 'content_security_policy', label: 'Content-Security-Policy' },
  { key: 'x_content_type_options', label: 'X-Content-Type-Options' },
  { key: 'x_frame_options', label: 'X-Frame-Options' },
  { key: 'referrer_policy', label: 'Referrer-Policy' },
  { key: 'permissions_policy', label: 'Permissions-Policy' },
]

const HTTP_SCORE_GOOD_GRADES = ['A+', 'A', 'A-', 'B+', 'B', 'B-']
const HTTP_SCORE_CAUTION_GRADES = ['C+', 'C', 'C-', 'D+', 'D', 'D-']

function displayText(value, fallback = 'Not available') {
  return typeof value === 'string' && value.trim() ? value : fallback
}

function formatControlName(control) {
  if (typeof control !== 'string' || !control.trim()) {
    return 'Not available'
  }

  const words = control
    .split('-')
    .map((word) => word.trim().toLowerCase())
    .filter(Boolean)

  if (words.length === 0) {
    return 'Not available'
  }

  const [first, ...rest] = words
  return [`${first.charAt(0).toUpperCase()}${first.slice(1)}`, ...rest].join(
    ' ',
  )
}

function gradePresentation(grade) {
  if (HTTP_SCORE_GOOD_GRADES.includes(grade)) {
    return {
      container: 'border-emerald-800 bg-emerald-950/35 text-emerald-100',
      badge: 'border-emerald-700 bg-emerald-900/60 text-emerald-100',
    }
  }

  if (HTTP_SCORE_CAUTION_GRADES.includes(grade)) {
    return {
      container: 'border-amber-700 bg-amber-950/40 text-amber-100',
      badge: 'border-amber-600 bg-amber-900/70 text-amber-100',
    }
  }

  if (grade === 'F') {
    return {
      container: 'border-rose-800 bg-rose-950/50 text-rose-100',
      badge: 'border-rose-700 bg-rose-900/70 text-rose-100',
    }
  }

  return {
    container: 'border-slate-700 bg-slate-900 text-slate-100',
    badge: 'border-slate-600 bg-slate-800 text-slate-200',
  }
}

function HttpScoreSummary({ score }) {
  const presentation = gradePresentation(score.grade)

  return (
    <section
      aria-labelledby="http-score-heading"
      className={`rounded-xl border p-5 sm:p-7 ${presentation.container}`}
    >
      <div className="flex flex-col gap-5 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] opacity-70">
            Backend-reported result
          </p>
          <h3 className="mt-2 text-xl font-semibold" id="http-score-heading">
            HTTP Security Configuration Score
          </h3>
          <p
            aria-label={`Score ${score.score} out of 100`}
            className="mt-3 text-4xl font-bold tracking-tight"
          >
            {score.score}{' '}
            <span className="text-lg font-medium opacity-70">/ 100</span>
          </p>
        </div>
        <span
          className={`inline-flex w-fit items-center rounded-full border px-4 py-2 text-sm font-semibold ${presentation.badge}`}
        >
          Grade {score.grade}
        </span>
      </div>
      <p className="mt-5 border-t border-current/20 pt-5 text-sm leading-6 opacity-80">
        Covers Strict-Transport-Security, framing protection,
        Referrer-Policy, and X-Content-Type-Options only. It is not an overall
        security rating; TLS certificate health is assessed separately.
      </p>
    </section>
  )
}

function ScoreDeductions({ deductions }) {
  return (
    <section
      aria-labelledby="http-score-deductions-heading"
      className="rounded-xl border border-slate-800 bg-slate-900 p-5 sm:p-6"
    >
      <h3
        className="text-xl font-semibold text-slate-100"
        id="http-score-deductions-heading"
      >
        Score deductions
      </h3>
      <p className="mt-2 text-sm leading-6 text-slate-400">
        Points deducted from the HTTP Security Configuration Score, as
        reported by the Sentinel backend.
      </p>

      {deductions.length > 0 ? (
        <ul className="mt-5 grid gap-3">
          {deductions.map((deduction, index) => (
            <li
              className="min-w-0 rounded-lg border border-slate-800 bg-slate-950/55 p-4"
              key={`${deduction.control}-${index}`}
            >
              <div className="flex flex-wrap items-baseline gap-2">
                <span className="text-lg font-bold text-rose-300">
                  -{deduction.points}
                  <span className="sr-only"> points</span>
                </span>
                <span className="min-w-0 break-words text-sm font-semibold text-slate-100 [overflow-wrap:anywhere]">
                  {formatControlName(deduction.control)}
                </span>
              </div>
              <p className="mt-2 break-words text-sm leading-6 text-slate-300 [overflow-wrap:anywhere]">
                {deduction.reason}
              </p>
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-5 rounded-lg border border-slate-700 bg-slate-950/50 p-4 text-sm text-slate-300">
          No scoring deductions were applied.
        </p>
      )}
    </section>
  )
}

function ScoreMethodology({ methodology }) {
  return (
    <section
      aria-labelledby="http-score-methodology-heading"
      className="rounded-xl border border-slate-800 bg-slate-900 p-5 sm:p-6"
    >
      <h3
        className="text-xl font-semibold text-slate-100"
        id="http-score-methodology-heading"
      >
        Scoring methodology
      </h3>
      <p className="mt-2 text-sm leading-6 text-slate-400">
        The full backend-provided scoring scope and limitations remain
        available below.
      </p>
      <details className="mt-5 rounded-lg border border-slate-700 bg-slate-950/55 open:border-slate-600">
        <summary className="cursor-pointer rounded-lg px-4 py-3 text-sm font-semibold text-slate-200 outline-none focus-visible:ring-2 focus-visible:ring-emerald-400 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-900">
          Read full methodology
        </summary>
        <p className="border-t border-slate-800 px-4 py-4 text-sm leading-7 text-slate-300 [overflow-wrap:anywhere]">
          {methodology}
        </p>
      </details>
    </section>
  )
}

function HeaderPresenceBadge({ present }) {
  return (
    <span
      className={`inline-flex w-fit shrink-0 items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold uppercase tracking-wide ${
        present
          ? 'border-emerald-700 bg-emerald-900/60 text-emerald-100'
          : 'border-slate-600 bg-slate-800 text-slate-300'
      }`}
    >
      <span aria-hidden="true">{present ? '✓' : '—'}</span>
      {present ? 'Present' : 'Missing'}
    </span>
  )
}

function HeaderItem({ header, label }) {
  const isPresent = header?.present === true
  const value = typeof header?.value === 'string' ? header.value : null
  const hasValue = value !== null && value.trim() !== ''

  let observedValue = 'No value observed'
  let observedValueClasses = 'italic text-slate-400'

  if (isPresent && hasValue) {
    observedValue = value
    observedValueClasses = 'font-mono text-slate-100'
  } else if (isPresent) {
    observedValue = 'Present with an empty value'
    observedValueClasses = 'italic text-amber-200/80'
  }

  return (
    <li className="min-w-0 rounded-lg border border-slate-800 bg-slate-950/55 p-4 sm:p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <h4 className="min-w-0 break-words font-mono text-sm font-semibold text-slate-100 [overflow-wrap:anywhere]">
          {label}
        </h4>
        <HeaderPresenceBadge present={isPresent} />
      </div>
      <div className="mt-4 border-t border-slate-800 pt-4">
        <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">
          Observed value
        </p>
        <p
          className={`mt-2 min-w-0 whitespace-pre-wrap break-words text-sm leading-6 [overflow-wrap:anywhere] ${observedValueClasses}`}
        >
          {observedValue}
        </p>
      </div>
    </li>
  )
}

function SecurityHeaders({ finalUrl, headers }) {
  const hasFinalUrl = typeof finalUrl === 'string' && finalUrl.trim() !== ''

  return (
    <section
      aria-labelledby="http-headers-heading"
      className="rounded-xl border border-slate-800 bg-slate-900 p-5 sm:p-6"
    >
      <h3 className="text-xl font-semibold text-slate-100" id="http-headers-heading">
        HTTP security headers
      </h3>
      <p className="mt-2 min-w-0 break-words text-sm leading-6 text-slate-400 [overflow-wrap:anywhere]">
        {hasFinalUrl
          ? `Header values observed in the final response at ${finalUrl}.`
          : 'Header values observed in the final HTTP response.'}
      </p>

      <ul className="mt-5 grid min-w-0 items-start gap-3 lg:grid-cols-2">
        {HTTP_HEADER_FIELDS.map(({ key, label }) => (
          <HeaderItem header={headers[key]} key={key} label={label} />
        ))}
      </ul>
    </section>
  )
}

function ResponseDetail({
  children,
  className = '',
  label,
  monospace = false,
}) {
  return (
    <div
      className={`min-w-0 rounded-lg border border-slate-800 bg-slate-950/55 p-4 ${className}`}
    >
      <dt className="text-xs font-semibold uppercase tracking-wide text-slate-400">
        {label}
      </dt>
      <dd
        className={`mt-2 break-words text-sm leading-6 text-slate-100 [overflow-wrap:anywhere] ${
          monospace ? 'font-mono' : ''
        }`}
      >
        {children}
      </dd>
    </div>
  )
}

function HttpResponseDetails({ result }) {
  return (
    <section
      aria-labelledby="http-response-details-heading"
      className="rounded-xl border border-slate-800 bg-slate-900 p-5 sm:p-6"
    >
      <h3
        className="text-xl font-semibold text-slate-100"
        id="http-response-details-heading"
      >
        HTTP response details
      </h3>
      <p className="mt-2 text-sm leading-6 text-slate-400">
        Connection and redirect metadata returned by the HTTP collector.
      </p>
      <dl className="mt-5 grid min-w-0 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <ResponseDetail label="Requested hostname">
          {displayText(result.requested_hostname)}
        </ResponseDetail>
        <ResponseDetail label="Final hostname">
          {displayText(result.final_hostname)}
        </ResponseDetail>
        <ResponseDetail label="Connected IP" monospace>
          {displayText(result.connected_ip)}
        </ResponseDetail>
        <ResponseDetail label="HTTP status code">
          {result.http_status_code}
        </ResponseDetail>
        <ResponseDetail label="Redirect count">
          {result.redirect_count}
        </ResponseDetail>
        <ResponseDetail
          className="sm:col-span-2 lg:col-span-3"
          label="Final URL"
          monospace
        >
          {displayText(result.final_url)}
        </ResponseDetail>
      </dl>
    </section>
  )
}

export function HttpResults({ outcome }) {
  const { error, result } = outcome

  return (
    <section aria-labelledby="http-analysis-heading" className="min-w-0">
      <div className="mb-5 border-l-2 border-sky-500 pl-4">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-sky-400">
          Scanner 02
        </p>
        <h2
          className="mt-2 text-2xl font-semibold tracking-tight text-slate-100 sm:text-3xl"
          id="http-analysis-heading"
        >
          HTTP Security Configuration
        </h2>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
          Backend-reported score, observed security headers, HTTP findings,
          and response metadata.
        </p>
      </div>

      <div className="grid min-w-0 gap-5">
        {result?.status === 'success' && (
          <>
            <HttpScoreSummary score={result.score} />
            <div className="grid min-w-0 gap-5 lg:grid-cols-2 lg:items-start">
              <ScoreDeductions deductions={result.score.deductions} />
              <ScoreMethodology methodology={result.score.methodology} />
            </div>
            <SecurityHeaders
              finalUrl={result.final_url}
              headers={result.headers}
            />
            <FindingsList
              description="Header observations evaluated by the Sentinel backend."
              emptyMessage="No issues were detected by the configured HTTP header checks."
              findings={result.findings}
              headingId="http-findings-heading"
              title="HTTP findings"
            />
            <HttpResponseDetails result={result} />
          </>
        )}

        {result?.status === 'failure' && (
          <CollectionFailureNotice
            headingId="http-collection-failure-heading"
            result={result}
            title="HTTP header scan could not be completed"
          />
        )}

        {error && (
          <ErrorNotice
            headingId="http-scan-error-heading"
            message={error}
            title="HTTP header scan error"
          />
        )}
      </div>
    </section>
  )
}
