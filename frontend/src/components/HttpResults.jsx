import { useEffect, useState } from 'react'
import {
  CollectionFailureNotice,
  ErrorNotice,
} from './ErrorNotice.jsx'
import { FindingsList } from './FindingsList.jsx'
import { CheckIcon, MinusIcon } from './icons.jsx'

const HTTP_HEADER_FIELDS = [
  { key: 'strict_transport_security', label: 'Strict-Transport-Security' },
  { key: 'content_security_policy', label: 'Content-Security-Policy' },
  { key: 'x_content_type_options', label: 'X-Content-Type-Options' },
  { key: 'x_frame_options', label: 'X-Frame-Options' },
  { key: 'referrer_policy', label: 'Referrer-Policy' },
  { key: 'permissions_policy', label: 'Permissions-Policy' },
]

function prefersReducedMotion() {
  if (typeof window === 'undefined' || !window.matchMedia) return true
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

// Ease a whole number from 0 up to `target` once on mount. Returns `target`
// unchanged when reduced motion is requested or there is no matchMedia (tests).
function useCountUp(target, duration = 750) {
  const [reduced] = useState(prefersReducedMotion)
  const animate = Number.isFinite(target) && !reduced
  const [value, setValue] = useState(animate ? 0 : target)

  useEffect(() => {
    if (!animate) return
    let raf
    const start = performance.now()
    const step = (now) => {
      const t = Math.min(1, (now - start) / duration)
      setValue(Math.round(target * (1 - Math.pow(1 - t, 3))))
      if (t < 1) raf = requestAnimationFrame(step)
    }
    raf = requestAnimationFrame(step)
    return () => cancelAnimationFrame(raf)
  }, [animate, target, duration])

  return animate ? value : target
}

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

// The meter shows the backend score and nothing else: the fill edge sits at
// exactly score/100 and the ticks behind it are a plain 0-100 axis.
function ScoreMeter({ score }) {
  const fill = Number.isFinite(score) ? Math.min(100, Math.max(0, score)) : 0

  return (
    <div aria-hidden="true" className="mt-9">
      <div className="meter">
        <span className="meter__fill" style={{ '--fill': `${fill}%` }} />
      </div>
      <div className="mt-2 flex justify-between font-mono text-[0.6rem] tracking-[0.18em] text-ink-faint">
        <span>0</span>
        <span>25</span>
        <span>50</span>
        <span>75</span>
        <span>100</span>
      </div>
    </div>
  )
}

function HttpScoreSummary({ score }) {
  const shownScore = useCountUp(score.score)

  return (
    <section
      aria-labelledby="http-score-heading"
      className="panel reticle min-w-0 p-6 sm:p-8"
    >
      <p className="font-mono text-[0.62rem] uppercase tracking-[0.28em] text-ink-dim">
        Backend-reported result
      </p>
      <h3 className="group-heading mt-4" id="http-score-heading">
        HTTP Security Configuration Score
      </h3>

      <div className="mt-8 flex min-w-0 flex-wrap items-end gap-x-8 gap-y-5">
        <p
          aria-label={`Score ${score.score} out of 100`}
          className="score-reveal font-mono text-7xl font-semibold leading-[0.82] text-ink-strong sm:text-8xl"
        >
          {shownScore}
          <span className="ml-1.5 align-baseline text-2xl font-normal tracking-normal text-ink-dim">
            / 100
          </span>
        </p>
        {/* One text node on purpose: "Grade A+" stays a single readable
            string for assistive tech and for the suite's text queries. */}
        <span className="mb-2 inline-flex shrink-0 items-baseline border border-hairline-strong bg-panel-raised px-4 py-3 font-mono text-lg font-semibold uppercase tracking-[0.2em] text-ink-strong">
          Grade {score.grade}
        </span>
      </div>

      <ScoreMeter score={score.score} />

      <p className="tech-value mt-9 border-t border-hairline pt-6 text-sm leading-6 text-ink-dim">
        Covers Strict-Transport-Security, framing protection, Referrer-Policy,
        and X-Content-Type-Options only. It is not an overall security rating;
        TLS certificate health is assessed separately.
      </p>
    </section>
  )
}

function ScoreDeductions({ deductions }) {
  return (
    <section aria-labelledby="http-score-deductions-heading" className="min-w-0">
      <h3 className="group-heading" id="http-score-deductions-heading">
        Score deductions
      </h3>
      <p className="mt-3 text-sm leading-6 text-ink-dim">
        Points deducted from the HTTP Security Configuration Score, as reported
        by the Sentinel backend.
      </p>

      {deductions.length > 0 ? (
        <ul className="mt-5 grid min-w-0 gap-4">
          {deductions.map((deduction, index) => (
            <li
              className="flex min-w-0 gap-4 border-t border-hairline pt-4 first:border-t-0 first:pt-0"
              key={`${deduction.control}-${index}`}
            >
              <span className="h-fit shrink-0 border border-hairline bg-panel-raised px-2.5 py-1 font-mono text-sm font-semibold text-ink-strong">
                -{deduction.points}
                <span className="sr-only"> points</span>
              </span>
              <div className="min-w-0">
                <p className="tech-value text-sm font-medium text-ink">
                  {formatControlName(deduction.control)}
                </p>
                <p className="tech-value mt-1.5 text-sm leading-6 text-ink-dim">
                  {deduction.reason}
                </p>
              </div>
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-5 border-l border-dashed border-hairline py-1 pl-4 text-sm text-ink-dim">
          No scoring deductions were applied.
        </p>
      )}
    </section>
  )
}

function ScoreMethodology({ methodology }) {
  return (
    <section aria-labelledby="http-score-methodology-heading" className="min-w-0">
      <h3 className="group-heading" id="http-score-methodology-heading">
        Scoring methodology
      </h3>
      <p className="mt-3 text-sm leading-6 text-ink-dim">
        The full backend-provided scoring scope and limitations remain
        available below.
      </p>
      <details className="disclosure mt-5">
        <summary className="font-mono text-[0.7rem] font-medium uppercase tracking-[0.18em] text-ink outline-none">
          Read full methodology
        </summary>
        <p className="disclosure__body tech-value mt-4 border-l border-hairline pl-4 text-sm leading-7 text-ink-dim">
          {methodology}
        </p>
      </details>
    </section>
  )
}

function HeaderPresenceBadge({ present }) {
  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1.5 border px-2.5 py-1 font-mono text-[0.62rem] uppercase tracking-[0.18em] ${
        present
          ? 'border-ink font-semibold text-ink-strong'
          : 'border-dashed border-hairline font-medium text-ink-dim'
      }`}
    >
      {present ? (
        <CheckIcon className="size-3.5" />
      ) : (
        <MinusIcon className="size-3.5" />
      )}
      {present ? 'Present' : 'Missing'}
    </span>
  )
}

function HeaderItem({ header, label }) {
  const isPresent = header?.present === true
  const value = typeof header?.value === 'string' ? header.value : null
  const hasValue = value !== null && value.trim() !== ''

  let observedValue = 'No value observed'
  let observedValueClasses = 'italic text-ink-dim'

  if (isPresent && hasValue) {
    observedValue = value
    observedValueClasses = 'font-mono text-[0.8125rem] text-ink'
  } else if (isPresent) {
    observedValue = 'Present with an empty value'
    observedValueClasses = 'italic text-ink-dim'
  }

  return (
    <li className={`min-w-0 border p-5 ${isPresent ? 'border-hairline bg-panel' : 'border-dashed border-hairline'}`}>
      <div className="flex min-w-0 flex-wrap items-start justify-between gap-x-3 gap-y-2">
        <h4 className="tech-value font-mono text-sm font-semibold text-ink-strong">
          {label}
        </h4>
        <HeaderPresenceBadge present={isPresent} />
      </div>
      <p className="mt-5 font-mono text-[0.6rem] uppercase tracking-[0.22em] text-ink-dim">
        Observed value
      </p>
      <p
        className={`tech-value mt-1.5 whitespace-pre-wrap text-sm leading-6 ${observedValueClasses}`}
      >
        {observedValue}
      </p>
    </li>
  )
}

function SecurityHeaders({ finalUrl, headers }) {
  const hasFinalUrl = typeof finalUrl === 'string' && finalUrl.trim() !== ''

  return (
    <section aria-labelledby="http-headers-heading" className="min-w-0">
      <h3 className="group-heading" id="http-headers-heading">
        HTTP security headers
      </h3>
      <p className="tech-value mt-3 max-w-2xl text-sm leading-6 text-ink-dim">
        {hasFinalUrl
          ? `Header values observed in the final response at ${finalUrl}.`
          : 'Header values observed in the final HTTP response.'}
      </p>

      <ul className="mt-6 grid min-w-0 items-start gap-4 sm:grid-cols-2">
        {HTTP_HEADER_FIELDS.map(({ key, label }) => (
          <HeaderItem header={headers[key]} key={key} label={label} />
        ))}
      </ul>
    </section>
  )
}

function ResponseDetail({ children, className = '', label, monospace = false }) {
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

// Telemetry ladder: the three stages the collector actually reports - what was
// asked for, where the request ended up, and what came back. No invented
// network stages, no progress model.
function TelemetryStage({ children, index, label }) {
  return (
    <div className="grid min-w-0 gap-5 border-t border-hairline pt-6 first:border-t-0 first:pt-0 lg:grid-cols-[minmax(0,12rem)_minmax(0,1fr)] lg:gap-12">
      <p className="flex items-center gap-3 font-mono text-[0.62rem] uppercase tracking-[0.26em] text-ink-dim">
        <span
          aria-hidden="true"
          className="inline-flex size-5 items-center justify-center border border-hairline text-[0.6rem] text-ink-faint"
        >
          {index}
        </span>
        {label}
      </p>
      <dl className="grid min-w-0 gap-x-8 gap-y-5 sm:grid-cols-2">
        {children}
      </dl>
    </div>
  )
}

function HttpResponseDetails({ result }) {
  return (
    <section aria-labelledby="http-response-details-heading" className="min-w-0">
      <h3 className="group-heading" id="http-response-details-heading">
        HTTP response details
      </h3>
      <p className="mt-3 max-w-xl text-sm leading-6 text-ink-dim">
        Connection and redirect metadata returned by the HTTP collector.
      </p>

      <div className="mt-6 grid min-w-0 gap-6">
        <TelemetryStage index="A" label="Request">
          <ResponseDetail className="sm:col-span-2" label="Requested hostname">
            {displayText(result.requested_hostname)}
          </ResponseDetail>
        </TelemetryStage>

        <TelemetryStage index="B" label="Destination">
          <ResponseDetail label="Final hostname">
            {displayText(result.final_hostname)}
          </ResponseDetail>
          <ResponseDetail label="Connected IP" monospace>
            {displayText(result.connected_ip)}
          </ResponseDetail>
          <ResponseDetail className="sm:col-span-2" label="Final URL" monospace>
            {displayText(result.final_url)}
          </ResponseDetail>
        </TelemetryStage>

        <TelemetryStage index="C" label="Response">
          <ResponseDetail label="HTTP status code">
            {result.http_status_code}
          </ResponseDetail>
          <ResponseDetail label="Redirect count">
            {result.redirect_count}
          </ResponseDetail>
        </TelemetryStage>
      </div>
    </section>
  )
}

export function HttpResults({ outcome }) {
  const { error, result } = outcome

  return (
    <section aria-labelledby="http-analysis-heading" className="min-w-0">
      {/* Level 1 band */}
      <div className="flex items-center gap-4">
        <span className="font-mono text-[0.62rem] uppercase tracking-[0.3em] text-ink-dim">
          02
        </span>
        <span aria-hidden="true" className="tick-rule h-px flex-1" />
        <span className="font-mono text-[0.62rem] uppercase tracking-[0.3em] text-ink-dim">
          Scanner
        </span>
      </div>

      <h2
        className="font-display mt-8 text-3xl leading-[1.08] text-ink-strong sm:text-4xl lg:text-[2.75rem]"
        id="http-analysis-heading"
      >
        HTTP Security Configuration
      </h2>
      <p className="mt-4 max-w-2xl text-sm leading-6 text-ink-dim sm:text-base sm:leading-7">
        Backend-reported score, observed security headers, HTTP findings, and
        response metadata.
      </p>

      <div className="mt-10 grid min-w-0 gap-12">
        {result?.status === 'success' && (
          <>
            <HttpScoreSummary score={result.score} />
            <div className="grid min-w-0 gap-10 lg:grid-cols-2 lg:items-start lg:gap-12">
              <ScoreDeductions deductions={result.score.deductions} />
              <ScoreMethodology methodology={result.score.methodology} />
            </div>
            <div className="min-w-0 border-t border-hairline pt-10">
              <SecurityHeaders
                finalUrl={result.final_url}
                headers={result.headers}
              />
            </div>
            <div className="min-w-0 border-t border-hairline pt-10">
              <FindingsList
                description="Header observations evaluated by the Sentinel backend."
                emptyMessage="No issues were detected by the configured HTTP header checks."
                findings={result.findings}
                headingId="http-findings-heading"
                title="HTTP findings"
              />
            </div>
            <div className="min-w-0 border-t border-hairline pt-10">
              <HttpResponseDetails result={result} />
            </div>
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
