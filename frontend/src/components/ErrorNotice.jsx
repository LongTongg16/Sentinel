import { CriticalIcon, WarningIcon } from './icons.jsx'

// Both notices use the same monochrome severity language as FindingsList: a
// left rail whose width and brightness carry the weight, plus an icon and an
// always-visible heading. Never colour, never opacity alone.

export function CollectionFailureNotice({ headingId, result, title }) {
  return (
    <div
      aria-labelledby={headingId}
      className="flex min-w-0 border border-hairline bg-panel"
    >
      <span aria-hidden="true" className="w-1 shrink-0 bg-ink" />
      <div className="min-w-0 flex-1 p-5 sm:p-6">
        <h3
          className="flex items-center gap-2.5 font-mono text-[0.72rem] font-semibold uppercase tracking-[0.2em] text-ink-strong"
          id={headingId}
        >
          <WarningIcon className="size-4 shrink-0" />
          {title}
        </h3>
        <p className="mt-3 max-w-xl text-sm leading-6 text-ink-dim">
          The collector returned a typed failure. The other scan result remains
          available independently.
        </p>
        <dl className="mt-5 flex min-w-0 flex-wrap gap-x-8 gap-y-4">
          <div className="min-w-0">
            <dt className="font-mono text-[0.62rem] uppercase tracking-[0.22em] text-ink-dim">
              Stage
            </dt>
            <dd className="tech-value mt-2 border border-hairline bg-panel-raised px-3 py-2 font-mono text-[0.8125rem] text-ink">
              {result.stage}
            </dd>
          </div>
          <div className="min-w-0">
            <dt className="font-mono text-[0.62rem] uppercase tracking-[0.22em] text-ink-dim">
              Code
            </dt>
            <dd className="tech-value mt-2 border border-hairline bg-panel-raised px-3 py-2 font-mono text-[0.8125rem] text-ink">
              {result.code}
            </dd>
          </div>
        </dl>
      </div>
    </div>
  )
}

export function ErrorNotice({ headingId, message, title }) {
  return (
    <div
      aria-labelledby={headingId}
      className="flex min-w-0 border border-hairline-strong bg-panel"
    >
      <span aria-hidden="true" className="w-1.5 shrink-0 bg-ink-strong" />
      <div className="min-w-0 flex-1 p-5 sm:p-6">
        <h3
          className="flex items-center gap-2.5 font-mono text-[0.72rem] font-semibold uppercase tracking-[0.2em] text-ink-strong"
          id={headingId}
        >
          <CriticalIcon className="size-4 shrink-0" />
          {title}
        </h3>
        <p className="tech-value mt-3 max-w-xl text-sm leading-6 text-ink-dim">
          {message}
        </p>
      </div>
    </div>
  )
}
