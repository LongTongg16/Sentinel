export function CollectionFailureNotice({ headingId, result, title }) {
  return (
    <div
      aria-labelledby={headingId}
      className="rounded-xl border border-amber-900 bg-amber-950/30 p-5 text-amber-100"
    >
      <h3 className="text-lg font-semibold text-amber-200" id={headingId}>
        {title}
      </h3>
      <p className="mt-2 text-sm leading-6 text-amber-100/75">
        The collector returned a typed failure. The other scan result remains
        available independently.
      </p>
      <dl className="mt-5 grid gap-4 sm:grid-cols-2">
        <div className="min-w-0 rounded-lg border border-amber-900/70 bg-black/15 p-4">
          <dt className="text-xs font-semibold uppercase tracking-wide text-amber-200/70">
            Stage
          </dt>
          <dd className="mt-2 break-words font-mono text-sm [overflow-wrap:anywhere]">
            {result.stage}
          </dd>
        </div>
        <div className="min-w-0 rounded-lg border border-amber-900/70 bg-black/15 p-4">
          <dt className="text-xs font-semibold uppercase tracking-wide text-amber-200/70">
            Code
          </dt>
          <dd className="mt-2 break-words font-mono text-sm [overflow-wrap:anywhere]">
            {result.code}
          </dd>
        </div>
      </dl>
    </div>
  )
}

export function ErrorNotice({ headingId, message, title }) {
  return (
    <div
      aria-labelledby={headingId}
      className="rounded-xl border border-rose-900 bg-rose-950/40 p-5 text-rose-100"
    >
      <h3 className="text-lg font-semibold text-rose-200" id={headingId}>
        {title}
      </h3>
      <p className="mt-2 break-words text-sm leading-6 text-rose-100/80 [overflow-wrap:anywhere]">
        {message}
      </p>
    </div>
  )
}
