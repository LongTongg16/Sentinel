function severityPresentation(severity) {
  if (severity === 'critical') {
    return {
      label: 'Critical',
      symbol: '!',
      container: 'border-rose-800 bg-rose-950/45 text-rose-100',
      badge: 'border-rose-700 bg-rose-900/70 text-rose-100',
    }
  }

  if (severity === 'warning') {
    return {
      label: 'Warning',
      symbol: '▲',
      container: 'border-amber-800 bg-amber-950/35 text-amber-100',
      badge: 'border-amber-700 bg-amber-900/70 text-amber-100',
    }
  }

  if (severity === 'info') {
    return {
      label: 'Info',
      symbol: 'i',
      container: 'border-emerald-900 bg-emerald-950/30 text-emerald-100',
      badge: 'border-emerald-800 bg-emerald-900/60 text-emerald-100',
    }
  }

  return {
    label: 'Unknown',
    symbol: '?',
    container: 'border-slate-700 bg-slate-950/60 text-slate-100',
    badge: 'border-slate-600 bg-slate-800 text-slate-200',
  }
}

function displayText(value, fallback = 'Not available') {
  return typeof value === 'string' && value.trim() ? value : fallback
}

function FindingCard({ finding }) {
  const presentation = severityPresentation(finding.severity)

  return (
    <li
      className={`min-w-0 rounded-lg border p-4 sm:p-5 ${presentation.container}`}
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

export function FindingsList({
  description,
  emptyMessage,
  findings,
  headingId,
  title,
}) {
  return (
    <section
      aria-labelledby={headingId}
      className="rounded-xl border border-slate-800 bg-slate-900 p-5 sm:p-6"
    >
      <h3 className="text-xl font-semibold text-slate-100" id={headingId}>
        {title}
      </h3>
      <p className="mt-2 text-sm leading-6 text-slate-400">{description}</p>

      {findings.length > 0 ? (
        <ul className="mt-5 grid gap-3">
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
