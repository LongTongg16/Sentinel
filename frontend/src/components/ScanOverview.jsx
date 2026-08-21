function outcomePresentation(outcome, isLoading) {
  if (isLoading) {
    return {
      label: 'In progress',
      symbol: '…',
      description: 'Request in progress.',
      classes: 'border-sky-800 bg-sky-950/35 text-sky-100',
      badgeClasses: 'border-sky-700 bg-sky-900/60 text-sky-100',
    }
  }

  if (outcome.error) {
    return {
      label: 'Error',
      symbol: '!',
      description: 'The request could not be completed.',
      classes: 'border-rose-900 bg-rose-950/35 text-rose-100',
      badgeClasses: 'border-rose-800 bg-rose-900/60 text-rose-100',
    }
  }

  if (outcome.result?.status === 'success') {
    return {
      label: 'Complete',
      symbol: '✓',
      description: 'A validated response was received.',
      classes: 'border-emerald-900 bg-emerald-950/30 text-emerald-100',
      badgeClasses:
        'border-emerald-800 bg-emerald-900/60 text-emerald-100',
    }
  }

  if (outcome.result?.status === 'failure') {
    return {
      label: 'Not completed',
      symbol: '—',
      description: `Collector response: ${outcome.result.code}.`,
      classes: 'border-amber-900 bg-amber-950/30 text-amber-100',
      badgeClasses: 'border-amber-800 bg-amber-900/60 text-amber-100',
    }
  }

  return {
    label: 'Pending',
    symbol: '·',
    description: 'Waiting to start.',
    classes: 'border-slate-800 bg-slate-950/50 text-slate-200',
    badgeClasses: 'border-slate-700 bg-slate-800 text-slate-200',
  }
}

function ScannerStatus({ isLoading, name, outcome, score }) {
  const presentation = outcomePresentation(outcome, isLoading)

  return (
    <div className={`min-w-0 rounded-xl border p-4 ${presentation.classes}`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="font-semibold">{name}</h3>
          <p className="mt-1 break-words text-sm opacity-75 [overflow-wrap:anywhere]">
            {presentation.description}
          </p>
        </div>
        <span
          className={`inline-flex shrink-0 items-center gap-2 rounded-full border px-2.5 py-1 text-xs font-semibold uppercase tracking-wide ${presentation.badgeClasses}`}
        >
          <span aria-hidden="true">{presentation.symbol}</span>
          {presentation.label}
        </span>
      </div>

      {score && (
        <dl className="mt-4 grid grid-cols-2 gap-3 border-t border-current/15 pt-4">
          <div>
            <dt className="text-xs opacity-70">
              HTTP Security Configuration Score
            </dt>
            <dd className="mt-1 text-lg font-bold">
              {score.score}
              <span className="text-sm font-medium opacity-70"> / 100</span>
            </dd>
          </div>
          <div>
            <dt className="text-xs opacity-70">Grade</dt>
            <dd className="mt-1 text-lg font-bold">{score.grade}</dd>
          </div>
        </dl>
      )}
    </div>
  )
}

export function ScanOverview({
  hostname,
  httpOutcome,
  isLoading,
  tlsOutcome,
}) {
  const httpScore =
    httpOutcome.result?.status === 'success' ? httpOutcome.result.score : null

  return (
    <section
      aria-labelledby="scan-overview-heading"
      className="rounded-2xl border border-slate-800 bg-slate-900 p-5 sm:p-7"
    >
      <div className="flex flex-col gap-3 border-b border-slate-800 pb-5 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">
            Scan result overview
          </p>
          <h2
            className="mt-2 break-words text-2xl font-semibold text-slate-100 [overflow-wrap:anywhere]"
            id="scan-overview-heading"
          >
            {hostname}
          </h2>
        </div>
        <p className="text-sm text-slate-400">
          TLS and HTTP are reported independently.
        </p>
      </div>

      <div className="mt-5 grid min-w-0 gap-4 md:grid-cols-2">
        <ScannerStatus
          isLoading={isLoading}
          name="TLS certificate analysis"
          outcome={tlsOutcome}
        />
        <ScannerStatus
          isLoading={isLoading}
          name="HTTP security configuration"
          outcome={httpOutcome}
          score={httpScore}
        />
      </div>
    </section>
  )
}
