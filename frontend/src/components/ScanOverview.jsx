import {
  CertificateIcon,
  CheckIcon,
  CriticalIcon,
  MinusIcon,
  NodesIcon,
  SpinnerIcon,
} from './icons.jsx'

function outcomePresentation(outcome, isLoading) {
  if (isLoading) {
    return {
      label: 'In progress',
      Icon: SpinnerIcon,
      iconClasses: 'size-3.5 animate-spin motion-reduce:animate-none',
      chip: 'border-hairline text-ink-dim',
      description: 'Request in progress.',
    }
  }

  if (outcome.error) {
    return {
      label: 'Error',
      Icon: CriticalIcon,
      iconClasses: 'size-3.5',
      chip: 'border-ink-strong bg-ink-strong font-semibold text-bg',
      description: 'The request could not be completed.',
    }
  }

  if (outcome.result?.status === 'success') {
    return {
      label: 'Complete',
      Icon: CheckIcon,
      iconClasses: 'size-3.5',
      chip: 'border-hairline-strong text-ink',
      description: 'A validated response was received.',
    }
  }

  if (outcome.result?.status === 'failure') {
    return {
      label: 'Not completed',
      Icon: MinusIcon,
      iconClasses: 'size-3.5',
      chip: 'border-ink font-semibold text-ink-strong',
      description: `Collector response: ${outcome.result.code}.`,
    }
  }

  return {
    label: 'Pending',
    Icon: MinusIcon,
    iconClasses: 'size-3.5',
    chip: 'border-dashed border-hairline text-ink-dim',
    description: 'Waiting to start.',
  }
}

function ScannerStatus({ Glyph, index, isLoading, name, outcome, score }) {
  const presentation = outcomePresentation(outcome, isLoading)
  const { Icon } = presentation

  return (
    <div className="panel reticle min-w-0 p-6 sm:p-7">
      <div className="flex items-start justify-between gap-4">
        <span className="inline-flex min-w-0 items-center gap-3">
          <Glyph className="size-5 shrink-0 text-ink-faint" />
          <span className="font-mono text-[0.62rem] uppercase tracking-[0.28em] text-ink-dim">
            Scanner {index}
          </span>
        </span>
        <span
          className={`inline-flex shrink-0 items-center gap-1.5 border px-2.5 py-1 font-mono text-[0.65rem] uppercase tracking-[0.16em] ${presentation.chip}`}
        >
          <Icon className={presentation.iconClasses} />
          {presentation.label}
        </span>
      </div>

      <h3 className="mt-6 text-lg font-semibold sm:text-xl">{name}</h3>
      <p className="tech-value mt-2 text-sm leading-6 text-ink-dim">
        {presentation.description}
      </p>

      {score && (
        <dl className="mt-6 flex min-w-0 flex-wrap gap-x-10 gap-y-4 border-t border-hairline pt-5">
          <div className="min-w-0">
            <dt className="font-mono text-[0.62rem] uppercase tracking-[0.22em] text-ink-dim">
              Score
            </dt>
            <dd className="mt-1.5 font-mono text-2xl font-semibold leading-none text-ink-strong">
              {score.score}
              <span className="ml-0.5 text-sm font-normal text-ink-dim">
                / 100
              </span>
            </dd>
          </div>
          <div className="min-w-0">
            <dt className="font-mono text-[0.62rem] uppercase tracking-[0.22em] text-ink-dim">
              Grade
            </dt>
            <dd className="mt-1.5 font-mono text-2xl font-semibold leading-none text-ink-strong">
              {score.grade}
            </dd>
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
    <section aria-labelledby="scan-overview-heading" className="min-w-0">
      <div className="flex items-center gap-4">
        <span className="font-mono text-[0.62rem] uppercase tracking-[0.3em] text-ink-dim">
          00
        </span>
        <span aria-hidden="true" className="tick-rule h-px flex-1" />
        <span className="font-mono text-[0.62rem] uppercase tracking-[0.3em] text-ink-dim">
          Overview
        </span>
      </div>

      <p className="mt-8 font-mono text-[0.65rem] uppercase tracking-[0.28em] text-ink-dim">
        Scan result overview
      </p>
      <h2
        className="tech-value mt-3 font-mono text-3xl font-semibold text-ink-strong sm:text-4xl"
        id="scan-overview-heading"
      >
        {hostname}
      </h2>
      <p className="mt-3 text-sm leading-6 text-ink-dim">
        TLS and HTTP are reported independently.
      </p>

      <div className="mt-8 grid min-w-0 gap-5 md:grid-cols-2">
        <ScannerStatus
          Glyph={CertificateIcon}
          index="01"
          isLoading={isLoading}
          name="TLS certificate analysis"
          outcome={tlsOutcome}
        />
        <ScannerStatus
          Glyph={NodesIcon}
          index="02"
          isLoading={isLoading}
          name="HTTP security configuration"
          outcome={httpOutcome}
          score={httpScore}
        />
      </div>
    </section>
  )
}
