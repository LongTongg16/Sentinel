import { CriticalIcon, HelpIcon, InfoIcon, WarningIcon } from './icons.jsx'

// Monochrome severity. Five independent, non-colour signals move together:
// the left rail (width + brightness + solid/dashed), the card fill, the card
// border style, the chip treatment (solid / outlined / dashed), and the icon
// shape. The written label is always present, so nothing depends on styling
// alone and nothing depends on opacity alone.
function severityPresentation(severity) {
  if (severity === 'critical') {
    return {
      label: 'Critical',
      Icon: CriticalIcon,
      card: 'border-hairline-strong bg-panel',
      rail: 'w-1.5 bg-ink-strong',
      chip: 'border-ink-strong bg-ink-strong font-semibold text-bg',
    }
  }
  if (severity === 'warning') {
    return {
      label: 'Warning',
      Icon: WarningIcon,
      card: 'border-hairline bg-panel',
      rail: 'w-1 bg-ink',
      chip: 'border-ink font-semibold text-ink-strong',
    }
  }
  if (severity === 'info') {
    return {
      label: 'Info',
      Icon: InfoIcon,
      card: 'border-hairline',
      rail: 'w-0.5 bg-hairline-strong',
      chip: 'border-hairline-strong font-medium text-ink-dim',
    }
  }
  return {
    label: 'Unknown',
    Icon: HelpIcon,
    card: 'border-dashed border-hairline',
    rail: 'w-0.5 bg-[repeating-linear-gradient(180deg,var(--color-hairline-strong)_0_4px,transparent_4px_9px)]',
    chip: 'border-dashed border-hairline font-medium text-ink-dim',
  }
}

function displayText(value, fallback = 'Not available') {
  return typeof value === 'string' && value.trim() ? value : fallback
}

function FindingCard({ finding }) {
  const { Icon, label, card, rail, chip } = severityPresentation(
    finding.severity,
  )

  return (
    <li className={`finding flex min-w-0 border ${card}`}>
      <span aria-hidden="true" className={`shrink-0 ${rail}`} />
      <div className="min-w-0 flex-1 px-5 py-4 sm:px-6 sm:py-5">
        <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-2">
          <span
            className={`inline-flex shrink-0 items-center gap-1.5 border px-2.5 py-1 font-mono text-[0.65rem] uppercase tracking-[0.18em] ${chip}`}
          >
            <Icon className="size-3.5" />
            {label}
          </span>
          <code className="tech-value font-mono text-xs text-ink-dim">
            {displayText(finding.code)}
          </code>
        </div>
        <p className="tech-value mt-3.5 text-sm leading-6">
          {displayText(finding.message)}
        </p>
      </div>
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
    <section aria-labelledby={headingId} className="min-w-0">
      <h3 className="group-heading" id={headingId}>
        {title}
      </h3>
      <p className="mt-3 max-w-xl text-sm leading-6 text-ink-dim">
        {description}
      </p>

      {findings.length > 0 ? (
        <ul className="mt-6 grid min-w-0 gap-4">
          {findings.map((finding, index) => (
            <FindingCard finding={finding} key={`${finding.code}-${index}`} />
          ))}
        </ul>
      ) : (
        <p className="mt-5 border-l border-dashed border-hairline py-1 pl-4 text-sm text-ink-dim">
          {emptyMessage}
        </p>
      )}
    </section>
  )
}
