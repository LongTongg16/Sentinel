import { useState } from 'react'
import { ArrowRightIcon, TargetIcon } from './icons.jsx'

export function ScanForm({ isLoading, onScan }) {
  const [hostname, setHostname] = useState('')
  const [formError, setFormError] = useState('')

  function handleSubmit(event) {
    event.preventDefault()

    const trimmedHostname = hostname.trim()
    if (!trimmedHostname) {
      setFormError('Enter a hostname to scan.')
      return
    }

    setFormError('')
    onScan(trimmedHostname)
  }

  function handleHostnameChange(event) {
    setHostname(event.target.value)
    if (formError) {
      setFormError('')
    }
  }

  const describedBy = formError
    ? 'hostname-help hostname-error'
    : 'hostname-help'

  return (
    <section
      aria-labelledby="scan-form-heading"
      className="scan-panel panel-raised"
      data-scanning={isLoading ? 'true' : 'false'}
    >
      {/* Instrument header strip. The right-hand readout is decorative - the
          authoritative state lives in the button label, aria-busy, and the
          polite live region in App. */}
      <div className="flex items-center justify-between gap-4 border-b border-hairline px-6 py-3.5 sm:px-8">
        <p className="flex items-center gap-2.5 font-mono text-[0.65rem] uppercase tracking-[0.28em] text-ink-dim">
          <TargetIcon
            className={`size-3.5 text-ink-faint ${isLoading ? 'pulse-dot' : ''}`}
          />
          Scan target
        </p>
        <p
          aria-hidden="true"
          className="font-mono text-[0.65rem] uppercase tracking-[0.28em] text-ink-faint"
        >
          {isLoading ? 'Active' : 'Standby'}
        </p>
      </div>

      <div className="px-6 py-7 sm:px-8 sm:py-8">
        <h2
          className="text-xl font-semibold tracking-tight sm:text-2xl"
          id="scan-form-heading"
        >
          Assess a hostname
        </h2>
        <p className="mt-2.5 max-w-xl text-sm leading-6 text-ink-dim">
          Sentinel runs the TLS certificate and HTTP header checks separately,
          then presents each result without combining their security meaning.
        </p>

        <form className="mt-8" noValidate onSubmit={handleSubmit}>
          <div className="flex items-baseline justify-between gap-4">
            <label
              className="font-mono text-[0.65rem] font-medium uppercase tracking-[0.24em] text-ink-dim"
              htmlFor="hostname"
            >
              Hostname
            </label>
            <span
              aria-hidden="true"
              className="font-mono text-[0.6rem] uppercase tracking-[0.24em] text-ink-faint"
            >
              Input
            </span>
          </div>
          <p className="mt-2 text-sm text-ink-dim" id="hostname-help">
            Enter a hostname only, without a URL scheme or path.
          </p>

          <div className="mt-4 flex flex-col gap-3 sm:flex-row">
            <input
              aria-describedby={describedBy}
              aria-invalid={formError ? 'true' : 'false'}
              autoCapitalize="none"
              autoComplete="off"
              autoCorrect="off"
              className="scan-input min-w-0 flex-1 border border-hairline bg-panel-raised px-4 py-3.5 font-mono text-base text-ink-strong outline-none placeholder:text-ink-dim disabled:opacity-50 sm:text-sm"
              disabled={isLoading}
              id="hostname"
              name="hostname"
              onChange={handleHostnameChange}
              placeholder="example.com"
              required
              spellCheck="false"
              type="text"
              value={hostname}
            />
            <button
              aria-busy={isLoading}
              className="scan-button inline-flex shrink-0 items-center justify-center gap-2.5 px-7 py-3.5 font-mono text-sm font-semibold uppercase tracking-[0.16em]"
              disabled={isLoading}
              type="submit"
            >
              {isLoading ? 'Scanning…' : 'Run scan'}
              <ArrowRightIcon className="scan-button__arrow size-4" />
            </button>
          </div>

          {isLoading && (
            <div aria-hidden="true" className="scan-rail mt-5 h-px w-full" />
          )}

          {formError && (
            <p
              className="mt-4 font-mono text-sm font-medium text-ink-strong"
              id="hostname-error"
              role="alert"
            >
              {formError}
            </p>
          )}
        </form>
      </div>
    </section>
  )
}
