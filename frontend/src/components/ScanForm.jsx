import { useState } from 'react'

export function ScanForm({ isLoading, onInvalidScan, onScan }) {
  const [hostname, setHostname] = useState('')
  const [formError, setFormError] = useState('')

  function handleSubmit(event) {
    event.preventDefault()

    const trimmedHostname = hostname.trim()
    if (!trimmedHostname) {
      setFormError('Enter a hostname to scan.')
      onInvalidScan()
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
      className="rounded-2xl border border-slate-800 bg-slate-900/90 p-5 shadow-2xl shadow-black/20 sm:p-7"
    >
      <div className="max-w-2xl">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-emerald-400">
          Scan target
        </p>
        <h2
          className="mt-2 text-xl font-semibold text-slate-100 sm:text-2xl"
          id="scan-form-heading"
        >
          Assess a hostname
        </h2>
        <p className="mt-2 text-sm leading-6 text-slate-400">
          Sentinel runs the TLS certificate and HTTP header checks separately,
          then presents each result without combining their security meaning.
        </p>
      </div>

      <form className="mt-6" noValidate onSubmit={handleSubmit}>
        <label
          className="block text-sm font-medium text-slate-200"
          htmlFor="hostname"
        >
          Hostname
        </label>
        <p className="mt-1 text-sm text-slate-400" id="hostname-help">
          Enter a hostname only, without a URL scheme or path.
        </p>

        <div className="mt-4 flex flex-col gap-3 sm:flex-row">
          <input
            aria-describedby={describedBy}
            aria-invalid={formError ? 'true' : 'false'}
            autoCapitalize="none"
            autoComplete="off"
            autoCorrect="off"
            className="min-w-0 flex-1 rounded-lg border border-slate-500 bg-slate-950 px-4 py-3 text-slate-100 outline-none transition placeholder:text-slate-400 hover:border-slate-600 focus:border-emerald-400 focus:ring-2 focus:ring-emerald-400/25 disabled:cursor-not-allowed disabled:opacity-60"
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
            className="rounded-lg bg-emerald-400 px-7 py-3 font-semibold text-slate-950 transition hover:bg-emerald-300 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
            disabled={isLoading}
            type="submit"
          >
            {isLoading ? 'Scanning…' : 'Run scan'}
          </button>
        </div>

        {formError && (
          <p
            className="mt-3 text-sm font-medium text-rose-300"
            id="hostname-error"
            role="alert"
          >
            {formError}
          </p>
        )}
      </form>
    </section>
  )
}
