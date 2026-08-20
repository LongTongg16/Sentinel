import { useState } from 'react'
import { HttpResults } from './components/HttpResults.jsx'
import { ScanForm } from './components/ScanForm.jsx'
import { ScanOverview } from './components/ScanOverview.jsx'
import { TlsResults } from './components/TlsResults.jsx'
import { scanHostname } from './api/scanApi.js'

function emptyOutcome() {
  return { result: null, error: '' }
}

function outcomeStatusLabel(outcome) {
  if (outcome.error) return 'error'
  if (outcome.result?.status === 'success') return 'complete'
  if (outcome.result?.status === 'failure') return 'not completed'
  return 'pending'
}

function App() {
  const [isLoading, setIsLoading] = useState(false)
  const [scannedHostname, setScannedHostname] = useState('')
  const [tlsOutcome, setTlsOutcome] = useState(emptyOutcome)
  const [httpOutcome, setHttpOutcome] = useState(emptyOutcome)

  async function handleScan(hostname) {
    setScannedHostname(hostname)
    setTlsOutcome(emptyOutcome())
    setHttpOutcome(emptyOutcome())
    setIsLoading(true)

    try {
      const { tls, http } = await scanHostname(hostname)
      setTlsOutcome(tls)
      setHttpOutcome(http)
    } finally {
      setIsLoading(false)
    }
  }

  function handleInvalidScan() {
    setScannedHostname('')
    setTlsOutcome(emptyOutcome())
    setHttpOutcome(emptyOutcome())
  }

  const hasScan = scannedHostname !== ''
  const scanStatusMessage = !hasScan
    ? ''
    : isLoading
      ? `Scanning ${scannedHostname}. TLS certificate and HTTP header checks are in progress.`
      : `Scan finished for ${scannedHostname}. TLS check: ${outcomeStatusLabel(tlsOutcome)}. HTTP check: ${outcomeStatusLabel(httpOutcome)}.`

  return (
    <main className="min-h-screen overflow-x-hidden bg-slate-950 px-4 py-10 text-slate-100 sm:px-6 sm:py-14 lg:px-8">
      <div className="mx-auto w-full max-w-6xl">
        <header className="mb-9 border-b border-slate-800 pb-8 sm:mb-10 sm:pb-10">
          <div className="flex flex-wrap items-center gap-3">
            <p className="text-sm font-semibold uppercase tracking-[0.24em] text-emerald-400">
              Sentinel
            </p>
            <span className="rounded-full border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-400">
              Passive assessment
            </span>
          </div>
          <h1 className="mt-4 max-w-4xl text-3xl font-bold tracking-tight text-white sm:text-4xl lg:text-5xl">
            Website security configuration, clearly observed
          </h1>
          <p className="mt-5 max-w-3xl text-base leading-7 text-slate-400 sm:text-lg">
            Inspect the TLS certificate and HTTP security headers a hostname
            publicly presents. Sentinel reports the two checks independently
            and explains every backend-provided finding.
          </p>
        </header>

        <p aria-live="polite" className="sr-only" role="status">
          {scanStatusMessage}
        </p>

        <ScanForm
          isLoading={isLoading}
          onInvalidScan={handleInvalidScan}
          onScan={handleScan}
        />

        {hasScan && (
          <div className="mt-8 grid min-w-0 gap-12 sm:mt-10 sm:gap-14">
            <ScanOverview
              hostname={scannedHostname}
              httpOutcome={httpOutcome}
              isLoading={isLoading}
              tlsOutcome={tlsOutcome}
            />

            {!isLoading && (
              <>
                <TlsResults outcome={tlsOutcome} />
                <HttpResults outcome={httpOutcome} />
              </>
            )}
          </div>
        )}

        <footer className="mt-14 border-t border-slate-800 pt-6 text-sm leading-6 text-slate-400">
          Sentinel observes public configuration only. Results are not proof
          that a website is secure or exploitable.
        </footer>
      </div>
    </main>
  )
}

export default App
