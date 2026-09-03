import { useState } from 'react'
import { HttpResults } from './components/HttpResults.jsx'
import { ScanForm } from './components/ScanForm.jsx'
import { ScanOverview } from './components/ScanOverview.jsx'
import { TlsResults } from './components/TlsResults.jsx'
import { HeroReticle } from './components/icons.jsx'
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

// The authorship signature, framed by the Sentinel reticle. Rendered near the
// hero and again in the footer, at two different scales.
function Signature({ className = '' }) {
  return (
    <p
      className={`reticle inline-flex flex-col gap-1.5 px-5 py-4 ${className}`}
    >
      <span className="font-mono text-[0.62rem] uppercase tracking-[0.34em] text-ink-dim">
        Built by
      </span>
      <span className="font-mono text-sm uppercase tracking-[0.26em] text-ink">
        Stallon Angelino
        <span aria-hidden="true" className="caret" />
      </span>
    </p>
  )
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

  const hasScan = scannedHostname !== ''
  const scanStatusMessage = !hasScan
    ? ''
    : isLoading
      ? `Scanning ${scannedHostname}. TLS certificate and HTTP header checks are in progress.`
      : `Scan finished for ${scannedHostname}. TLS check: ${outcomeStatusLabel(tlsOutcome)}. HTTP check: ${outcomeStatusLabel(httpOutcome)}.`

  return (
    <main className="relative min-h-screen overflow-x-hidden px-5 py-12 text-ink sm:px-8 sm:py-16">
      <div className="mx-auto w-full max-w-5xl">
        <header>
          {/* Masthead: wordmark, measurement rule, operating mode. */}
          <div
            className="reveal flex items-center gap-4 sm:gap-6"
            style={{ '--i': 0 }}
          >
            <p className="font-mono text-sm font-semibold uppercase tracking-[0.42em] text-ink-strong">
              Sentinel
            </p>
            <span aria-hidden="true" className="tick-rule h-px flex-1" />
            <p className="hidden font-mono text-[0.62rem] uppercase tracking-[0.3em] text-ink-dim sm:block">
              Passive observation
            </p>
          </div>

          <div className="mt-12 grid gap-12 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-center lg:gap-16">
            <div className="min-w-0">
              <h1
                className="reveal font-display text-[2.6rem] leading-[1.03] sm:text-6xl lg:text-[4.25rem]"
                style={{ '--i': 1 }}
              >
                <span className="block font-normal text-ink">
                  Website security configuration,
                </span>
                <span className="mt-1 block font-semibold italic text-ink-strong">
                  clearly observed.
                </span>
              </h1>

              <p
                className="reveal mt-8 flex items-start gap-3 font-mono text-[0.68rem] uppercase leading-5 tracking-[0.24em] text-ink-dim sm:text-xs"
                style={{ '--i': 2 }}
              >
                <span
                  aria-hidden="true"
                  className="mt-1 h-3 w-px shrink-0 bg-ink-faint"
                />
                Passive TLS certificate and HTTP security configuration analysis
              </p>

              <p
                className="reveal mt-6 max-w-xl text-base leading-7 text-ink-dim"
                style={{ '--i': 3 }}
              >
                Inspect the TLS certificate and HTTP security headers a hostname
                publicly presents. Sentinel reports the two checks independently
                and explains every backend-provided finding.
              </p>
            </div>

            <div
              aria-hidden="true"
              className="reveal hidden shrink-0 text-ink-dim lg:block"
              style={{ '--i': 2 }}
            >
              <HeroReticle className="size-60" />
            </div>
          </div>

          <div className="reveal mt-12" style={{ '--i': 4 }}>
            <Signature />
          </div>
        </header>

        <p aria-live="polite" className="sr-only" role="status">
          {scanStatusMessage}
        </p>

        <div className="reveal mt-16" style={{ '--i': 5 }}>
          <ScanForm isLoading={isLoading} onScan={handleScan} />
        </div>

        {hasScan && (
          <div className="mt-20 grid min-w-0 gap-20">
            <div className="reveal min-w-0" style={{ '--i': 0 }}>
              <ScanOverview
                hostname={scannedHostname}
                httpOutcome={httpOutcome}
                isLoading={isLoading}
                tlsOutcome={tlsOutcome}
              />
            </div>

            {!isLoading && (
              <>
                <div className="reveal min-w-0" style={{ '--i': 1 }}>
                  <TlsResults outcome={tlsOutcome} />
                </div>
                <div className="reveal min-w-0" style={{ '--i': 2 }}>
                  <HttpResults outcome={httpOutcome} />
                </div>
              </>
            )}
          </div>
        )}

        <footer className="mt-28">
          <div aria-hidden="true" className="tick-scale h-2 w-full" />
          <div className="mt-10 grid gap-10 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-start sm:gap-12">
            <div className="min-w-0">
              <p className="font-mono text-sm font-semibold uppercase tracking-[0.42em] text-ink-strong">
                Sentinel
              </p>
              <p className="mt-3 text-sm text-ink-dim">
                Passive website security configuration analysis.
              </p>
              <p className="mt-6 max-w-xl border-l border-hairline pl-4 text-sm leading-6 text-ink-dim">
                Sentinel observes public configuration only. Results are not
                proof that a website is secure or exploitable.
              </p>
            </div>
            <Signature className="self-start" />
          </div>
        </footer>
      </div>
    </main>
  )
}

export default App
