import { useState } from 'react'

const API_BASE_URL = '/api/v1'
const TLS_LEAF_CERTIFICATE_ENDPOINT = `${API_BASE_URL}/tls/leaf-certificate`

function isSuccessResponse(value) {
  return (
    value?.status === 'success' &&
    typeof value.hostname === 'string' &&
    typeof value.connected_ip === 'string' &&
    typeof value.certificate_sha256 === 'string'
  )
}

function isFailureResponse(value) {
  return (
    value?.status === 'failure' &&
    typeof value.stage === 'string' &&
    typeof value.code === 'string'
  )
}

function App() {
  const [hostname, setHostname] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)

  async function handleSubmit(event) {
    event.preventDefault()

    const trimmedHostname = hostname.trim()
    if (!trimmedHostname) {
      setResult(null)
      setError('Enter a hostname to scan.')
      return
    }

    setIsLoading(true)
    setResult(null)
    setError('')

    try {
      const response = await fetch(TLS_LEAF_CERTIFICATE_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ hostname: trimmedHostname }),
      })

      let responseBody
      try {
        responseBody = await response.json()
      } catch {
        setError('Sentinel returned an unexpected response. Please try again.')
        return
      }

      if (!response.ok) {
        if (isFailureResponse(responseBody)) {
          setResult(responseBody)
        } else {
          setError('The scan request failed unexpectedly. Please try again.')
        }
        return
      }

      if (isSuccessResponse(responseBody) || isFailureResponse(responseBody)) {
        setResult(responseBody)
      } else {
        setError('Sentinel returned an unexpected response. Please try again.')
      }
    } catch {
      setError(
        'Unable to reach the Sentinel API. Check that the backend is running.',
      )
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <main className="min-h-screen bg-slate-950 px-5 py-16 text-slate-100">
      <div className="mx-auto w-full max-w-3xl">
        <header className="mb-10">
          <p className="mb-3 text-sm font-semibold uppercase tracking-[0.2em] text-emerald-400">
            Sentinel
          </p>
          <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">
            TLS leaf certificate scan
          </h1>
          <p className="mt-4 max-w-2xl text-slate-400">
            Check the publicly observable TLS certificate presented for a
            hostname.
          </p>
        </header>

        <section className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-xl shadow-black/20 sm:p-8">
          <form onSubmit={handleSubmit}>
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
                aria-describedby="hostname-help"
                autoCapitalize="none"
                autoCorrect="off"
                className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-emerald-400 focus:ring-2 focus:ring-emerald-400/20"
                disabled={isLoading}
                id="hostname"
                name="hostname"
                onChange={(event) => setHostname(event.target.value)}
                placeholder="example.com"
                required
                spellCheck="false"
                type="text"
                value={hostname}
              />
              <button
                aria-busy={isLoading}
                className="rounded-lg bg-emerald-400 px-6 py-3 font-semibold text-slate-950 transition hover:bg-emerald-300 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
                disabled={isLoading}
                type="submit"
              >
                {isLoading ? 'Scanning…' : 'Scan'}
              </button>
            </div>
          </form>
        </section>

        <div aria-live="polite" className="mt-6">
          {error && (
            <p
              className="rounded-xl border border-rose-900 bg-rose-950/60 p-4 text-rose-200"
              role="alert"
            >
              {error}
            </p>
          )}

          {result?.status === 'success' && (
            <section className="rounded-xl border border-emerald-900 bg-emerald-950/30 p-6">
              <h2 className="text-lg font-semibold text-emerald-300">
                Certificate collected
              </h2>
              <dl className="mt-5 grid gap-5">
                <div>
                  <dt className="text-sm text-slate-400">Hostname</dt>
                  <dd className="mt-1 font-medium">{result.hostname}</dd>
                </div>
                <div>
                  <dt className="text-sm text-slate-400">Connected IP</dt>
                  <dd className="mt-1 font-mono text-sm">
                    {result.connected_ip}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm text-slate-400">
                    Certificate SHA-256
                  </dt>
                  <dd className="mt-1 break-all font-mono text-sm text-slate-200">
                    {result.certificate_sha256}
                  </dd>
                </div>
              </dl>
            </section>
          )}

          {result?.status === 'failure' && (
            <section className="rounded-xl border border-amber-900 bg-amber-950/30 p-6">
              <h2 className="text-lg font-semibold text-amber-300">
                Scan could not be completed
              </h2>
              <dl className="mt-5 grid gap-5 sm:grid-cols-2">
                <div>
                  <dt className="text-sm text-slate-400">Stage</dt>
                  <dd className="mt-1 font-mono text-sm">{result.stage}</dd>
                </div>
                <div>
                  <dt className="text-sm text-slate-400">Code</dt>
                  <dd className="mt-1 font-mono text-sm">{result.code}</dd>
                </div>
              </dl>
            </section>
          )}
        </div>
      </div>
    </main>
  )
}

export default App
