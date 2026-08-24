import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { scanHostname } from './scanApi.js'
import {
  makeHttpFailure,
  makeHttpScore,
  makeHttpSuccess,
  makeTlsFailure,
  makeTlsSuccess,
} from '../test/fixtures.js'

const UNEXPECTED_RESPONSE =
  'Sentinel returned an unexpected response. Please try again.'
const TIMEOUT_RESPONSE = 'The scan timed out. Please try again.'
const SCAN_FAILURE_RESPONSE =
  'The scan request failed unexpectedly. Please try again.'
const NETWORK_RESPONSE =
  'Unable to reach the Sentinel API. Check that the backend is running.'

function makeResponse(body, { jsonError = null, ok = true } = {}) {
  return {
    ok,
    json: jsonError
      ? vi.fn().mockRejectedValue(jsonError)
      : vi.fn().mockResolvedValue(body),
  }
}

function withoutField(value, field) {
  const result = { ...value }
  delete result[field]
  return result
}

describe('scanHostname', () => {
  let fetchMock

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  function mockResponses(tlsResponse, httpResponse) {
    fetchMock.mockImplementation((endpoint) =>
      Promise.resolve(
        endpoint.includes('/tls/') ? tlsResponse : httpResponse,
      ),
    )
  }

  it('posts the same hostname to both endpoints with independent signals', async () => {
    mockResponses(
      makeResponse(makeTlsSuccess()),
      makeResponse(makeHttpSuccess()),
    )

    const result = await scanHostname('example.com')

    expect(result.tls.result).toMatchObject({ status: 'success' })
    expect(result.http.result).toMatchObject({ status: 'success' })
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      '/api/v1/tls/leaf-certificate',
      expect.objectContaining({
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostname: 'example.com' }),
        signal: expect.anything(),
      }),
    )
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      '/api/v1/http/security-headers',
      expect.objectContaining({
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostname: 'example.com' }),
        signal: expect.anything(),
      }),
    )
    expect(fetchMock.mock.calls[0][1].signal).not.toBe(
      fetchMock.mock.calls[1][1].signal,
    )
  })

  it.each([
    {
      label: 'TLS success missing a required field',
      scanner: 'tls',
      body: () => withoutField(makeTlsSuccess(), 'subject'),
    },
    {
      label: 'HTTP success missing a required field',
      scanner: 'http',
      body: () => withoutField(makeHttpSuccess(), 'final_url'),
    },
    {
      label: 'HTTP score with an invalid grade',
      scanner: 'http',
      body: () =>
        makeHttpSuccess({ score: makeHttpScore({ grade: 'Z' }) }),
    },
    {
      label: 'HTTP score with a fractional value',
      scanner: 'http',
      body: () =>
        makeHttpSuccess({ score: makeHttpScore({ score: 99.5 }) }),
    },
    {
      label: 'HTTP score with negative deduction points',
      scanner: 'http',
      body: () =>
        makeHttpSuccess({
          score: makeHttpScore({
            deductions: [
              {
                control: 'strict-transport-security',
                points: -5,
                reason: 'Invalid negative deduction.',
              },
            ],
          }),
        }),
    },
  ])('fails safely for $label', async ({ body, scanner }) => {
    const tlsBody = scanner === 'tls' ? body() : makeTlsSuccess()
    const httpBody = scanner === 'http' ? body() : makeHttpSuccess()
    mockResponses(makeResponse(tlsBody), makeResponse(httpBody))

    const result = await scanHostname('example.com')

    expect(result[scanner]).toEqual({
      result: null,
      error: UNEXPECTED_RESPONSE,
    })
    expect(result[scanner === 'tls' ? 'http' : 'tls'].result).toMatchObject({
      status: 'success',
    })
  })

  it('classifies AbortError thrown during response parsing as a timeout', async () => {
    const abortError = new Error('aborted while reading JSON')
    abortError.name = 'AbortError'
    mockResponses(
      makeResponse(null, { jsonError: abortError }),
      makeResponse(makeHttpSuccess()),
    )

    const result = await scanHostname('example.com')

    expect(result.tls).toEqual({ result: null, error: TIMEOUT_RESPONSE })
    expect(result.http.result).toMatchObject({ status: 'success' })
  })

  it('classifies AbortError thrown by fetch as a timeout', async () => {
    const abortError = new Error('request aborted')
    abortError.name = 'AbortError'
    fetchMock.mockImplementation((endpoint) =>
      endpoint.includes('/tls/')
        ? Promise.reject(abortError)
        : Promise.resolve(makeResponse(makeHttpSuccess())),
    )

    const result = await scanHostname('example.com')

    expect(result.tls).toEqual({ result: null, error: TIMEOUT_RESPONSE })
    expect(result.http.result).toMatchObject({ status: 'success' })
  })

  it('classifies malformed JSON as an unexpected response', async () => {
    mockResponses(
      makeResponse(null, { jsonError: new SyntaxError('invalid JSON') }),
      makeResponse(makeHttpSuccess()),
    )

    const result = await scanHostname('example.com')

    expect(result.tls).toEqual({ result: null, error: UNEXPECTED_RESPONSE })
  })

  it('preserves typed backend failures returned with non-OK status codes', async () => {
    mockResponses(
      makeResponse(makeTlsFailure(), { ok: false }),
      makeResponse(makeHttpFailure(), { ok: false }),
    )

    const result = await scanHostname('example.com')

    expect(result.tls).toEqual({ result: makeTlsFailure(), error: '' })
    expect(result.http).toEqual({ result: makeHttpFailure(), error: '' })
  })

  it('classifies a malformed non-OK response as a generic scan request failure', async () => {
    mockResponses(
      makeResponse({ detail: 'unexpected shape' }, { ok: false }),
      makeResponse(makeHttpSuccess()),
    )

    const result = await scanHostname('example.com')

    expect(result.tls).toEqual({
      result: null,
      error: SCAN_FAILURE_RESPONSE,
    })
    expect(result.http.result).toMatchObject({ status: 'success' })
  })

  it('classifies fetch rejection as a network error without hiding HTTP success', async () => {
    fetchMock.mockImplementation((endpoint) =>
      endpoint.includes('/tls/')
        ? Promise.reject(new TypeError('network unavailable'))
        : Promise.resolve(makeResponse(makeHttpSuccess())),
    )

    const result = await scanHostname('example.com')

    expect(result.tls).toEqual({ result: null, error: NETWORK_RESPONSE })
    expect(result.http.result).toMatchObject({ status: 'success' })
  })
})
