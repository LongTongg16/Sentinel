import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App.jsx'
import { scanHostname } from './api/scanApi.js'
import {
  errorOutcome,
  makeHttpFailure,
  makeHttpScore,
  makeHttpSuccess,
  makeTlsFailure,
  makeTlsSuccess,
  successOutcome,
} from './test/fixtures.js'

vi.mock('./api/scanApi.js', () => ({
  scanHostname: vi.fn(),
}))

function submitHostname(hostname) {
  const input = screen.getByLabelText('Hostname')
  fireEvent.change(input, { target: { value: hostname } })
  fireEvent.click(screen.getByRole('button', { name: 'Run scan' }))
  return input
}

describe('App scanner outcomes', () => {
  beforeEach(() => {
    scanHostname.mockReset()
  })

  it.each([
    {
      label: 'TLS success and HTTP success',
      tls: () => successOutcome(makeTlsSuccess()),
      http: () => successOutcome(makeHttpSuccess()),
      tlsSucceeded: true,
      httpSucceeded: true,
    },
    {
      label: 'TLS success and HTTP failure',
      tls: () => successOutcome(makeTlsSuccess()),
      http: () => successOutcome(makeHttpFailure()),
      tlsSucceeded: true,
      httpSucceeded: false,
    },
    {
      label: 'TLS failure and HTTP success',
      tls: () => successOutcome(makeTlsFailure()),
      http: () => successOutcome(makeHttpSuccess()),
      tlsSucceeded: false,
      httpSucceeded: true,
    },
    {
      label: 'TLS failure and HTTP failure',
      tls: () => successOutcome(makeTlsFailure()),
      http: () => successOutcome(makeHttpFailure()),
      tlsSucceeded: false,
      httpSucceeded: false,
    },
  ])(
    'renders independent results for $label',
    async ({ http, httpSucceeded, tls, tlsSucceeded }) => {
      scanHostname.mockResolvedValue({ tls: tls(), http: http() })
      render(<App />)

      submitHostname('example.com')

      await waitFor(() => {
        expect(scanHostname).toHaveBeenCalledWith('example.com')
      })

      if (tlsSucceeded) {
        expect(
          await screen.findByRole('heading', { name: 'Connection' }),
        ).toBeInTheDocument()
        expect(screen.getByText('CN=example.com')).toBeInTheDocument()
        expect(
          screen.queryByRole('heading', {
            name: 'TLS scan could not be completed',
          }),
        ).not.toBeInTheDocument()
      } else {
        expect(
          await screen.findByRole('heading', {
            name: 'TLS scan could not be completed',
          }),
        ).toBeInTheDocument()
        expect(
          screen.queryByRole('heading', { name: 'Connection' }),
        ).not.toBeInTheDocument()
      }

      if (httpSucceeded) {
        expect(
          screen.getByRole('heading', {
            name: 'HTTP Security Configuration Score',
          }),
        ).toBeInTheDocument()
        expect(
          screen.getByLabelText('Score 100 out of 100'),
        ).toBeInTheDocument()
        expect(screen.getByText('Grade A+')).toBeInTheDocument()
        expect(
          screen.queryByRole('heading', {
            name: 'HTTP header scan could not be completed',
          }),
        ).not.toBeInTheDocument()
      } else {
        expect(
          screen.getByRole('heading', {
            name: 'HTTP header scan could not be completed',
          }),
        ).toBeInTheDocument()
        expect(
          screen.queryByRole('heading', {
            name: 'HTTP Security Configuration Score',
          }),
        ).not.toBeInTheDocument()
      }
    },
  )

  it('disables scanning controls while preserving the submitted hostname snapshot', async () => {
    let resolveScan
    scanHostname.mockReturnValue(
      new Promise((resolve) => {
        resolveScan = resolve
      }),
    )
    render(<App />)

    const input = submitHostname('  Example.COM  ')

    expect(scanHostname).toHaveBeenCalledWith('Example.COM')
    expect(input).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Scanning…' })).toBeDisabled()

    await act(async () => {
      resolveScan({
        tls: successOutcome(makeTlsSuccess({ hostname: 'Example.COM' })),
        http: successOutcome(
          makeHttpSuccess({ requested_hostname: 'Example.COM' }),
        ),
      })
    })

    expect(
      await screen.findByRole('heading', { name: 'Example.COM', level: 2 }),
    ).toBeInTheDocument()
    fireEvent.change(input, { target: { value: 'other.example' } })
    expect(
      screen.getByRole('heading', { name: 'Example.COM', level: 2 }),
    ).toBeInTheDocument()
  })

  it.each(['', '   '])(
    'preserves completed results when invalid hostname %j is submitted',
    async (invalidHostname) => {
      scanHostname.mockResolvedValue({
        tls: successOutcome(
          makeTlsSuccess({ subject: 'CN=preserved-certificate.example' }),
        ),
        http: successOutcome(
          makeHttpSuccess({ score: makeHttpScore({ score: 90, grade: 'A' }) }),
        ),
      })
      render(<App />)

      const input = submitHostname('example.com')
      expect(
        await screen.findByText('CN=preserved-certificate.example'),
      ).toBeInTheDocument()
      expect(screen.getByLabelText('Score 90 out of 100')).toBeInTheDocument()

      fireEvent.change(input, { target: { value: invalidHostname } })
      fireEvent.click(screen.getByRole('button', { name: 'Run scan' }))

      expect(screen.getByRole('alert')).toHaveTextContent(
        'Enter a hostname to scan.',
      )
      expect(
        screen.getByText('CN=preserved-certificate.example'),
      ).toBeInTheDocument()
      expect(screen.getByLabelText('Score 90 out of 100')).toBeInTheDocument()
      expect(scanHostname).toHaveBeenCalledTimes(1)
    },
  )

  it('keeps one persistent polite scan-status region through a scan', async () => {
    let resolveScan
    scanHostname.mockReturnValue(
      new Promise((resolve) => {
        resolveScan = resolve
      }),
    )
    render(<App />)

    const statusRegion = screen.getByRole('status')
    expect(statusRegion).toHaveAttribute('aria-live', 'polite')
    expect(statusRegion).toBeEmptyDOMElement()

    submitHostname('example.com')

    expect(screen.getAllByRole('status')).toHaveLength(1)
    expect(statusRegion).toHaveTextContent(
      'Scanning example.com. TLS certificate and HTTP header checks are in progress.',
    )

    await act(async () => {
      resolveScan({
        tls: successOutcome(makeTlsSuccess()),
        http: successOutcome(makeHttpSuccess()),
      })
    })

    expect(screen.getAllByRole('status')).toHaveLength(1)
    expect(screen.getByRole('status')).toBe(statusRegion)
    expect(statusRegion).toHaveTextContent(
      'Scan finished for example.com. TLS check: complete. HTTP check: complete.',
    )
  })

  it('keeps TLS and HTTP request errors distinct without assertive result alerts', async () => {
    scanHostname.mockResolvedValue({
      tls: errorOutcome('The TLS request failed for this test.'),
      http: errorOutcome('The HTTP request failed for this test.'),
    })
    render(<App />)

    submitHostname('example.com')

    expect(
      await screen.findByRole('heading', { name: 'TLS scan error' }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('heading', { name: 'HTTP header scan error' }),
    ).toBeInTheDocument()
    expect(
      screen.getByText('The TLS request failed for this test.'),
    ).toBeInTheDocument()
    expect(
      screen.getByText('The HTTP request failed for this test.'),
    ).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getAllByRole('status')).toHaveLength(1)
  })

  it('clears stale results and errors across rescans', async () => {
    let resolveSecondScan
    scanHostname
      .mockResolvedValueOnce({
        tls: successOutcome(
          makeTlsSuccess({ subject: 'CN=first-certificate.example' }),
        ),
        http: successOutcome(
          makeHttpSuccess({ score: makeHttpScore({ score: 90, grade: 'A' }) }),
        ),
      })
      .mockReturnValueOnce(
        new Promise((resolve) => {
          resolveSecondScan = resolve
        }),
      )
      .mockResolvedValueOnce({
        tls: successOutcome(
          makeTlsSuccess({ subject: 'CN=third-certificate.example' }),
        ),
        http: successOutcome(
          makeHttpSuccess({ score: makeHttpScore({ score: 80, grade: 'B' }) }),
        ),
      })
    render(<App />)

    const input = submitHostname('first.example')
    expect(
      await screen.findByText('CN=first-certificate.example'),
    ).toBeInTheDocument()
    expect(screen.getByLabelText('Score 90 out of 100')).toBeInTheDocument()

    fireEvent.change(input, { target: { value: 'second.example' } })
    fireEvent.click(screen.getByRole('button', { name: 'Run scan' }))

    expect(
      screen.queryByText('CN=first-certificate.example'),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByLabelText('Score 90 out of 100'),
    ).not.toBeInTheDocument()

    await act(async () => {
      resolveSecondScan({
        tls: successOutcome(makeTlsFailure()),
        http: errorOutcome('The HTTP request failed for this test.'),
      })
    })

    expect(
      await screen.findByRole('heading', {
        name: 'TLS scan could not be completed',
      }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('heading', { name: 'HTTP header scan error' }),
    ).toBeInTheDocument()

    fireEvent.change(input, { target: { value: 'third.example' } })
    fireEvent.click(screen.getByRole('button', { name: 'Run scan' }))

    expect(
      await screen.findByText('CN=third-certificate.example'),
    ).toBeInTheDocument()
    expect(screen.getByLabelText('Score 80 out of 100')).toBeInTheDocument()
    expect(
      screen.queryByRole('heading', {
        name: 'TLS scan could not be completed',
      }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('heading', { name: 'HTTP header scan error' }),
    ).not.toBeInTheDocument()
  })
})
