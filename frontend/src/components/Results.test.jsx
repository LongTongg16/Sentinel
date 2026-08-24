import { fireEvent, render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import {
  makeHttpHeaders,
  makeHttpSuccess,
  makeTlsFinding,
  makeTlsSuccess,
  successOutcome,
} from '../test/fixtures.js'
import { HttpResults } from './HttpResults.jsx'
import { TlsResults } from './TlsResults.jsx'

describe('TLS result rendering', () => {
  it('renders empty SANs, an unavailable key size, and no findings', () => {
    render(
      <TlsResults
        outcome={successOutcome(
          makeTlsSuccess({
            dns_names: [],
            public_key_size: null,
            findings: [],
          }),
        )}
      />,
    )

    expect(screen.getByText('No DNS SAN entries')).toBeInTheDocument()
    expect(screen.getByText('RSA')).toBeInTheDocument()
    expect(screen.queryByText(/2048 bits/)).not.toBeInTheDocument()
    expect(
      screen.getByText(
        'No issues were detected by the configured certificate checks.',
      ),
    ).toBeInTheDocument()
  })

  it('renders unknown severities and long certificate values without discarding content', () => {
    const longSubject = `CN=${'long-subject-value-'.repeat(30)}example.com`
    const longMessage = `Future scanner detail: ${'evidence '.repeat(40)}`.trim()

    render(
      <TlsResults
        outcome={successOutcome(
          makeTlsSuccess({
            subject: longSubject,
            findings: [
              makeTlsFinding({
                code: 'future_finding',
                severity: 'future',
                message: longMessage,
              }),
            ],
          }),
        )}
      />,
    )

    expect(screen.getByText(longSubject)).toBeInTheDocument()
    expect(screen.getByText('Unknown')).toBeInTheDocument()
    expect(screen.getByText('future_finding')).toBeInTheDocument()
    expect(screen.getByText(longMessage)).toBeInTheDocument()
  })
})

describe('HTTP result rendering', () => {
  it('renders present-but-empty headers, long values, no findings, and native methodology disclosure', () => {
    const longPolicy =
      `default-src 'self'; ${'img-src https://static.example; '.repeat(30)}`.trim()

    render(
      <HttpResults
        outcome={successOutcome(
          makeHttpSuccess({
            headers: makeHttpHeaders({
              content_security_policy: {
                present: true,
                value: longPolicy,
              },
              x_content_type_options: {
                present: true,
                value: '',
              },
              x_frame_options: {
                present: false,
                value: null,
              },
            }),
            findings: [],
          }),
        )}
      />,
    )

    expect(screen.getByText('Present with an empty value')).toBeInTheDocument()
    expect(screen.getByText(longPolicy)).toBeInTheDocument()

    const missingHeader = screen
      .getByRole('heading', { name: 'X-Frame-Options', level: 4 })
      .closest('li')
    expect(missingHeader).not.toBeNull()
    expect(within(missingHeader).getByText('Missing')).toBeInTheDocument()
    expect(
      within(missingHeader).getByText('No value observed'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(
        'No issues were detected by the configured HTTP header checks.',
      ),
    ).toBeInTheDocument()

    const methodologySummary = screen.getByText('Read full methodology')
    const methodologyDisclosure = methodologySummary.closest('details')

    expect(methodologySummary.tagName).toBe('SUMMARY')
    expect(methodologyDisclosure).not.toBeNull()
    fireEvent.click(methodologySummary)
    expect(methodologyDisclosure).toHaveAttribute('open')
  })
})
