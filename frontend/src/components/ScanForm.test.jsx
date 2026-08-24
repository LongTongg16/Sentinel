import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ScanForm } from './ScanForm.jsx'

function renderScanForm(overrides = {}) {
  const props = {
    isLoading: false,
    onScan: vi.fn(),
    ...overrides,
  }

  render(<ScanForm {...props} />)
  return props
}

describe('ScanForm', () => {
  it('submits a trimmed hostname through the labelled input', () => {
    const { onScan } = renderScanForm()
    const input = screen.getByLabelText('Hostname')

    fireEvent.change(input, { target: { value: '  Example.COM  ' } })
    fireEvent.click(screen.getByRole('button', { name: 'Run scan' }))

    expect(onScan).toHaveBeenCalledOnce()
    expect(onScan).toHaveBeenCalledWith('Example.COM')
  })

  it.each(['', '   '])(
    'announces validation for an empty hostname value %j',
    (hostname) => {
      const { onScan } = renderScanForm()
      const input = screen.getByLabelText('Hostname')

      fireEvent.change(input, { target: { value: hostname } })
      fireEvent.click(screen.getByRole('button', { name: 'Run scan' }))

      expect(screen.getByRole('alert')).toHaveTextContent(
        'Enter a hostname to scan.',
      )
      expect(input).toHaveAttribute('aria-invalid', 'true')
      expect(input).toHaveAttribute(
        'aria-describedby',
        'hostname-help hostname-error',
      )
      expect(onScan).not.toHaveBeenCalled()
    },
  )

  it('disables the input and submit button while scanning', () => {
    renderScanForm({ isLoading: true })

    expect(screen.getByLabelText('Hostname')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Scanning…' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Scanning…' })).toHaveAttribute(
      'aria-busy',
      'true',
    )
  })
})
