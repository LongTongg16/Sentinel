const API_BASE_URL = '/api/v1'
const TLS_LEAF_CERTIFICATE_ENDPOINT = `${API_BASE_URL}/tls/leaf-certificate`
const HTTP_SECURITY_HEADERS_ENDPOINT = `${API_BASE_URL}/http/security-headers`
const SCAN_REQUEST_TIMEOUT_MS = 15000

const TLS_SUCCESS_STRING_FIELDS = [
  'hostname',
  'connected_ip',
  'certificate_sha256',
  'subject',
  'issuer',
  'valid_from',
  'expires_at',
  'serial_number',
  'signature_algorithm',
  'public_key_type',
]

const HTTP_SUCCESS_STRING_FIELDS = [
  'requested_hostname',
  'connected_ip',
  'final_url',
  'final_hostname',
]

const HTTP_HEADER_KEYS = [
  'strict_transport_security',
  'content_security_policy',
  'x_content_type_options',
  'x_frame_options',
  'referrer_policy',
  'permissions_policy',
]

const HTTP_SCORE_VALID_GRADES = [
  'A+',
  'A',
  'A-',
  'B+',
  'B',
  'B-',
  'C+',
  'C',
  'C-',
  'D+',
  'D',
  'D-',
  'F',
]

function isFinding(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    typeof value.code === 'string' &&
    typeof value.severity === 'string' &&
    typeof value.message === 'string'
  )
}

function isTlsSuccessResponse(value) {
  return (
    value?.status === 'success' &&
    TLS_SUCCESS_STRING_FIELDS.every(
      (field) => typeof value[field] === 'string',
    ) &&
    Number.isInteger(value.days_remaining) &&
    Array.isArray(value.dns_names) &&
    value.dns_names.every((dnsName) => typeof dnsName === 'string') &&
    (value.public_key_size === null ||
      Number.isInteger(value.public_key_size)) &&
    Array.isArray(value.findings) &&
    value.findings.every(isFinding)
  )
}

function isSecurityHeaderValue(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    typeof value.present === 'boolean' &&
    (value.value === null || typeof value.value === 'string')
  )
}

function isNormalizedHeaders(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    HTTP_HEADER_KEYS.every((key) => isSecurityHeaderValue(value[key]))
  )
}

function isHttpScoreDeduction(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    typeof value.control === 'string' &&
    value.control.trim() !== '' &&
    typeof value.points === 'number' &&
    Number.isInteger(value.points) &&
    value.points >= 0 &&
    typeof value.reason === 'string' &&
    value.reason.trim() !== ''
  )
}

function isHttpSecurityScore(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    typeof value.score === 'number' &&
    Number.isInteger(value.score) &&
    typeof value.grade === 'string' &&
    HTTP_SCORE_VALID_GRADES.includes(value.grade) &&
    typeof value.methodology === 'string' &&
    value.methodology.trim() !== '' &&
    Array.isArray(value.deductions) &&
    value.deductions.every(isHttpScoreDeduction)
  )
}

function isHttpSuccessResponse(value) {
  return (
    value?.status === 'success' &&
    HTTP_SUCCESS_STRING_FIELDS.every(
      (field) => typeof value[field] === 'string',
    ) &&
    Number.isInteger(value.http_status_code) &&
    Number.isInteger(value.redirect_count) &&
    isNormalizedHeaders(value.headers) &&
    Array.isArray(value.findings) &&
    value.findings.every(isFinding) &&
    isHttpSecurityScore(value.score)
  )
}

function isFailureResponse(value) {
  return (
    value?.status === 'failure' &&
    typeof value.stage === 'string' &&
    typeof value.code === 'string'
  )
}

async function requestScanResult(endpoint, hostname, isSuccessResponse) {
  const controller = new AbortController()
  const timeoutId = setTimeout(
    () => controller.abort(),
    SCAN_REQUEST_TIMEOUT_MS,
  )

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ hostname }),
      signal: controller.signal,
    })

    let responseBody
    try {
      responseBody = await response.json()
    } catch (error) {
      if (error?.name === 'AbortError') {
        throw error
      }
      return {
        result: null,
        error: 'Sentinel returned an unexpected response. Please try again.',
      }
    }

    if (!response.ok) {
      if (isFailureResponse(responseBody)) {
        return { result: responseBody, error: '' }
      }
      return {
        result: null,
        error: 'The scan request failed unexpectedly. Please try again.',
      }
    }

    if (isSuccessResponse(responseBody) || isFailureResponse(responseBody)) {
      return { result: responseBody, error: '' }
    }

    return {
      result: null,
      error: 'Sentinel returned an unexpected response. Please try again.',
    }
  } catch (error) {
    if (error?.name === 'AbortError') {
      return {
        result: null,
        error: 'The scan timed out. Please try again.',
      }
    }
    return {
      result: null,
      error:
        'Unable to reach the Sentinel API. Check that the backend is running.',
    }
  } finally {
    clearTimeout(timeoutId)
  }
}

export async function scanHostname(hostname) {
  const [tls, http] = await Promise.all([
    requestScanResult(
      TLS_LEAF_CERTIFICATE_ENDPOINT,
      hostname,
      isTlsSuccessResponse,
    ),
    requestScanResult(
      HTTP_SECURITY_HEADERS_ENDPOINT,
      hostname,
      isHttpSuccessResponse,
    ),
  ])

  return { tls, http }
}
