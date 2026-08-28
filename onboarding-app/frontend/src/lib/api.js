// Thin fetch wrapper for the onboarding API. Vite's dev server proxies
// /api/* to the FastAPI backend (see vite.config.js), so these paths work
// unchanged in dev and in any deployment that keeps the same reverse-proxy
// convention.

class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

async function request(path, options) {
  const response = await fetch(path, options)
  if (!response.ok) {
    let detail = response.statusText
    try {
      const body = await response.json()
      detail = body.detail || detail
    } catch {
      // response body wasn't JSON -- fall back to statusText
    }
    throw new ApiError(detail, response.status)
  }
  return response.json()
}

export function getSiemCatalog() {
  return request('/api/siem-catalog')
}

export function getOnboardingState(token) {
  return request(`/api/onboarding/${encodeURIComponent(token)}`)
}

export function submitOnboarding(token, submission) {
  return request(`/api/onboarding/${encodeURIComponent(token)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(submission),
  })
}

export { ApiError }
