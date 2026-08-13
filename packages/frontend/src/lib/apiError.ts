/**
 * Turns an unknown error (RTK Query `FetchBaseQueryError`, `SerializedError`,
 * or a plain throw) into a message that is safe to show a user.
 *
 * Keep this the single place that knows the FastAPI error envelope
 * (`{ detail: string }` or the 422 `{ detail: [{ msg }] }` list).
 */
export function getApiErrorMessage(
  err: unknown,
  fallback = 'Something went wrong. Please try again.'
): string {
  if (err == null) return fallback
  if (typeof err === 'string') return err

  const e = err as {
    status?: number | string
    data?: unknown
    error?: string
    message?: string
  }

  const data = e.data
  if (typeof data === 'string' && data.trim()) return data.trim()

  if (data && typeof data === 'object') {
    const detail = (data as { detail?: unknown }).detail
    if (typeof detail === 'string' && detail.trim()) return detail.trim()
    if (Array.isArray(detail)) {
      const messages = detail
        .map((d) =>
          d && typeof d === 'object' && 'msg' in d
            ? String((d as { msg?: unknown }).msg ?? '')
            : String(d ?? '')
        )
        .filter(Boolean)
      if (messages.length) return messages.join('; ')
    }
    const message = (data as { message?: unknown }).message
    if (typeof message === 'string' && message.trim()) return message.trim()
  }

  if (typeof e.status === 'number') {
    switch (e.status) {
      case 401:
        return 'Your session has expired. Please sign in again.'
      case 403:
        return "You don't have permission to do that."
      case 404:
        return 'That resource no longer exists.'
      default:
        return `Request failed (HTTP ${e.status}).`
    }
  }

  if (e.status === 'FETCH_ERROR') {
    return 'Unable to reach the server. Check your connection and try again.'
  }
  if (e.status === 'PARSING_ERROR' || e.status === 'CUSTOM_ERROR') {
    return 'The server returned an unexpected response.'
  }
  if (e.status === 'TIMEOUT_ERROR') {
    return 'The server took too long to respond. Please try again.'
  }

  if (typeof e.error === 'string' && e.error.trim()) return e.error.trim()
  if (typeof e.message === 'string' && e.message.trim()) return e.message.trim()

  return fallback
}
