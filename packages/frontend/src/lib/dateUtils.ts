import { formatDistanceToNow as fnsFormatDistanceToNow } from 'date-fns'

/**
 * Parse timestamps as UTC.
 * Backend returns naive timestamps without timezone info, so we need to
 * treat them as UTC to avoid timezone issues in the browser.
 */
export const parseUTCDate = (dateStr: string): Date => {
  // If the timestamp doesn't have timezone info, treat it as UTC
  if (!dateStr.endsWith('Z') && !dateStr.includes('+') && !/T.*-/.test(dateStr)) {
    return new Date(dateStr + 'Z')
  }
  return new Date(dateStr)
}

/**
 * Format a timestamp as a relative time string (e.g., "5 minutes ago").
 * Automatically handles UTC parsing for backend timestamps.
 */
export const formatRelativeTime = (
  dateStr: string,
  options: { addSuffix?: boolean } = { addSuffix: true }
): string => {
  return fnsFormatDistanceToNow(parseUTCDate(dateStr), options)
}
