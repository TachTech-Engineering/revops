import { useMemo, useState } from 'react'
import { Search, Database, AlertTriangle, ChevronLeft, ChevronRight } from 'lucide-react'
import { useSearchLogsQuery, useGetLogStoreStatsQuery } from '../api/pantherApi'
import type { LogEntry } from '../api/pantherApi'

const PAGE_SIZE = 100

const TIME_RANGES = [
  { label: 'Last hour', hours: 1 },
  { label: 'Last 24 hours', hours: 24 },
  { label: 'Last 7 days', hours: 24 * 7 },
  { label: 'Last 14 days', hours: 24 * 14 },
]

const SOURCE_TYPES = [
  { value: '', label: 'All sources' },
  { value: 'unifi_syslog', label: 'UniFi syslog' },
  { value: 'falco', label: 'Falco' },
]

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit++
  }
  return `${value.toFixed(1)} ${units[unit]}`
}

function severityClass(severity: string | null): string {
  const s = (severity ?? '').toLowerCase()
  if (['0', '1', '2', '3', 'emergency', 'alert', 'critical', 'error'].includes(s)) {
    return 'text-red-500'
  }
  if (['4', 'warning'].includes(s)) return 'text-amber-500'
  return 'text-muted-foreground'
}

function LogRow({ entry }: { entry: LogEntry }) {
  const [expanded, setExpanded] = useState(false)
  const hasAttributes = entry.attributes && Object.keys(entry.attributes).length > 0

  return (
    <>
      <tr
        className="border-b align-top hover:bg-muted/40 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <td className="whitespace-nowrap px-3 py-2 text-xs text-muted-foreground">
          {new Date(entry.event_time).toLocaleString()}
        </td>
        <td className="whitespace-nowrap px-3 py-2 text-xs">{entry.source_type}</td>
        <td className="whitespace-nowrap px-3 py-2 text-xs">{entry.host ?? '-'}</td>
        <td className={`whitespace-nowrap px-3 py-2 text-xs ${severityClass(entry.severity)}`}>
          {entry.severity ?? '-'}
        </td>
        {/* Rendered as text, never as markup: these are untrusted remote lines. */}
        <td className="px-3 py-2 font-mono text-xs break-all">{entry.message}</td>
      </tr>
      {expanded && hasAttributes && (
        <tr className="border-b bg-muted/20">
          <td colSpan={5} className="px-3 py-2">
            <pre className="overflow-x-auto text-xs">
              {JSON.stringify(entry.attributes, null, 2)}
            </pre>
          </td>
        </tr>
      )}
    </>
  )
}

export default function LogSearchPage() {
  const [queryInput, setQueryInput] = useState('')
  const [submittedQuery, setSubmittedQuery] = useState('')
  const [sourceType, setSourceType] = useState('')
  const [host, setHost] = useState('')
  const [rangeHours, setRangeHours] = useState(24)
  const [offset, setOffset] = useState(0)

  const { data: stats } = useGetLogStoreStatsQuery()

  // Recomputed only when a filter changes, so the window does not slide out
  // from under an open result set on every render.
  const window = useMemo(() => {
    const end = new Date()
    const start = new Date(end.getTime() - rangeHours * 3600 * 1000)
    return { start: start.toISOString(), end: end.toISOString() }
  }, [rangeHours, submittedQuery, sourceType, host])

  const { data, isFetching, error } = useSearchLogsQuery({
    q: submittedQuery || undefined,
    source_type: sourceType || undefined,
    host: host || undefined,
    start: window.start,
    end: window.end,
    limit: PAGE_SIZE,
    offset,
  })

  const runSearch = () => {
    setOffset(0)
    setSubmittedQuery(queryInput.trim())
  }

  const total = data?.total ?? 0
  const showing = data?.results.length ?? 0

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Log Search</h1>
        <p className="text-muted-foreground">
          Raw log lines from the sources this platform ingests directly. Panther-sourced
          logs stay in Snowflake &mdash; search those from IOC Search.
        </p>
      </div>

      <div className="rounded-lg border bg-background p-6">
        <div className="flex flex-col gap-4 md:flex-row">
          <div className="flex-1">
            <label className="mb-2 block text-sm font-medium">Search</label>
            <input
              type="text"
              value={queryInput}
              onChange={(e) => setQueryInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && runSearch()}
              placeholder="Words or a &quot;quoted phrase&quot;; blank returns everything in range"
              className="w-full rounded-md border bg-background px-4 py-2 text-sm"
            />
          </div>
          <div className="w-full md:w-48">
            <label className="mb-2 block text-sm font-medium">Source</label>
            <select
              value={sourceType}
              onChange={(e) => {
                setOffset(0)
                setSourceType(e.target.value)
              }}
              className="w-full rounded-md border bg-background px-4 py-2 text-sm"
            >
              {SOURCE_TYPES.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </select>
          </div>
          <div className="w-full md:w-40">
            <label className="mb-2 block text-sm font-medium">Host</label>
            <input
              type="text"
              value={host}
              onChange={(e) => {
                setOffset(0)
                setHost(e.target.value)
              }}
              placeholder="exact hostname"
              className="w-full rounded-md border bg-background px-4 py-2 text-sm"
            />
          </div>
          <div className="w-full md:w-44">
            <label className="mb-2 block text-sm font-medium">Time range</label>
            <select
              value={rangeHours}
              onChange={(e) => {
                setOffset(0)
                setRangeHours(Number(e.target.value))
              }}
              className="w-full rounded-md border bg-background px-4 py-2 text-sm"
            >
              {TIME_RANGES.map((r) => (
                <option key={r.hours} value={r.hours}>
                  {r.label}
                </option>
              ))}
            </select>
          </div>
          <div className="flex items-end">
            <button
              onClick={runSearch}
              disabled={isFetching}
              className="flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm text-primary-foreground disabled:opacity-50"
            >
              <Search className="h-4 w-4" />
              {isFetching ? 'Searching...' : 'Search'}
            </button>
          </div>
        </div>
      </div>

      {stats && (
        <div className="flex flex-wrap items-center gap-6 rounded-lg border bg-background px-6 py-3 text-sm">
          <span className="flex items-center gap-2 text-muted-foreground">
            <Database className="h-4 w-4" />
            {formatBytes(stats.stored_bytes)} of {formatBytes(stats.max_stored_bytes)} used
          </span>
          <span className="text-muted-foreground">
            {stats.retention_days}-day retention &middot; {stats.partitions} daily partitions
          </span>
          {stats.at_capacity && (
            <span className="flex items-center gap-2 text-red-500">
              <AlertTriangle className="h-4 w-4" />
              At capacity &mdash; new log lines are being dropped
            </span>
          )}
        </div>
      )}

      <div className="rounded-lg border bg-background">
        {error ? (
          <div className="p-6 text-sm text-red-500">
            Search failed. Narrow the time range and try again.
          </div>
        ) : showing === 0 ? (
          <div className="p-6 text-sm text-muted-foreground">
            {isFetching ? 'Searching...' : 'No log lines match these filters.'}
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b text-left text-xs text-muted-foreground">
                    <th className="px-3 py-2 font-medium">Time</th>
                    <th className="px-3 py-2 font-medium">Source</th>
                    <th className="px-3 py-2 font-medium">Host</th>
                    <th className="px-3 py-2 font-medium">Severity</th>
                    <th className="px-3 py-2 font-medium">Message</th>
                  </tr>
                </thead>
                <tbody>
                  {data?.results.map((entry) => (
                    <LogRow key={entry.id} entry={entry} />
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-between border-t px-3 py-2 text-xs text-muted-foreground">
              <span>
                {offset + 1}&ndash;{offset + showing} of {total}
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                  disabled={offset === 0 || isFetching}
                  className="flex items-center gap-1 rounded-md border px-2 py-1 disabled:opacity-40"
                >
                  <ChevronLeft className="h-3 w-3" />
                  Previous
                </button>
                <button
                  onClick={() => setOffset(offset + PAGE_SIZE)}
                  disabled={offset + showing >= total || isFetching}
                  className="flex items-center gap-1 rounded-md border px-2 py-1 disabled:opacity-40"
                >
                  Next
                  <ChevronRight className="h-3 w-3" />
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
