import { Fragment, useState } from 'react'
import type { FormEvent } from 'react'
import { AlertTriangle, Archive, Clock, Database, Search } from 'lucide-react'
import { useGetLogStatsQuery, useSearchLogsQuery } from '../api/pantherApi'
import { cn } from '../lib/utils'
import { parseUTCDate } from '../lib/dateUtils'
import { SeverityBadge, SourceTypeBadge } from '../components/cnapp/badges'

const PAGE_SIZE = 100

// The backend defaults to a 24h window and caps windows at 90 days, so all
// presets stay comfortably inside that.
const TIME_PRESETS: { value: string; label: string; hours: number }[] = [
  { value: '1h', label: 'Last 1 hour', hours: 1 },
  { value: '6h', label: 'Last 6 hours', hours: 6 },
  { value: '24h', label: 'Last 24 hours', hours: 24 },
  { value: '7d', label: 'Last 7 days', hours: 24 * 7 },
  { value: '30d', label: 'Last 30 days', hours: 24 * 30 },
]

// Source types RevOps ingests directly (Panther-sourced logs live in
// Snowflake and are searched via IOC Search instead).
const SOURCE_TYPES: { value: string; label: string }[] = [
  { value: '', label: 'All Sources' },
  { value: 'unifi_syslog', label: 'UniFi Syslog' },
  { value: 'falco', label: 'Falco' },
]

interface AppliedFilters {
  q: string
  sourceType: string
  host: string
  start: string
  end: string
}

function presetHours(preset: string): number {
  return TIME_PRESETS.find((p) => p.value === preset)?.hours ?? 24
}

// end = now, start = now - preset, both as ISO strings (computed client-side).
function rangeForPreset(preset: string): { start: string; end: string } {
  const end = new Date()
  const start = new Date(end.getTime() - presetHours(preset) * 60 * 60 * 1000)
  return { start: start.toISOString(), end: end.toISOString() }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB', 'PB']
  let value = bytes
  let unit = -1
  do {
    value /= 1024
    unit += 1
  } while (value >= 1024 && unit < units.length - 1)
  return `${value.toFixed(1)} ${units[unit]}`
}

function formatEventTime(dateStr: string): string {
  return parseUTCDate(dateStr).toLocaleString()
}

export default function RawLogsPage() {
  // Draft inputs (text fields apply on Enter / form submit).
  const [queryInput, setQueryInput] = useState('')
  const [hostInput, setHostInput] = useState('')
  const [sourceType, setSourceType] = useState('')
  const [preset, setPreset] = useState('24h')

  // Committed filters actually sent to the API.
  const [applied, setApplied] = useState<AppliedFilters>(() => ({
    q: '',
    sourceType: '',
    host: '',
    ...rangeForPreset('24h'),
  }))
  const [offset, setOffset] = useState(0)
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const { data: stats } = useGetLogStatsQuery()
  const { data, isLoading, isFetching, error } = useSearchLogsQuery({
    q: applied.q || undefined,
    sourceType: applied.sourceType || undefined,
    host: applied.host || undefined,
    start: applied.start,
    end: applied.end,
    limit: PAGE_SIZE,
    offset,
  })

  // Recompute the window from "now" on every search so Enter re-runs against
  // fresh data instead of the range captured at mount.
  const runSearch = (nextSourceType: string = sourceType, nextPreset: string = preset) => {
    setApplied({
      q: queryInput.trim(),
      sourceType: nextSourceType,
      host: hostInput.trim(),
      ...rangeForPreset(nextPreset),
    })
    setOffset(0)
    setExpandedId(null)
  }

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    runSearch()
  }

  const storagePct = stats && stats.max_stored_bytes > 0
    ? Math.min(100, (stats.stored_bytes / stats.max_stored_bytes) * 100)
    : 0

  const total = data?.total ?? 0
  const page = Math.floor(offset / PAGE_SIZE) + 1

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Raw Logs</h1>
          <p className="text-muted-foreground mt-1">
            Full-text search over directly ingested logs (UniFi syslog, Falco)
          </p>
        </div>
      </div>

      {/* Capacity warning */}
      {stats?.at_capacity && (
        <div className="mb-6 flex items-center gap-2 bg-destructive/10 border border-destructive/20 rounded-lg p-4 text-destructive">
          <AlertTriangle size={16} className="shrink-0" />
          <span className="text-sm font-medium">
            Log store at capacity — new lines may be dropped.
          </span>
        </div>
      )}

      {/* Stats strip */}
      {stats && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
          <div className="bg-card border border-border rounded-lg p-4">
            <div className="flex items-center gap-2 text-muted-foreground text-sm">
              <Database size={16} />
              Storage Used
            </div>
            <p className="text-2xl font-bold text-foreground mt-1">
              {formatBytes(stats.stored_bytes)}{' '}
              <span className="text-sm font-normal text-muted-foreground">
                of {formatBytes(stats.max_stored_bytes)}
              </span>
            </p>
            <div className="mt-2 h-1.5 w-full rounded-full bg-muted overflow-hidden">
              <div
                className={cn(
                  'h-full rounded-full transition-all',
                  storagePct >= 90 ? 'bg-red-500' : 'bg-primary'
                )}
                style={{ width: `${storagePct}%` }}
              />
            </div>
          </div>
          <div className="bg-card border border-border rounded-lg p-4">
            <div className="flex items-center gap-2 text-muted-foreground text-sm">
              <Clock size={16} />
              Retention
            </div>
            <p className="text-2xl font-bold text-foreground mt-1">
              {stats.retention_days}{' '}
              <span className="text-sm font-normal text-muted-foreground">days</span>
            </p>
          </div>
          <div className="bg-card border border-border rounded-lg p-4">
            <div className="flex items-center gap-2 text-muted-foreground text-sm">
              <Archive size={16} />
              Partitions
            </div>
            <p className="text-2xl font-bold text-foreground mt-1">{stats.partitions}</p>
          </div>
        </div>
      )}

      {/* Filters */}
      <form onSubmit={handleSubmit} className="flex flex-wrap gap-4 mb-6 items-center">
        <div className="relative">
          <Search
            size={16}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground"
          />
          <input
            type="text"
            value={queryInput}
            onChange={(e) => setQueryInput(e.target.value)}
            placeholder="Search log messages... (Enter)"
            className="pl-9 pr-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary w-72"
          />
        </div>

        <select
          value={sourceType}
          onChange={(e) => {
            setSourceType(e.target.value)
            runSearch(e.target.value)
          }}
          className="px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
        >
          {SOURCE_TYPES.map(({ value, label }) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>

        <input
          type="text"
          value={hostInput}
          onChange={(e) => setHostInput(e.target.value)}
          placeholder="Host..."
          className="px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary w-48"
        />

        <select
          value={preset}
          onChange={(e) => {
            setPreset(e.target.value)
            runSearch(sourceType, e.target.value)
          }}
          className="px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
        >
          {TIME_PRESETS.map(({ value, label }) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>

        {/* Hidden submit keeps Enter-to-search working in both text inputs */}
        <button type="submit" className="sr-only">
          Search
        </button>
      </form>

      {/* Results */}
      {error ? (
        <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4 text-destructive">
          Failed to search logs
        </div>
      ) : isLoading ? (
        <div className="flex justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      ) : (
        <>
          <div
            className={cn(
              'bg-card border border-border rounded-lg shadow-sm overflow-hidden',
              isFetching && 'opacity-60'
            )}
          >
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-border">
                <thead className="bg-muted/50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Event Time
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Source
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Severity
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Host
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Source IP
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      Message
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {data?.results.map((entry) => (
                    <Fragment key={entry.id}>
                      <tr
                        onClick={() => setExpandedId(expandedId === entry.id ? null : entry.id)}
                        className="hover:bg-muted/30 transition-colors cursor-pointer"
                      >
                        <td className="px-6 py-4 text-sm text-foreground font-mono whitespace-nowrap">
                          {formatEventTime(entry.event_time)}
                        </td>
                        <td className="px-6 py-4">
                          <SourceTypeBadge sourceType={entry.source_type} />
                        </td>
                        <td className="px-6 py-4">
                          {entry.severity ? (
                            <SeverityBadge severity={entry.severity} />
                          ) : (
                            <span className="text-sm text-muted-foreground">-</span>
                          )}
                        </td>
                        <td className="px-6 py-4 text-sm text-foreground whitespace-nowrap">
                          {entry.host || '-'}
                        </td>
                        <td className="px-6 py-4 text-sm text-muted-foreground font-mono whitespace-nowrap">
                          {entry.source_ip || '-'}
                        </td>
                        <td className="px-6 py-4 max-w-xl">
                          <p className="text-sm text-foreground font-mono truncate">
                            {entry.message}
                          </p>
                        </td>
                      </tr>
                      {expandedId === entry.id && (
                        <tr className="bg-muted/20">
                          <td colSpan={6} className="px-6 py-4">
                            <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">
                              Message
                            </div>
                            <p className="text-sm text-foreground font-mono whitespace-pre-wrap break-all">
                              {entry.message}
                            </p>
                            <div className="mt-3 text-xs text-muted-foreground">
                              Received {formatEventTime(entry.received_at)} · Connector{' '}
                              <span className="font-mono">{entry.connector_id}</span>
                            </div>
                            {entry.attributes && Object.keys(entry.attributes).length > 0 && (
                              <>
                                <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mt-4 mb-1">
                                  Attributes
                                </div>
                                <pre className="text-xs text-foreground font-mono bg-background border border-border rounded-lg p-3 overflow-x-auto">
                                  {JSON.stringify(entry.attributes, null, 2)}
                                </pre>
                              </>
                            )}
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  ))}
                  {data?.results.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-6 py-12 text-center text-muted-foreground">
                        No log lines match the current filters
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Footer: total + pagination */}
          {data && (
            <div className="mt-4 flex justify-between items-center">
              <p className="text-sm text-muted-foreground">
                {total === 0
                  ? '0 log lines'
                  : `Showing ${offset + 1} to ${Math.min(offset + PAGE_SIZE, total)} of ${total} log lines`}
              </p>
              {total > PAGE_SIZE && (
                <div className="flex items-center gap-2">
                  <span className="text-sm text-muted-foreground">
                    Page {page} of {Math.ceil(total / PAGE_SIZE)}
                  </span>
                  <button
                    onClick={() => {
                      setOffset((o) => Math.max(0, o - PAGE_SIZE))
                      setExpandedId(null)
                    }}
                    disabled={offset === 0}
                    className="px-3 py-1 border border-border rounded text-sm text-foreground hover:bg-muted disabled:opacity-50 transition-colors"
                  >
                    Previous
                  </button>
                  <button
                    onClick={() => {
                      setOffset((o) => o + PAGE_SIZE)
                      setExpandedId(null)
                    }}
                    disabled={offset + PAGE_SIZE >= total}
                    className="px-3 py-1 border border-border rounded text-sm text-foreground hover:bg-muted disabled:opacity-50 transition-colors"
                  >
                    Next
                  </button>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  )
}
