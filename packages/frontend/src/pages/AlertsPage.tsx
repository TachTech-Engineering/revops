import { useState } from 'react'
import { Link } from 'react-router-dom'
import { FileJson, FileSpreadsheet, CheckSquare, Square, X, Search, Sparkles, Database, ChevronRight } from 'lucide-react'
import { useListAlertsQuery, useUpdateAlertMutation, useBulkUpdateAlertsMutation, useAskYourDataMutation } from '../api/pantherApi'
import { getSeverityColor, getStatusColor, formatDate } from '../lib/utils'
import type { AlertStatus, Severity } from '../types'

export default function AlertsPage() {
  const [statusFilter, setStatusFilter] = useState<AlertStatus | ''>('')
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('')
  const [selectedAlerts, setSelectedAlerts] = useState<Set<string>>(new Set())
  const [bulkStatus, setBulkStatus] = useState<AlertStatus | ''>('')
  
  // NLQ State
  const [nlqQuery, setNlqQuery] = useState('')
  const [nlqResult, setNlqResult] = useState<{ answer: string; sql: string; results: any[] } | null>(null)
  const [isNlqOpen, setIsNlqOpen] = useState(false)

  const { data, isLoading, error } = useListAlertsQuery({
    status: statusFilter || undefined,
    severity: severityFilter || undefined,
    pageSize: 50,
  })

  const [updateAlert] = useUpdateAlertMutation()
  const [bulkUpdateAlerts, { isLoading: isBulkUpdating }] = useBulkUpdateAlertsMutation()
  const [askYourData, { isLoading: isAsking }] = useAskYourDataMutation()

  const handleNlqSearch = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!nlqQuery.trim()) return
    
    try {
      const result = await askYourData({ query: nlqQuery }).unwrap()
      setNlqResult(result)
      setIsNlqOpen(true)
    } catch (err) {
      console.error('NLQ failed:', err)
    }
  }

  const handleStatusChange = async (alertId: string, newStatus: AlertStatus) => {
    try {
      await updateAlert({ id: alertId, status: newStatus }).unwrap()
    } catch (err) {
      console.error('Failed to update alert:', err)
    }
  }

  const handleSelectAll = () => {
    if (!data?.results) return
    if (selectedAlerts.size === data.results.length) {
      setSelectedAlerts(new Set())
    } else {
      setSelectedAlerts(new Set(data.results.map((a) => a.id)))
    }
  }

  const handleSelectAlert = (alertId: string) => {
    const newSelected = new Set(selectedAlerts)
    if (newSelected.has(alertId)) {
      newSelected.delete(alertId)
    } else {
      newSelected.add(alertId)
    }
    setSelectedAlerts(newSelected)
  }

  const handleBulkUpdate = async () => {
    if (selectedAlerts.size === 0 || !bulkStatus) return
    try {
      const result = await bulkUpdateAlerts({
        alert_ids: Array.from(selectedAlerts),
        status: bulkStatus,
      }).unwrap()
      console.log(`Updated ${result.success.length} alerts, ${result.failed.length} failed`)
      setSelectedAlerts(new Set())
      setBulkStatus('')
    } catch (err) {
      console.error('Bulk update failed:', err)
    }
  }

  const handleExportJSON = () => {
    if (!data?.results) return
    const alertsToExport = selectedAlerts.size > 0
      ? data.results.filter((a) => selectedAlerts.has(a.id))
      : data.results
    const jsonContent = JSON.stringify(alertsToExport, null, 2)
    const blob = new Blob([jsonContent], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `alerts_export_${new Date().toISOString().split('T')[0]}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleExportCSV = () => {
    if (!data?.results || data.results.length === 0) return
    const alertsToExport = selectedAlerts.size > 0
      ? data.results.filter((a) => selectedAlerts.has(a.id))
      : data.results
    const headers = ['id', 'title', 'severity', 'status', 'eventCount', 'createdAt', 'detectionId']
    const csvContent = [
      headers.join(','),
      ...alertsToExport.map(alert =>
        headers.map(h => {
          const val = alert[h as keyof typeof alert]
          const str = String(val ?? '')
          return str.includes(',') || str.includes('"') ? `"${str.replace(/"/g, '""')}"` : str
        }).join(',')
      )
    ].join('\n')

    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `alerts_export_${new Date().toISOString().split('T')[0]}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  const allSelected = data?.results && data.results.length > 0 && selectedAlerts.size === data.results.length

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Alerts</h1>
          <p className="text-muted-foreground">Manage and triage security alerts</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleExportJSON}
            disabled={!data?.results?.length}
            className="flex items-center gap-2 px-3 py-2 rounded-md border hover:bg-accent text-sm disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <FileJson size={16} />
            Export JSON {selectedAlerts.size > 0 && `(${selectedAlerts.size})`}
          </button>
          <button
            onClick={handleExportCSV}
            disabled={!data?.results?.length}
            className="flex items-center gap-2 px-3 py-2 rounded-md border hover:bg-accent text-sm disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <FileSpreadsheet size={16} />
            Export CSV {selectedAlerts.size > 0 && `(${selectedAlerts.size})`}
          </button>
        </div>
      </div>

      {/* AI Ask Your Data Search Bar */}
      <div className="bg-card border rounded-lg p-4 shadow-sm">
        <form onSubmit={handleNlqSearch} className="relative">
          <Sparkles className="absolute left-3 top-1/2 -translate-y-1/2 text-primary" size={18} />
          <input
            type="text"
            value={nlqQuery}
            onChange={(e) => setNlqQuery(e.target.value)}
            placeholder="Ask your data anything... (e.g. 'Show me critical alerts from the last 24 hours')"
            className="w-full bg-background border rounded-md pl-10 pr-24 py-2.5 focus:outline-none focus:ring-2 focus:ring-primary/50"
          />
          <button
            type="submit"
            disabled={isAsking}
            className="absolute right-1.5 top-1/2 -translate-y-1/2 px-4 py-1.5 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
          >
            {isAsking ? 'Thinking...' : 'Search'}
          </button>
        </form>

        {isNlqOpen && nlqResult && (
          <div className="mt-4 border-t pt-4 space-y-4">
            <div className="flex items-start gap-3 bg-primary/5 p-3 rounded-md border border-primary/20">
              <Sparkles className="text-primary mt-0.5 shrink-0" size={16} />
              <div className="text-sm">
                <p className="font-medium text-primary mb-1">AI Answer</p>
                <p className="text-muted-foreground leading-relaxed">{nlqResult.answer}</p>
              </div>
            </div>

            <details className="group">
              <summary className="flex items-center gap-2 text-xs font-medium text-muted-foreground cursor-pointer hover:text-foreground">
                <Database size={12} />
                <span>Generated SQL Query</span>
                <ChevronRight size={12} className="group-open:rotate-90 transition-transform" />
              </summary>
              <pre className="mt-2 p-3 bg-muted rounded-md text-[10px] overflow-x-auto font-mono">
                {nlqResult.sql}
              </pre>
            </details>

            {nlqResult.results && nlqResult.results.length > 0 && (
              <div className="space-y-2">
                <p className="text-xs font-medium text-muted-foreground px-1">Matching Results ({nlqResult.results.length})</p>
                <div className="grid gap-2">
                  {nlqResult.results.slice(0, 5).map((alert: any) => (
                    <div key={alert.id} className="flex items-center justify-between p-2 bg-card border rounded-md hover:bg-muted/50 transition-colors">
                      <div className="flex flex-col gap-0.5">
                        <span className="text-xs font-medium">{alert.title}</span>
                        <span className="text-[10px] text-muted-foreground">{alert.source_system} • {alert.severity}</span>
                      </div>
                      <Link to={`/alerts/${alert.id}`} className="text-primary hover:underline text-[10px] font-medium">View Detail</Link>
                    </div>
                  ))}
                  {nlqResult.results.length > 5 && (
                    <p className="text-[10px] text-center text-muted-foreground italic pt-1">...and {nlqResult.results.length - 5} more results</p>
                  )}
                </div>
              </div>
            )}
            
            <button 
              onClick={() => setIsNlqOpen(false)}
              className="text-xs text-muted-foreground hover:text-foreground"
            >
              Clear Search
            </button>
          </div>
        )}
      </div>

      {/* Filters */}
      <div className="flex gap-4 flex-wrap">
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as AlertStatus | '')}
          className="rounded-md border bg-background px-3 py-2 text-sm"
        >
          <option value="">All Statuses</option>
          <option value="OPEN">Open</option>
          <option value="TRIAGED">Triaged</option>
          <option value="CLOSED">Closed</option>
          <option value="RESOLVED">Resolved</option>
        </select>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as Severity | '')}
          className="rounded-md border bg-background px-3 py-2 text-sm"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="INFO">Info</option>
        </select>
      </div>

      {/* Bulk Actions Bar */}
      {selectedAlerts.size > 0 && (
        <div className="flex items-center gap-4 p-3 bg-primary/10 rounded-lg border border-primary/30">
          <span className="text-sm font-medium">
            {selectedAlerts.size} alert{selectedAlerts.size > 1 ? 's' : ''} selected
          </span>
          <div className="flex items-center gap-2">
            <select
              value={bulkStatus}
              onChange={(e) => setBulkStatus(e.target.value as AlertStatus | '')}
              className="rounded-md border bg-background px-3 py-1.5 text-sm"
            >
              <option value="">Change status to...</option>
              <option value="OPEN">Open</option>
              <option value="TRIAGED">Triaged</option>
              <option value="CLOSED">Closed</option>
              <option value="RESOLVED">Resolved</option>
            </select>
            <button
              onClick={handleBulkUpdate}
              disabled={!bulkStatus || isBulkUpdating}
              className="px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
            >
              {isBulkUpdating ? 'Updating...' : 'Apply'}
            </button>
          </div>
          <button
            onClick={() => setSelectedAlerts(new Set())}
            className="ml-auto p-1 hover:bg-accent rounded"
            title="Clear selection"
          >
            <X size={16} />
          </button>
        </div>
      )}

      {/* Alert Table */}
      <div className="rounded-lg border bg-background">
        {isLoading ? (
          <div className="p-6 text-center text-muted-foreground">Loading alerts...</div>
        ) : error ? (
          <div className="p-6 text-center text-red-500">Error loading alerts</div>
        ) : data?.results.length === 0 ? (
          <div className="p-6 text-center text-muted-foreground">No alerts found</div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="px-4 py-3 text-left">
                  <button onClick={handleSelectAll} className="p-1 hover:bg-accent rounded">
                    {allSelected ? (
                      <CheckSquare size={18} className="text-primary" />
                    ) : (
                      <Square size={18} />
                    )}
                  </button>
                </th>
                <th className="px-4 py-3 text-left text-sm font-medium">Title</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Severity</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Status</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Events</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Created</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {data?.results.map((alert) => (
                <tr
                  key={alert.id}
                  className={`hover:bg-muted/50 ${selectedAlerts.has(alert.id) ? 'bg-primary/5' : ''}`}
                >
                  <td className="px-4 py-3">
                    <button
                      onClick={() => handleSelectAlert(alert.id)}
                      className="p-1 hover:bg-accent rounded"
                    >
                      {selectedAlerts.has(alert.id) ? (
                        <CheckSquare size={18} className="text-primary" />
                      ) : (
                        <Square size={18} />
                      )}
                    </button>
                  </td>
                  <td className="px-4 py-3">
                    <Link
                      to={`/alerts/${alert.id}`}
                      className="font-medium hover:text-primary hover:underline"
                    >
                      {alert.title}
                    </Link>
                    <p className="text-sm text-muted-foreground">{alert.detectionId}</p>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(alert.severity)}`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(alert.status)}`}>
                      {alert.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm">{alert.eventCount}</td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    {formatDate(alert.createdAt)}
                  </td>
                  <td className="px-4 py-3">
                    <select
                      value={alert.status}
                      onChange={(e) => handleStatusChange(alert.id, e.target.value as AlertStatus)}
                      className="rounded border bg-background px-2 py-1 text-sm"
                    >
                      <option value="OPEN">Open</option>
                      <option value="TRIAGED">Triaged</option>
                      <option value="CLOSED">Closed</option>
                      <option value="RESOLVED">Resolved</option>
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
