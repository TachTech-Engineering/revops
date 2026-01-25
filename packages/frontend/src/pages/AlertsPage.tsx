import { useState } from 'react'
import { Link } from 'react-router-dom'
import { FileJson, FileSpreadsheet, CheckSquare, Square, X } from 'lucide-react'
import { useListAlertsQuery, useUpdateAlertMutation, useBulkUpdateAlertsMutation } from '../api/pantherApi'
import { getSeverityColor, getStatusColor, formatDate } from '../lib/utils'
import type { AlertStatus, Severity } from '../types'

export default function AlertsPage() {
  const [statusFilter, setStatusFilter] = useState<AlertStatus | ''>('')
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('')
  const [selectedAlerts, setSelectedAlerts] = useState<Set<string>>(new Set())
  const [bulkStatus, setBulkStatus] = useState<AlertStatus | ''>('')

  const { data, isLoading, error } = useListAlertsQuery({
    status: statusFilter || undefined,
    severity: severityFilter || undefined,
    pageSize: 50,
  })

  const [updateAlert] = useUpdateAlertMutation()
  const [bulkUpdateAlerts, { isLoading: isBulkUpdating }] = useBulkUpdateAlertsMutation()

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
