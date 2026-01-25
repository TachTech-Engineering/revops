import { useState } from 'react'
import { BarChart3, TrendingUp, AlertTriangle, Shield, Clock, RefreshCw } from 'lucide-react'
import { useGetAlertAnalyticsQuery } from '../api/pantherApi'
import { getSeverityColor } from '../lib/utils'

export default function AnalyticsDashboardPage() {
  const [days, setDays] = useState(7)
  const { data, isLoading, error, refetch } = useGetAlertAnalyticsQuery({ days })

  const maxDailyCount = data?.byDay
    ? Math.max(...Object.values(data.byDay), 1)
    : 1

  const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const
  const maxSeverityCount = data?.bySeverity
    ? Math.max(...Object.values(data.bySeverity), 1)
    : 1

  const statusColors: Record<string, string> = {
    OPEN: 'bg-red-500',
    TRIAGED: 'bg-yellow-500',
    CLOSED: 'bg-gray-500',
    RESOLVED: 'bg-green-500',
  }

  const totalByStatus = data?.byStatus
    ? Object.values(data.byStatus).reduce((a, b) => a + b, 0) || 1
    : 1

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Analytics</h1>
          <p className="text-muted-foreground">Security metrics and alert trends</p>
        </div>
        <div className="flex items-center gap-4">
          <select
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
            className="rounded-md border bg-background px-3 py-2 text-sm"
          >
            <option value={7}>Last 7 days</option>
            <option value={14}>Last 14 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
          </select>
          <button
            onClick={() => refetch()}
            disabled={isLoading}
            className="flex items-center gap-2 px-3 py-2 rounded-md border hover:bg-accent text-sm"
          >
            <RefreshCw size={14} className={isLoading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-red-400">
          <p className="font-medium">Error loading analytics</p>
          <p className="text-sm">Please check your connection and try again.</p>
        </div>
      )}

      {isLoading ? (
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="rounded-lg border bg-background p-6 animate-pulse">
              <div className="h-4 bg-muted rounded w-24 mb-2" />
              <div className="h-8 bg-muted rounded w-16" />
            </div>
          ))}
        </div>
      ) : data && (
        <>
          {/* Summary Cards */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-lg border bg-background p-6">
              <div className="flex items-center gap-3">
                <div className="rounded-full bg-blue-500/20 p-2">
                  <BarChart3 className="h-5 w-5 text-blue-400" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Total Alerts</p>
                  <p className="text-2xl font-bold">{data.totalAlerts.toLocaleString()}</p>
                </div>
              </div>
            </div>

            <div className="rounded-lg border bg-background p-6">
              <div className="flex items-center gap-3">
                <div className="rounded-full bg-red-500/20 p-2">
                  <AlertTriangle className="h-5 w-5 text-red-400" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Critical/High</p>
                  <p className="text-2xl font-bold">
                    {(data.bySeverity.CRITICAL + data.bySeverity.HIGH).toLocaleString()}
                  </p>
                </div>
              </div>
            </div>

            <div className="rounded-lg border bg-background p-6">
              <div className="flex items-center gap-3">
                <div className="rounded-full bg-yellow-500/20 p-2">
                  <Clock className="h-5 w-5 text-yellow-400" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Open Alerts</p>
                  <p className="text-2xl font-bold">{data.byStatus.OPEN.toLocaleString()}</p>
                </div>
              </div>
            </div>

            <div className="rounded-lg border bg-background p-6">
              <div className="flex items-center gap-3">
                <div className="rounded-full bg-green-500/20 p-2">
                  <Shield className="h-5 w-5 text-green-400" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Resolved</p>
                  <p className="text-2xl font-bold">{data.byStatus.RESOLVED.toLocaleString()}</p>
                </div>
              </div>
            </div>
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            {/* Alerts by Day */}
            <div className="rounded-lg border bg-background p-6">
              <h3 className="font-semibold mb-4 flex items-center gap-2">
                <TrendingUp size={18} />
                Alerts Over Time
              </h3>
              <div className="h-48 flex items-end gap-1">
                {Object.entries(data.byDay)
                  .sort(([a], [b]) => a.localeCompare(b))
                  .slice(-14)
                  .map(([date, count]) => {
                    const height = (count / maxDailyCount) * 100
                    return (
                      <div key={date} className="flex-1 flex flex-col items-center gap-1">
                        <div
                          className="w-full bg-primary/80 rounded-t hover:bg-primary transition-colors"
                          style={{ height: `${Math.max(height, 2)}%` }}
                          title={`${date}: ${count} alerts`}
                        />
                        <span className="text-[10px] text-muted-foreground -rotate-45 origin-top-left whitespace-nowrap">
                          {date.slice(5)}
                        </span>
                      </div>
                    )
                  })}
              </div>
              {Object.keys(data.byDay).length === 0 && (
                <div className="h-48 flex items-center justify-center text-muted-foreground">
                  No data for this period
                </div>
              )}
            </div>

            {/* Alerts by Severity */}
            <div className="rounded-lg border bg-background p-6">
              <h3 className="font-semibold mb-4 flex items-center gap-2">
                <AlertTriangle size={18} />
                Alerts by Severity
              </h3>
              <div className="space-y-3">
                {severityOrder.map((severity) => {
                  const count = data.bySeverity[severity]
                  const percentage = (count / maxSeverityCount) * 100
                  return (
                    <div key={severity} className="flex items-center gap-3">
                      <span className={`w-20 px-2 py-0.5 rounded text-xs font-medium text-center ${getSeverityColor(severity)}`}>
                        {severity}
                      </span>
                      <div className="flex-1 h-6 bg-muted rounded overflow-hidden">
                        <div
                          className={`h-full transition-all ${
                            severity === 'CRITICAL' ? 'bg-red-500' :
                            severity === 'HIGH' ? 'bg-orange-500' :
                            severity === 'MEDIUM' ? 'bg-yellow-500' :
                            severity === 'LOW' ? 'bg-green-500' :
                            'bg-blue-500'
                          }`}
                          style={{ width: `${percentage}%` }}
                        />
                      </div>
                      <span className="w-12 text-right text-sm font-medium">{count}</span>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Alerts by Status */}
            <div className="rounded-lg border bg-background p-6">
              <h3 className="font-semibold mb-4 flex items-center gap-2">
                <Clock size={18} />
                Alerts by Status
              </h3>
              <div className="flex items-center gap-4 mb-4">
                <div className="flex-1 h-8 rounded overflow-hidden flex">
                  {Object.entries(data.byStatus).map(([status, count]) => {
                    const percentage = (count / totalByStatus) * 100
                    if (percentage === 0) return null
                    return (
                      <div
                        key={status}
                        className={`${statusColors[status]} transition-all`}
                        style={{ width: `${percentage}%` }}
                        title={`${status}: ${count}`}
                      />
                    )
                  })}
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2">
                {Object.entries(data.byStatus).map(([status, count]) => (
                  <div key={status} className="flex items-center gap-2">
                    <div className={`w-3 h-3 rounded ${statusColors[status]}`} />
                    <span className="text-sm">{status}</span>
                    <span className="text-sm font-medium ml-auto">{count}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Top Rules */}
            <div className="rounded-lg border bg-background p-6">
              <h3 className="font-semibold mb-4 flex items-center gap-2">
                <Shield size={18} />
                Top Triggered Rules
              </h3>
              {data.topRules.length === 0 ? (
                <div className="text-center text-muted-foreground py-8">
                  No rules triggered in this period
                </div>
              ) : (
                <div className="space-y-2">
                  {data.topRules.map((rule, i) => (
                    <div key={i} className="flex items-center gap-3">
                      <span className="w-6 h-6 rounded-full bg-muted flex items-center justify-center text-xs font-medium">
                        {i + 1}
                      </span>
                      <span className="flex-1 text-sm truncate" title={rule.name}>
                        {rule.name}
                      </span>
                      <span className="text-sm font-medium">{rule.count}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
