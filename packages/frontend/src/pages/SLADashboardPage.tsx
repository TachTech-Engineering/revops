import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Clock, AlertTriangle, CheckCircle, XCircle, Settings, TrendingUp } from 'lucide-react'
import {
  useGetSLADashboardQuery,
  useListSLAMetricsQuery,
  type SLASummary,
  type SLAMetricResponse,
  type SLAStatus,
} from '../api/pantherApi'
import { cn } from '../lib/utils'

export default function SLADashboardPage() {
  const [days, setDays] = useState(7)
  const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null)

  const { data: dashboard, isLoading: dashboardLoading } = useGetSLADashboardQuery({ days })
  const { data: metrics } = useListSLAMetricsQuery({
    days,
    severity: selectedSeverity || undefined,
    page_size: 20,
  })

  const getStatusColor = (status: SLAStatus) => {
    switch (status) {
      case 'on_track':
        return 'text-green-600 bg-green-100 dark:bg-green-900/30'
      case 'at_risk':
        return 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900/30'
      case 'breached':
        return 'text-red-600 bg-red-100 dark:bg-red-900/30'
      default:
        return 'text-gray-600 bg-gray-100'
    }
  }

  const getStatusIcon = (status: SLAStatus) => {
    switch (status) {
      case 'on_track':
        return <CheckCircle className="w-4 h-4" />
      case 'at_risk':
        return <AlertTriangle className="w-4 h-4" />
      case 'breached':
        return <XCircle className="w-4 h-4" />
      default:
        return null
    }
  }

  const formatMinutes = (minutes: number | null) => {
    if (minutes === null) return '-'
    if (minutes < 60) return `${minutes}m`
    const hours = Math.floor(minutes / 60)
    const mins = minutes % 60
    if (hours < 24) return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`
    const d = Math.floor(hours / 24)
    const h = hours % 24
    return h > 0 ? `${d}d ${h}h` : `${d}d`
  }

  const renderSummaryCard = (summary: SLASummary, title: string) => (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
      <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-3">{title}</h3>
      <div className="grid grid-cols-4 gap-4">
        <div>
          <div className="text-2xl font-bold text-gray-900 dark:text-white">
            {summary.total_alerts}
          </div>
          <div className="text-xs text-gray-500">Total</div>
        </div>
        <div>
          <div className="text-2xl font-bold text-green-600">{summary.on_track}</div>
          <div className="text-xs text-gray-500">On Track</div>
        </div>
        <div>
          <div className="text-2xl font-bold text-yellow-600">{summary.at_risk}</div>
          <div className="text-xs text-gray-500">At Risk</div>
        </div>
        <div>
          <div className="text-2xl font-bold text-red-600">{summary.breached}</div>
          <div className="text-xs text-gray-500">Breached</div>
        </div>
      </div>
      <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span className="text-gray-500">Avg Ack Time:</span>{' '}
            <span className="font-medium text-gray-900 dark:text-white">
              {formatMinutes(summary.avg_ack_time_minutes)}
            </span>
          </div>
          <div>
            <span className="text-gray-500">Avg Resolve:</span>{' '}
            <span className="font-medium text-gray-900 dark:text-white">
              {formatMinutes(summary.avg_resolve_time_minutes)}
            </span>
          </div>
        </div>
      </div>
    </div>
  )

  if (dashboardLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Clock className="w-8 h-8 text-blue-500" />
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">SLA Dashboard</h1>
            <p className="text-gray-600 dark:text-gray-400">
              Monitor alert response and resolution times
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <select
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
            className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
          >
            <option value={7}>Last 7 days</option>
            <option value={14}>Last 14 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
          </select>
          <Link
            to="/sla/policies"
            className="flex items-center gap-2 px-4 py-2 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-200 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
          >
            <Settings className="w-4 h-4" />
            Manage Policies
          </Link>
        </div>
      </div>

      {/* Compliance Rates */}
      {dashboard && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                Acknowledgment Compliance
              </h3>
              <TrendingUp className="w-5 h-5 text-green-500" />
            </div>
            <div className="flex items-end gap-4">
              <div className="text-4xl font-bold text-gray-900 dark:text-white">
                {dashboard.summary.ack_compliance_rate}%
              </div>
              <div className="text-sm text-gray-500 pb-1">of alerts acknowledged within SLA</div>
            </div>
            <div className="mt-4">
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3">
                <div
                  className={cn(
                    'h-3 rounded-full transition-all',
                    dashboard.summary.ack_compliance_rate >= 90
                      ? 'bg-green-500'
                      : dashboard.summary.ack_compliance_rate >= 75
                        ? 'bg-yellow-500'
                        : 'bg-red-500'
                  )}
                  style={{ width: `${dashboard.summary.ack_compliance_rate}%` }}
                />
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                Resolution Compliance
              </h3>
              <TrendingUp className="w-5 h-5 text-blue-500" />
            </div>
            <div className="flex items-end gap-4">
              <div className="text-4xl font-bold text-gray-900 dark:text-white">
                {dashboard.summary.resolve_compliance_rate}%
              </div>
              <div className="text-sm text-gray-500 pb-1">of alerts resolved within SLA</div>
            </div>
            <div className="mt-4">
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3">
                <div
                  className={cn(
                    'h-3 rounded-full transition-all',
                    dashboard.summary.resolve_compliance_rate >= 90
                      ? 'bg-green-500'
                      : dashboard.summary.resolve_compliance_rate >= 75
                        ? 'bg-yellow-500'
                        : 'bg-red-500'
                  )}
                  style={{ width: `${dashboard.summary.resolve_compliance_rate}%` }}
                />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Overall Summary */}
      {dashboard && renderSummaryCard(dashboard.summary, 'Overall SLA Performance')}

      {/* By Severity */}
      {dashboard && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
          <div className="p-4 border-b border-gray-200 dark:border-gray-700">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
              Performance by Severity
            </h2>
          </div>
          <div className="p-4">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((severity) => {
                const summary = dashboard.by_severity[severity]
                if (!summary) return null

                const severityColors: Record<string, string> = {
                  CRITICAL: 'border-l-red-500',
                  HIGH: 'border-l-orange-500',
                  MEDIUM: 'border-l-yellow-500',
                  LOW: 'border-l-blue-500',
                }

                return (
                  <button
                    key={severity}
                    onClick={() =>
                      setSelectedSeverity(selectedSeverity === severity ? null : severity)
                    }
                    className={cn(
                      'text-left p-4 rounded-lg border-l-4 bg-gray-50 dark:bg-gray-700/50 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors',
                      severityColors[severity],
                      selectedSeverity === severity && 'ring-2 ring-blue-500'
                    )}
                  >
                    <div className="font-medium text-gray-900 dark:text-white mb-2">
                      {severity}
                    </div>
                    <div className="space-y-1 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-500">Total</span>
                        <span className="font-medium">{summary.total_alerts}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-green-600">On Track</span>
                        <span className="font-medium">{summary.on_track}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-red-600">Breached</span>
                        <span className="font-medium">{summary.breached}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-500">Ack Compliance</span>
                        <span className="font-medium">{summary.ack_compliance_rate}%</span>
                      </div>
                    </div>
                  </button>
                )
              })}
            </div>
          </div>
        </div>
      )}

      {/* Recent Breaches */}
      {dashboard && dashboard.recent_breaches.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
          <div className="p-4 border-b border-gray-200 dark:border-gray-700">
            <h2 className="text-lg font-semibold text-red-600">Recent SLA Breaches</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-900/50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Alert ID
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Severity
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Ack Status
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Resolve Status
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Created
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {dashboard.recent_breaches.map((metric: SLAMetricResponse) => (
                  <tr key={metric.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                    <td className="px-4 py-3">
                      <Link
                        to={`/alerts/${metric.alert_id}`}
                        className="text-blue-600 hover:text-blue-700 font-mono text-sm"
                      >
                        {metric.alert_id.slice(0, 12)}...
                      </Link>
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={metric.severity} />
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={cn(
                          'inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium',
                          getStatusColor(metric.ack_status)
                        )}
                      >
                        {getStatusIcon(metric.ack_status)}
                        {metric.ack_status.replace('_', ' ')}
                        {metric.ack_time_minutes !== null && (
                          <span className="ml-1">({formatMinutes(metric.ack_time_minutes)})</span>
                        )}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={cn(
                          'inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium',
                          getStatusColor(metric.resolve_status)
                        )}
                      >
                        {getStatusIcon(metric.resolve_status)}
                        {metric.resolve_status.replace('_', ' ')}
                        {metric.resolve_time_minutes !== null && (
                          <span className="ml-1">
                            ({formatMinutes(metric.resolve_time_minutes)})
                          </span>
                        )}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-500">
                      {new Date(metric.alert_created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Metrics Table */}
      {metrics && metrics.items.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
          <div className="p-4 border-b border-gray-200 dark:border-gray-700">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
              Recent SLA Metrics
              {selectedSeverity && (
                <span className="ml-2 text-sm font-normal text-gray-500">
                  (filtered by {selectedSeverity})
                </span>
              )}
            </h2>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-900/50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Alert
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Severity
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Ack Target
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Ack Actual
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Resolve Target
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Resolve Actual
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Status
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {metrics.items.map((metric: SLAMetricResponse) => (
                  <tr key={metric.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                    <td className="px-4 py-3">
                      <Link
                        to={`/alerts/${metric.alert_id}`}
                        className="text-blue-600 hover:text-blue-700 font-mono text-sm"
                      >
                        {metric.alert_id.slice(0, 12)}...
                      </Link>
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={metric.severity} />
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">
                      {formatMinutes(metric.ack_target_minutes)}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={cn(
                          'text-sm font-medium',
                          metric.ack_time_minutes !== null &&
                            metric.ack_time_minutes > metric.ack_target_minutes
                            ? 'text-red-600'
                            : 'text-green-600'
                        )}
                      >
                        {formatMinutes(metric.ack_time_minutes)}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">
                      {formatMinutes(metric.resolve_target_minutes)}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={cn(
                          'text-sm font-medium',
                          metric.resolve_time_minutes !== null &&
                            metric.resolve_time_minutes > metric.resolve_target_minutes
                            ? 'text-red-600'
                            : 'text-green-600'
                        )}
                      >
                        {formatMinutes(metric.resolve_time_minutes)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-1">
                        <span
                          className={cn(
                            'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium',
                            getStatusColor(metric.ack_status)
                          )}
                        >
                          A: {metric.ack_status.replace('_', ' ')}
                        </span>
                        <span
                          className={cn(
                            'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium',
                            getStatusColor(metric.resolve_status)
                          )}
                        >
                          R: {metric.resolve_status.replace('_', ' ')}
                        </span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    CRITICAL: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
    HIGH: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
    MEDIUM: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
    LOW: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
    INFO: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300',
  }

  return (
    <span
      className={cn(
        'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium',
        colors[severity] || colors.INFO
      )}
    >
      {severity}
    </span>
  )
}
