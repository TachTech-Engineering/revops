import { Link } from 'react-router-dom'
import { Bell, Plug, ArrowRightLeft, AlertTriangle } from 'lucide-react'
import { useListUnifiedAlertsQuery, useListConnectorsQuery } from '../api/pantherApi'
import { getSeverityColor, formatDate } from '../lib/utils'

export default function Dashboard() {
  // Use unified alerts API to get accurate total counts
  const { data: alertsData, isLoading: alertsLoading } = useListUnifiedAlertsQuery({
    page_size: 5,
    status: 'open'
  })
  const { data: connectorsData, isLoading: connectorsLoading } = useListConnectorsQuery({})

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <p className="text-muted-foreground">Overview of your security posture</p>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Link
          to="/alerts"
          className="rounded-lg border border-border bg-card p-6 hover:border-red-500/50 hover:bg-red-500/5 transition-colors"
        >
          <div className="flex items-center gap-4">
            <div className="rounded-full bg-red-500/20 p-3">
              <Bell className="h-6 w-6 text-red-400" />
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Open Alerts</p>
              <p className="text-2xl font-bold">
                {alertsLoading ? '...' : alertsData?.total?.toLocaleString() || 0}
              </p>
            </div>
          </div>
        </Link>

        <Link
          to="/connectors"
          className="rounded-lg border border-border bg-card p-6 hover:border-blue-500/50 hover:bg-blue-500/5 transition-colors"
        >
          <div className="flex items-center gap-4">
            <div className="rounded-full bg-blue-500/20 p-3">
              <Plug className="h-6 w-6 text-blue-400" />
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Data Connectors</p>
              <p className="text-2xl font-bold">
                {connectorsLoading ? '...' : connectorsData?.items?.filter(c => c.is_enabled).length || 0}
              </p>
            </div>
          </div>
        </Link>

        <Link
          to="/converter"
          className="rounded-lg border border-border bg-card p-6 hover:border-purple-500/50 hover:bg-purple-500/5 transition-colors"
        >
          <div className="flex items-center gap-4">
            <div className="rounded-full bg-purple-500/20 p-3">
              <ArrowRightLeft className="h-6 w-6 text-purple-400" />
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Rule Converter</p>
              <p className="text-sm font-medium">Convert detection rules</p>
            </div>
          </div>
        </Link>
      </div>

      {/* Recent Alerts */}
      <div className="rounded-lg border border-border bg-card">
        <div className="border-b border-border px-6 py-4">
          <h2 className="font-semibold flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-yellow-400" />
            Recent Open Alerts
          </h2>
        </div>
        <div className="divide-y divide-border">
          {alertsLoading ? (
            <div className="p-6 text-center text-muted-foreground">Loading...</div>
          ) : !alertsData?.items?.length ? (
            <div className="p-6 text-center text-muted-foreground">No open alerts</div>
          ) : (
            alertsData.items.map((alert) => (
              <Link
                key={alert.id}
                to={`/alerts/${alert.id}`}
                className="flex items-center justify-between px-6 py-4 hover:bg-accent transition-colors"
              >
                <div>
                  <p className="font-medium">{alert.title}</p>
                  <p className="text-sm text-muted-foreground">
                    {alert.source_type} {alert.rule_name ? `- ${alert.rule_name}` : ''}
                  </p>
                </div>
                <div className="flex items-center gap-4">
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(alert.severity)}`}>
                    {alert.severity}
                  </span>
                  <span className="text-sm text-muted-foreground">
                    {formatDate(alert.created_at_source)}
                  </span>
                </div>
              </Link>
            ))
          )}
        </div>
        {alertsData && alertsData.items?.length > 0 && (
          <div className="border-t border-border px-6 py-3">
            <Link to="/alerts" className="text-sm text-primary hover:underline">
              View all alerts
            </Link>
          </div>
        )}
      </div>
    </div>
  )
}
