import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  ArrowLeft,
  AlertTriangle,
  Clock,
  User,
  ExternalLink,
  RefreshCw,
  MoreVertical,
  Shield,
  Activity,
} from 'lucide-react'
import {
  useGetAlertClusterQuery,
  useGetClusterAlertsQuery,
  useUpdateAlertClusterMutation,
} from '../api/pantherApi'
import { cn } from '../lib/utils'
import { formatRelativeTime } from '../lib/dateUtils'

const severityColors: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/50',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/50',
  info: 'bg-gray-500/20 text-gray-400 border-gray-500/50',
}

const statusColors: Record<string, string> = {
  open: 'bg-red-500/20 text-red-400',
  investigating: 'bg-yellow-500/20 text-yellow-400',
  resolved: 'bg-green-500/20 text-green-400',
  dismissed: 'bg-gray-500/20 text-gray-400',
}

export default function ClusteredAlertDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { data: cluster, isLoading: isLoadingCluster, refetch: refetchCluster } = useGetAlertClusterQuery(id!)
  const { data: alerts, isLoading: isLoadingAlerts } = useGetClusterAlertsQuery(id!)
  const [updateCluster] = useUpdateAlertClusterMutation()

  const handleStatusChange = async (status: string) => {
    try {
      await updateCluster({ id: id!, status }).unwrap()
    } catch (err) {
      console.error('Failed to update cluster status:', err)
    }
  }

  if (isLoadingCluster) {
    return (
      <div className="flex items-center justify-center py-12">
        <RefreshCw className="animate-spin text-muted-foreground" size={24} />
      </div>
    )
  }

  if (!cluster) {
    return (
      <div className="p-6 text-center">
        <p className="text-muted-foreground">Cluster not found</p>
        <Link to="/alerts/clusters" className="text-primary hover:underline mt-4 inline-block">
          Back to Clusters
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4">
        <div className="flex items-center gap-4">
          <Link to="/alerts/clusters" className="p-2 hover:bg-accent rounded-md">
            <ArrowLeft size={20} />
          </Link>
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-1">
              <span className={cn(
                'px-2 py-0.5 rounded text-xs font-medium border',
                severityColors[cluster.severity] || severityColors.info
              )}>
                {cluster.severity.toUpperCase()}
              </span>
              <h1 className="text-2xl font-bold">{cluster.name}</h1>
            </div>
            <p className="text-muted-foreground text-sm">Cluster ID: {cluster.id}</p>
          </div>
          <div className="flex items-center gap-2">
            <select
              value={cluster.status}
              onChange={(e) => handleStatusChange(e.target.value)}
              className={cn(
                'px-3 py-1.5 rounded-md text-sm font-medium border bg-background',
                statusColors[cluster.status]
              )}
            >
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
              <option value="dismissed">Dismissed</option>
            </select>
            <button className="p-2 hover:bg-accent rounded-md">
              <MoreVertical size={20} />
            </button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Details & Entities */}
        <div className="lg:col-span-2 space-y-6">
          {/* Summary Card */}
          <div className="bg-card rounded-lg border p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Activity size={18} className="text-primary" />
              Cluster Summary
            </h2>
            <p className="text-muted-foreground whitespace-pre-wrap">{cluster.summary}</p>
            
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-6 pt-6 border-t">
              <div>
                <p className="text-xs text-muted-foreground uppercase font-semibold">Alert Count</p>
                <p className="text-xl font-bold">{cluster.alert_count}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground uppercase font-semibold">First Seen</p>
                <p className="text-sm mt-1">{new Date(cluster.first_alert_at).toLocaleString()}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground uppercase font-semibold">Last Seen</p>
                <p className="text-sm mt-1">{new Date(cluster.last_alert_at).toLocaleString()}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground uppercase font-semibold">Assignee</p>
                <p className="text-sm mt-1">{cluster.assignee || 'Unassigned'}</p>
              </div>
            </div>
          </div>

          {/* Alerts List */}
          <div className="bg-card rounded-lg border overflow-hidden">
            <div className="px-6 py-4 border-b bg-muted/30 flex items-center justify-between">
              <h2 className="text-lg font-semibold">Alerts in Cluster</h2>
              <span className="text-sm text-muted-foreground">{alerts?.length || 0} alerts total</span>
            </div>
            <div className="divide-y">
              {isLoadingAlerts ? (
                <div className="p-12 text-center">
                  <RefreshCw className="animate-spin mx-auto text-muted-foreground mb-2" size={24} />
                  <p className="text-sm text-muted-foreground">Loading cluster alerts...</p>
                </div>
              ) : alerts?.length === 0 ? (
                <div className="p-12 text-center text-muted-foreground">
                  No alerts found in this cluster
                </div>
              ) : (
                alerts?.map((alert) => (
                  <div key={alert.id} className="p-4 hover:bg-muted/20 transition-colors">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className={cn(
                            'px-1.5 py-0.5 rounded-[4px] text-[10px] font-bold uppercase',
                            severityColors[(alert.severity || 'info').toLowerCase()] || severityColors.info
                          )}>
                            {alert.severity || 'INFO'}
                          </span>
                          <Link to={`/alerts/${alert.id}`} className="font-medium hover:underline truncate">
                            {alert.title}
                          </Link>
                        </div>
                        <p className="text-xs text-muted-foreground mb-2">{alert.rule_name}</p>
                        <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
                          <span className="flex items-center gap-1">
                            <Clock size={10} />
                            {new Date(alert.created_at).toLocaleString()}
                          </span>
                          {alert.source_type && (
                            <span className="flex items-center gap-1">
                              <Shield size={10} />
                              {alert.source_type}
                            </span>
                          )}
                        </div>
                      </div>
                      <Link 
                        to={`/alerts/${alert.id}`}
                        className="p-2 hover:bg-accent rounded-md text-muted-foreground hover:text-foreground"
                      >
                        <ExternalLink size={16} />
                      </Link>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Right Column: Entities & Context */}
        <div className="space-y-6">
          <div className="bg-card rounded-lg border p-6">
            <h2 className="text-lg font-semibold mb-4">Common Entities</h2>
            {cluster.common_entities && Object.keys(cluster.common_entities).length > 0 ? (
              <div className="space-y-4">
                {Object.entries(cluster.common_entities).map(([key, value]) => (
                  <div key={key} className="p-3 bg-muted/30 rounded-md">
                    <p className="text-xs text-muted-foreground uppercase font-semibold mb-1">{key}</p>
                    <p className="text-sm font-mono break-all">{String(value)}</p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground text-center py-4 italic">
                No common entities identified
              </p>
            )}
          </div>

          <div className="bg-card rounded-lg border p-6">
            <h2 className="text-lg font-semibold mb-4">Correlation Logic</h2>
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Clustered By:</span>
                <span className="font-medium">{cluster.clustered_by?.join(', ') || 'N/A'}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Time Window:</span>
                <span className="font-medium">24 Hours</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
