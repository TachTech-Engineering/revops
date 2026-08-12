import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Layers,
  RefreshCw,
  ChevronRight,
  AlertTriangle,
  Clock,
  User,
  Merge,
  Trash2,
} from 'lucide-react'
import {
  useListAlertClustersQuery,
  useGenerateClustersMutation,
  useUpdateAlertClusterMutation,
  useMergeClustersMutation,
  useDeleteAlertClusterMutation,
  useBulkDeleteAlertClustersMutation,
} from '../api/pantherApi'
import { cn } from '../lib/utils'

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

export default function ClusteredAlertsPage() {
  const [statusFilter, setStatusFilter] = useState<string>('open')
  const [severityFilter, setSeverityFilter] = useState<string>('')
  const [selectedClusters, setSelectedClusters] = useState<Set<string>>(new Set())
  const [showMergeModal, setShowMergeModal] = useState(false)

  const { data, isLoading, refetch } = useListAlertClustersQuery({
    status: statusFilter || undefined,
    severity: severityFilter || undefined,
    page: 1,
    pageSize: 50,
  })

  const [generateClusters, { isLoading: isGenerating }] = useGenerateClustersMutation()
  const [updateCluster] = useUpdateAlertClusterMutation()
  const [mergeClusters, { isLoading: isMerging }] = useMergeClustersMutation()
  const [deleteCluster] = useDeleteAlertClusterMutation()
  const [bulkDeleteClusters, { isLoading: isBulkDeleting }] = useBulkDeleteAlertClustersMutation()

  const handleGenerate = async () => {
    try {
      await generateClusters({
        timeWindowHours: 24,
        minClusterSize: 3,
        clusterBy: ['rule_id', 'entity'],
      }).unwrap()
      refetch()
    } catch (err) {
      console.error('Failed to generate clusters:', err)
    }
  }

  const handleBulkDelete = async () => {
    if (selectedClusters.size === 0) return
    if (!confirm(`Are you sure you want to delete ${selectedClusters.size} clusters? This cannot be undone.`)) return

    try {
      await bulkDeleteClusters({ clusterIds: Array.from(selectedClusters) }).unwrap()
      setSelectedClusters(new Set())
      refetch()
    } catch (err) {
      console.error('Failed to bulk delete clusters:', err)
      alert('Failed to bulk delete clusters')
    }
  }

  const handleStatusChange = async (clusterId: string, status: string) => {
    try {
      await updateCluster({ id: clusterId, status }).unwrap()
    } catch (err) {
      console.error('Failed to update cluster:', err)
    }
  }

  const handleMerge = async () => {
    if (selectedClusters.size < 2) return
    const clusterIds = Array.from(selectedClusters)
    const targetId = clusterIds[0]
    const sourceIds = clusterIds.slice(1)

    try {
      await mergeClusters({ targetClusterId: targetId, sourceClusterIds: sourceIds }).unwrap()
      setSelectedClusters(new Set())
      setShowMergeModal(false)
      refetch()
    } catch (err) {
      console.error('Failed to merge clusters:', err)
    }
  }

  const handleDelete = async (clusterId: string, clusterName: string) => {
    if (!confirm(`Are you sure you want to delete the cluster "${clusterName}"? This cannot be undone.`)) return

    try {
      await deleteCluster(clusterId).unwrap()
      selectedClusters.delete(clusterId)
      setSelectedClusters(new Set(selectedClusters))
    } catch (err) {
      console.error('Failed to delete cluster:', err)
      alert('Failed to delete cluster')
    }
  }

  const toggleClusterSelection = (clusterId: string) => {
    setSelectedClusters((prev) => {
      const next = new Set(prev)
      if (next.has(clusterId)) {
        next.delete(clusterId)
      } else {
        next.add(clusterId)
      }
      return next
    })
  }

  return (
    <div className="space-y-4">
      {/* Header with Filters */}
      <div className="flex items-center gap-4 p-4 bg-card rounded-lg border flex-wrap">
        <div className="flex items-center gap-2 mr-2">
          <Layers className="text-primary" size={20} />
          <h1 className="text-lg font-bold">Alert Clusters</h1>
        </div>

        <div className="h-6 w-px bg-border hidden sm:block" />

        <div className="flex items-center gap-2 px-3 py-1.5 border rounded-md bg-background">
          <input
            type="checkbox"
            checked={!!data && data.clusters.length > 0 && selectedClusters.size === data.clusters.length}
            onChange={(e) => {
              if (e.target.checked && data?.clusters) {
                setSelectedClusters(new Set(data.clusters.map((c) => c.id)))
              } else {
                setSelectedClusters(new Set())
              }
            }}
            className="rounded border-gray-600"
          />
          <span className="text-sm font-medium">Select All</span>
        </div>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-1.5 bg-background border rounded-md text-sm"
        >
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
          <option value="dismissed">Dismissed</option>
        </select>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="px-3 py-1.5 bg-background border rounded-md text-sm"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <span className="text-sm text-muted-foreground">
          {data?.total || 0} clusters
        </span>

        <div className="flex items-center gap-2 ml-auto">
          {selectedClusters.size > 0 && (
            <button
              onClick={handleBulkDelete}
              disabled={isBulkDeleting}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-destructive text-destructive-foreground rounded-md hover:bg-destructive/90 text-sm disabled:opacity-50"
            >
              <Trash2 size={14} />
              Delete Selected ({selectedClusters.size})
            </button>
          )}
          {selectedClusters.size >= 2 && (
            <button
              onClick={() => setShowMergeModal(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 text-sm"
            >
              <Merge size={14} />
              Merge ({selectedClusters.size})
            </button>
          )}
          <button
            onClick={handleGenerate}
            disabled={isGenerating}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50 text-sm"
          >
            <RefreshCw size={14} className={isGenerating ? 'animate-spin' : ''} />
            Generate
          </button>
        </div>
      </div>

      {/* Clusters List */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="animate-spin text-muted-foreground" size={24} />
        </div>
      ) : !data?.clusters?.length ? (
        <div className="text-center py-12 bg-card rounded-lg border">
          <Layers className="mx-auto text-muted-foreground mb-4" size={48} />
          <h3 className="text-lg font-medium">No clusters found</h3>
          <p className="text-muted-foreground mt-1">
            Click "Generate Clusters" to analyze recent alerts
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {data.clusters.map((cluster) => (
            <div
              key={cluster.id}
              className={cn(
                'bg-card rounded-lg border p-4 hover:border-primary/50 transition-colors',
                selectedClusters.has(cluster.id) && 'border-primary ring-1 ring-primary'
              )}
            >
              <div className="flex items-start gap-4">
                <input
                  type="checkbox"
                  checked={selectedClusters.has(cluster.id)}
                  onChange={() => toggleClusterSelection(cluster.id)}
                  className="mt-1.5 rounded border-gray-600"
                />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3 mb-2">
                    <span
                      className={cn(
                        'px-2 py-0.5 rounded text-xs font-medium border',
                        severityColors[cluster.severity] || severityColors.info
                      )}
                    >
                      {cluster.severity.toUpperCase()}
                    </span>
                    <span
                      className={cn(
                        'px-2 py-0.5 rounded text-xs font-medium',
                        statusColors[cluster.status] || statusColors.open
                      )}
                    >
                      {cluster.status}
                    </span>
                    <span className="text-xs text-muted-foreground flex items-center gap-1">
                      <AlertTriangle size={12} />
                      {cluster.alert_count} alerts
                    </span>
                  </div>
                  <h3 className="font-medium text-lg">{cluster.name}</h3>
                  <p className="text-muted-foreground text-sm mt-1 line-clamp-2">
                    {cluster.summary}
                  </p>
                  <div className="flex items-center gap-4 mt-3 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Clock size={12} />
                      First: {new Date(cluster.first_alert_at).toLocaleString()}
                    </span>
                    <span className="flex items-center gap-1">
                      <Clock size={12} />
                      Last: {new Date(cluster.last_alert_at).toLocaleString()}
                    </span>
                    {cluster.assignee && (
                      <span className="flex items-center gap-1">
                        <User size={12} />
                        {cluster.assignee}
                      </span>
                    )}
                  </div>
                  {cluster.common_entities && Object.keys(cluster.common_entities).length > 0 && (
                    <div className="flex flex-wrap gap-2 mt-3">
                      {Object.entries(cluster.common_entities).map(([key, value]) => (
                        <span
                          key={key}
                          className="px-2 py-1 bg-accent rounded text-xs"
                        >
                          {key}: {String(value)}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                <div className="flex flex-col gap-2">
                  <select
                    value={cluster.status}
                    onChange={(e) => handleStatusChange(cluster.id, e.target.value)}
                    className="px-2 py-1 bg-background border rounded text-sm"
                  >
                    <option value="open">Open</option>
                    <option value="investigating">Investigating</option>
                    <option value="resolved">Resolved</option>
                    <option value="dismissed">Dismissed</option>
                  </select>
                  <Link
                    to={`/alerts/clusters/${cluster.id}`}
                    className="flex items-center justify-center gap-1 px-3 py-1.5 text-sm border rounded hover:bg-accent transition-colors"
                  >
                    View <ChevronRight size={14} />
                  </Link>
                  <button
                    onClick={() => handleDelete(cluster.id, cluster.name)}
                    className="flex items-center justify-center gap-1 px-3 py-1.5 text-sm border border-red-500/50 rounded hover:bg-red-500/20 text-red-400"
                  >
                    <Trash2 size={14} /> Delete
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Merge Modal */}
      {showMergeModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card rounded-lg p-6 max-w-md w-full mx-4">
            <h2 className="text-lg font-semibold mb-4">Merge Clusters</h2>
            <p className="text-muted-foreground mb-4">
              Are you sure you want to merge {selectedClusters.size} clusters?
              The first selected cluster will be the target, and all alerts from
              other clusters will be moved into it.
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setShowMergeModal(false)}
                className="px-4 py-2 border rounded-md hover:bg-accent"
              >
                Cancel
              </button>
              <button
                onClick={handleMerge}
                disabled={isMerging}
                className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
              >
                {isMerging ? 'Merging...' : 'Merge Clusters'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
