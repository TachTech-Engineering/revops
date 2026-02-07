import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Plus,
  Trash2,
  Edit2,
  RefreshCw,
  Play,
  Pause,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  GitBranch,
  Filter,
  Shuffle,
  TrendingDown,
  Activity,
  MoreVertical,
} from 'lucide-react'
import {
  useListPipelinesQuery,
  useDeletePipelineMutation,
  useUpdatePipelineMutation,
  useExecutePipelineMutation,
  PipelineStatus,
} from '../api/pantherApi'
import { cn } from '../lib/utils'
import { formatDistanceToNow } from 'date-fns'

const statusConfig: Record<PipelineStatus, { label: string; color: string; icon: typeof CheckCircle }> = {
  active: { label: 'Active', color: 'bg-green-500/20 text-green-400', icon: CheckCircle },
  inactive: { label: 'Inactive', color: 'bg-gray-500/20 text-gray-400', icon: Pause },
  draft: { label: 'Draft', color: 'bg-blue-500/20 text-blue-400', icon: Clock },
  error: { label: 'Error', color: 'bg-red-500/20 text-red-400', icon: XCircle },
}

export default function PipelinesPage() {
  const navigate = useNavigate()
  const [filterStatus, setFilterStatus] = useState<PipelineStatus | ''>('')
  const [actionMenuOpen, setActionMenuOpen] = useState<string | null>(null)

  const { data: pipelines, isLoading, refetch } = useListPipelinesQuery(
    filterStatus ? { status: filterStatus } : undefined
  )
  const [deletePipeline] = useDeletePipelineMutation()
  const [updatePipeline] = useUpdatePipelineMutation()
  const [executePipeline, { isLoading: isExecuting }] = useExecutePipelineMutation()

  const handleDelete = async (id: string, name: string) => {
    if (confirm(`Are you sure you want to delete pipeline "${name}"?`)) {
      try {
        await deletePipeline(id).unwrap()
      } catch (err) {
        alert('Failed to delete pipeline')
      }
    }
  }

  const handleToggleStatus = async (id: string, currentStatus: PipelineStatus) => {
    const newStatus = currentStatus === 'active' ? 'inactive' : 'active'
    try {
      await updatePipeline({ id, update: { status: newStatus } }).unwrap()
    } catch (err) {
      alert('Failed to update pipeline status')
    }
  }

  const handleExecute = async (id: string) => {
    try {
      const result = await executePipeline({ id }).unwrap()
      alert(
        `Pipeline executed: ${result.events_output} events processed, ` +
        `${result.events_filtered} filtered (${result.duration_ms}ms)`
      )
    } catch (err) {
      alert('Failed to execute pipeline')
    }
  }

  const formatReduction = (percentage: number) => {
    if (percentage === 0) return '0%'
    return `${percentage.toFixed(1)}%`
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Data Pipelines</h1>
          <p className="text-muted-foreground">
            Transform, filter, and route your security data
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="flex items-center gap-2 px-4 py-2 bg-muted text-muted-foreground rounded-md font-medium hover:bg-accent"
          >
            <RefreshCw size={18} className={isLoading ? 'animate-spin' : ''} />
            Refresh
          </button>
          <Link
            to="/pipelines/new"
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md font-medium hover:bg-primary/90"
          >
            <Plus size={18} />
            Create Pipeline
          </Link>
        </div>
      </div>

      {/* Status Filters */}
      <div className="flex gap-2">
        <button
          onClick={() => setFilterStatus('')}
          className={cn(
            'px-3 py-1.5 rounded-md text-sm font-medium transition-colors',
            filterStatus === '' ? 'bg-primary text-primary-foreground' : 'bg-muted hover:bg-accent'
          )}
        >
          All
        </button>
        {(['active', 'inactive', 'draft', 'error'] as const).map((status) => (
          <button
            key={status}
            onClick={() => setFilterStatus(status)}
            className={cn(
              'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium transition-colors',
              filterStatus === status ? 'bg-primary text-primary-foreground' : 'bg-muted hover:bg-accent'
            )}
          >
            {React.createElement(statusConfig[status].icon, { size: 14 })}
            {statusConfig[status].label}
          </button>
        ))}
      </div>

      {/* Pipeline Cards */}
      <div className="grid gap-4">
        {isLoading ? (
          <div className="p-12 text-center text-muted-foreground rounded-lg border bg-background">
            <RefreshCw size={32} className="mx-auto mb-4 animate-spin opacity-50" />
            <p>Loading pipelines...</p>
          </div>
        ) : !pipelines || pipelines.length === 0 ? (
          <div className="p-12 text-center text-muted-foreground rounded-lg border bg-background">
            <GitBranch size={48} className="mx-auto mb-4 opacity-20" />
            <p className="text-lg font-medium mb-2">No pipelines configured</p>
            <p className="text-sm mb-4">
              Create a pipeline to transform, filter, and route your security data
            </p>
            <Link
              to="/pipelines/new"
              className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md font-medium hover:bg-primary/90"
            >
              <Plus size={18} />
              Create Your First Pipeline
            </Link>
          </div>
        ) : (
          pipelines.map((pipeline) => {
            const StatusIcon = statusConfig[pipeline.status].icon
            const metrics = pipeline.metrics

            return (
              <div
                key={pipeline.id}
                className="rounded-lg border bg-background hover:border-primary/50 transition-colors"
              >
                <div className="p-4">
                  <div className="flex items-start justify-between">
                    {/* Pipeline Info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 mb-2">
                        <div className="p-2 rounded-lg bg-primary/10">
                          <GitBranch size={20} className="text-primary" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <Link
                              to={`/pipelines/${pipeline.id}`}
                              className="font-semibold text-lg hover:underline truncate"
                            >
                              {pipeline.name}
                            </Link>
                            <span
                              className={cn(
                                'flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium shrink-0',
                                statusConfig[pipeline.status].color
                              )}
                            >
                              <StatusIcon size={12} />
                              {statusConfig[pipeline.status].label}
                            </span>
                          </div>
                          {pipeline.description && (
                            <p className="text-sm text-muted-foreground truncate">
                              {pipeline.description}
                            </p>
                          )}
                        </div>
                      </div>

                      {/* Metrics Row */}
                      {metrics && (
                        <div className="flex items-center gap-6 mt-4 text-sm">
                          <div className="flex items-center gap-2">
                            <Activity size={16} className="text-muted-foreground" />
                            <span className="text-muted-foreground">Events (24h):</span>
                            <span className="font-medium">
                              {metrics.events_last_24h.toLocaleString()}
                            </span>
                          </div>

                          <div className="flex items-center gap-2">
                            <TrendingDown size={16} className="text-green-500" />
                            <span className="text-muted-foreground">Reduction:</span>
                            <span className="font-medium text-green-500">
                              {formatReduction(metrics.reduction_percentage)}
                            </span>
                          </div>

                          <div className="flex items-center gap-2">
                            <Clock size={16} className="text-muted-foreground" />
                            <span className="text-muted-foreground">Avg latency:</span>
                            <span className="font-medium">
                              {metrics.avg_processing_ms.toFixed(0)}ms
                            </span>
                          </div>

                          {metrics.error_rate > 0 && (
                            <div className="flex items-center gap-2">
                              <AlertTriangle size={16} className="text-yellow-500" />
                              <span className="text-muted-foreground">Error rate:</span>
                              <span className="font-medium text-yellow-500">
                                {metrics.error_rate.toFixed(1)}%
                              </span>
                            </div>
                          )}

                          {metrics.last_execution && (
                            <div className="flex items-center gap-2 text-muted-foreground">
                              <span>Last run:</span>
                              <span>
                                {formatDistanceToNow(new Date(metrics.last_execution), { addSuffix: true })}
                              </span>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Source Info */}
                      <div className="flex items-center gap-4 mt-3 text-xs text-muted-foreground">
                        {pipeline.source_connector_ids.length > 0 && (
                          <span>
                            {pipeline.source_connector_ids.length} connector{pipeline.source_connector_ids.length !== 1 ? 's' : ''}
                          </span>
                        )}
                        <span>Batch size: {pipeline.batch_size}</span>
                        <span>
                          Updated {formatDistanceToNow(new Date(pipeline.updated_at), { addSuffix: true })}
                        </span>
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-1 ml-4">
                      {pipeline.status === 'active' ? (
                        <button
                          onClick={() => handleToggleStatus(pipeline.id, pipeline.status)}
                          className="p-2 rounded hover:bg-accent text-muted-foreground hover:text-yellow-500"
                          title="Deactivate Pipeline"
                        >
                          <Pause size={18} />
                        </button>
                      ) : pipeline.status !== 'error' ? (
                        <button
                          onClick={() => handleToggleStatus(pipeline.id, pipeline.status)}
                          className="p-2 rounded hover:bg-accent text-muted-foreground hover:text-green-500"
                          title="Activate Pipeline"
                        >
                          <Play size={18} />
                        </button>
                      ) : null}

                      <button
                        onClick={() => handleExecute(pipeline.id)}
                        disabled={isExecuting || pipeline.status === 'error'}
                        className="p-2 rounded hover:bg-accent text-muted-foreground hover:text-foreground disabled:opacity-50"
                        title="Execute Pipeline"
                      >
                        <RefreshCw size={18} className={isExecuting ? 'animate-spin' : ''} />
                      </button>

                      <Link
                        to={`/pipelines/${pipeline.id}`}
                        className="p-2 rounded hover:bg-accent text-muted-foreground hover:text-foreground"
                        title="Edit Pipeline"
                      >
                        <Edit2 size={18} />
                      </Link>

                      <div className="relative">
                        <button
                          onClick={() => setActionMenuOpen(actionMenuOpen === pipeline.id ? null : pipeline.id)}
                          className="p-2 rounded hover:bg-accent text-muted-foreground hover:text-foreground"
                        >
                          <MoreVertical size={18} />
                        </button>

                        {actionMenuOpen === pipeline.id && (
                          <div className="absolute right-0 top-full mt-1 w-48 rounded-md border bg-popover shadow-lg z-10">
                            <button
                              onClick={() => {
                                setActionMenuOpen(null)
                                navigate(`/pipelines/${pipeline.id}`)
                              }}
                              className="flex items-center gap-2 w-full px-3 py-2 text-sm hover:bg-accent text-left"
                            >
                              <Edit2 size={14} />
                              Edit Pipeline
                            </button>
                            <button
                              onClick={() => {
                                setActionMenuOpen(null)
                                // Clone functionality
                              }}
                              className="flex items-center gap-2 w-full px-3 py-2 text-sm hover:bg-accent text-left"
                            >
                              <Plus size={14} />
                              Clone Pipeline
                            </button>
                            <hr className="my-1" />
                            <button
                              onClick={() => {
                                setActionMenuOpen(null)
                                handleDelete(pipeline.id, pipeline.name)
                              }}
                              className="flex items-center gap-2 w-full px-3 py-2 text-sm hover:bg-accent text-left text-destructive"
                            >
                              <Trash2 size={14} />
                              Delete Pipeline
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Visual Pipeline Preview */}
                <div className="px-4 pb-4">
                  <div className="flex items-center gap-2 p-3 rounded-lg bg-muted/50 overflow-x-auto">
                    <div className="flex items-center gap-1 px-2 py-1 rounded bg-blue-500/20 text-blue-400 text-xs font-medium shrink-0">
                      <Shuffle size={12} />
                      Transform
                    </div>
                    <div className="w-8 h-px bg-border shrink-0" />
                    <div className="flex items-center gap-1 px-2 py-1 rounded bg-yellow-500/20 text-yellow-400 text-xs font-medium shrink-0">
                      <Filter size={12} />
                      Filter
                    </div>
                    <div className="w-8 h-px bg-border shrink-0" />
                    <div className="flex items-center gap-1 px-2 py-1 rounded bg-green-500/20 text-green-400 text-xs font-medium shrink-0">
                      <GitBranch size={12} />
                      Route
                    </div>
                  </div>
                </div>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
