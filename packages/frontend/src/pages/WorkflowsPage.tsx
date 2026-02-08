import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Plus,
  Trash2,
  Edit2,
  Play,
  Pause,
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle,
  GitBranch,
  Zap,
  Calendar,
  Webhook,
  MousePointerClick,
} from 'lucide-react'
import {
  useListWorkflowsQuery,
  useDeleteWorkflowMutation,
  useExecuteWorkflowMutation,
  WorkflowStatus,
} from '../api/pantherApi'
import { cn } from '../lib/utils'
import { formatRelativeTime } from '../lib/dateUtils'

const statusConfig: Record<WorkflowStatus, { label: string; color: string; icon: typeof CheckCircle }> = {
  active: { label: 'Active', color: 'bg-green-500/20 text-green-400', icon: CheckCircle },
  inactive: { label: 'Inactive', color: 'bg-gray-500/20 text-gray-400', icon: Pause },
  draft: { label: 'Draft', color: 'bg-yellow-500/20 text-yellow-400', icon: Clock },
}

const triggerTypeConfig: Record<string, { label: string; icon: typeof Zap }> = {
  trigger_alert: { label: 'Alert Trigger', icon: Zap },
  trigger_schedule: { label: 'Scheduled', icon: Calendar },
  trigger_webhook: { label: 'Webhook', icon: Webhook },
  trigger_manual: { label: 'Manual', icon: MousePointerClick },
}

export default function WorkflowsPage() {
  const [filterStatus, setFilterStatus] = useState<WorkflowStatus | ''>('')

  const { data: workflows, isLoading } = useListWorkflowsQuery({
    status: filterStatus || undefined,
  })
  const [deleteWorkflow] = useDeleteWorkflowMutation()
  const [executeWorkflow, { isLoading: isExecuting }] = useExecuteWorkflowMutation()

  const handleDelete = async (id: string, name: string) => {
    if (confirm(`Are you sure you want to delete workflow "${name}"?`)) {
      await deleteWorkflow(id)
    }
  }

  const handleExecute = async (id: string) => {
    try {
      const result = await executeWorkflow({ workflowId: id }).unwrap()
      alert(`Workflow execution started: ${result.id}`)
    } catch (err) {
      alert('Failed to execute workflow')
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Workflows</h1>
          <p className="text-muted-foreground">
            Visual automation workflows with branching, loops, and integrations
          </p>
        </div>
        <Link
          to="/workflows/new"
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md font-medium hover:bg-primary/90"
        >
          <Plus size={18} />
          New Workflow
        </Link>
      </div>

      {/* Filters */}
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
        {(['active', 'inactive', 'draft'] as const).map((status) => (
          <button
            key={status}
            onClick={() => setFilterStatus(status)}
            className={cn(
              'px-3 py-1.5 rounded-md text-sm font-medium transition-colors capitalize',
              filterStatus === status ? 'bg-primary text-primary-foreground' : 'bg-muted hover:bg-accent'
            )}
          >
            {statusConfig[status].label}
          </button>
        ))}
      </div>

      {/* Workflows List */}
      <div className="rounded-lg border bg-background">
        {isLoading ? (
          <div className="p-6 text-center text-muted-foreground">Loading workflows...</div>
        ) : workflows?.items.length === 0 ? (
          <div className="p-12 text-center text-muted-foreground">
            <GitBranch size={48} className="mx-auto mb-4 opacity-20" />
            <p>No workflows configured</p>
            <p className="text-sm mt-2">Create a workflow to automate your security operations</p>
          </div>
        ) : (
          <div className="divide-y">
            {workflows?.items.map((workflow) => {
              const StatusIcon = statusConfig[workflow.status].icon
              const triggerInfo = triggerTypeConfig[workflow.trigger_type || ''] || {
                label: workflow.trigger_type || 'No Trigger',
                icon: AlertCircle,
              }
              const TriggerIcon = triggerInfo.icon

              return (
                <div key={workflow.id} className="p-4 hover:bg-muted/50">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <Link
                          to={`/workflows/${workflow.id}`}
                          className="font-semibold hover:underline"
                        >
                          {workflow.name}
                        </Link>
                        <span
                          className={cn(
                            'flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium',
                            statusConfig[workflow.status].color
                          )}
                        >
                          <StatusIcon size={12} />
                          {statusConfig[workflow.status].label}
                        </span>
                        <span className="flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-muted">
                          <TriggerIcon size={12} />
                          {triggerInfo.label}
                        </span>
                        <span className="px-2 py-0.5 rounded text-xs text-muted-foreground">
                          v{workflow.version}
                        </span>
                      </div>
                      {workflow.description && (
                        <p className="text-sm text-muted-foreground mb-2">{workflow.description}</p>
                      )}
                      <div className="flex items-center gap-4 text-xs text-muted-foreground">
                        <span>Created by {workflow.created_by}</span>
                        <span>
                          Updated {formatRelativeTime(workflow.updated_at)}
                        </span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {workflow.status === 'active' && (
                        <button
                          onClick={() => handleExecute(workflow.id)}
                          disabled={isExecuting}
                          className="p-2 rounded hover:bg-accent text-muted-foreground hover:text-foreground"
                          title="Execute Manually"
                        >
                          <Play size={18} />
                        </button>
                      )}
                      <Link
                        to={`/workflows/${workflow.id}/executions`}
                        className="p-2 rounded hover:bg-accent text-muted-foreground hover:text-foreground"
                        title="View Executions"
                      >
                        <Clock size={18} />
                      </Link>
                      <Link
                        to={`/workflows/${workflow.id}/edit`}
                        className="p-2 rounded hover:bg-accent text-muted-foreground hover:text-foreground"
                        title="Edit"
                      >
                        <Edit2 size={18} />
                      </Link>
                      <button
                        onClick={() => handleDelete(workflow.id, workflow.name)}
                        className="p-2 rounded hover:bg-accent text-muted-foreground hover:text-destructive"
                        title="Delete"
                      >
                        <Trash2 size={18} />
                      </button>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Quick Stats */}
      {workflows && workflows.items.length > 0 && (
        <div className="grid grid-cols-4 gap-4">
          <div className="rounded-lg border bg-background p-4">
            <div className="text-2xl font-bold">{workflows.total}</div>
            <div className="text-sm text-muted-foreground">Total Workflows</div>
          </div>
          <div className="rounded-lg border bg-background p-4">
            <div className="text-2xl font-bold text-green-400">
              {workflows.items.filter((w) => w.status === 'active').length}
            </div>
            <div className="text-sm text-muted-foreground">Active</div>
          </div>
          <div className="rounded-lg border bg-background p-4">
            <div className="text-2xl font-bold text-yellow-400">
              {workflows.items.filter((w) => w.status === 'draft').length}
            </div>
            <div className="text-sm text-muted-foreground">Drafts</div>
          </div>
          <div className="rounded-lg border bg-background p-4">
            <div className="text-2xl font-bold text-gray-400">
              {workflows.items.filter((w) => w.status === 'inactive').length}
            </div>
            <div className="text-sm text-muted-foreground">Inactive</div>
          </div>
        </div>
      )}
    </div>
  )
}
