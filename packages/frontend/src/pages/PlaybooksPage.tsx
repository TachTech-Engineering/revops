import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Play, Plus, Trash2, Edit2, Pause, CheckCircle, XCircle, Clock } from 'lucide-react'
import {
  useListPlaybooksQuery,
  useUpdatePlaybookMutation,
  useDeletePlaybookMutation,
  PlaybookStatus,
} from '../api/pantherApi'
import { cn } from '../lib/utils'

const statusConfig = {
  active: { label: 'Active', color: 'bg-green-500/20 text-green-400' },
  inactive: { label: 'Inactive', color: 'bg-gray-500/20 text-gray-400' },
  draft: { label: 'Draft', color: 'bg-yellow-500/20 text-yellow-400' },
}

const actionTypeLabels: Record<string, string> = {
  webhook: 'Webhook',
  jira_ticket: 'Jira Ticket',
  servicenow_ticket: 'ServiceNow',
  update_alert: 'Update Alert',
  run_query: 'Run Query',
  crowdstrike_isolate: 'CrowdStrike Isolate',
  sentinelone_isolate: 'SentinelOne Isolate',
  firewall_block: 'Firewall Block',
  soar_trigger: 'SOAR Trigger',
}

export default function PlaybooksPage() {
  const [filterStatus, setFilterStatus] = useState<PlaybookStatus | ''>('')

  const { data: playbooks, isLoading } = useListPlaybooksQuery({
    status: filterStatus || undefined,
  })
  const [updatePlaybook] = useUpdatePlaybookMutation()
  const [deletePlaybook] = useDeletePlaybookMutation()

  const handleToggleStatus = async (playbook: NonNullable<typeof playbooks>[0]) => {
    const newStatus = playbook.status === 'active' ? 'inactive' : 'active'
    await updatePlaybook({ id: playbook.id, update: { status: newStatus } })
  }

  const handleDelete = async (id: string) => {
    if (confirm('Are you sure you want to delete this playbook?')) {
      await deletePlaybook(id)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Playbooks</h1>
          <p className="text-muted-foreground">Automate response actions for alerts</p>
        </div>
        <Link
          to="/playbooks/new"
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md font-medium hover:bg-primary/90"
        >
          <Plus size={18} />
          New Playbook
        </Link>
      </div>

      {/* Filters */}
      <div className="flex gap-2">
        <button
          onClick={() => setFilterStatus('')}
          className={cn(
            "px-3 py-1.5 rounded-md text-sm font-medium transition-colors",
            filterStatus === '' ? "bg-primary text-primary-foreground" : "bg-muted hover:bg-accent"
          )}
        >
          All
        </button>
        {(['active', 'inactive', 'draft'] as const).map((status) => (
          <button
            key={status}
            onClick={() => setFilterStatus(status)}
            className={cn(
              "px-3 py-1.5 rounded-md text-sm font-medium transition-colors capitalize",
              filterStatus === status ? "bg-primary text-primary-foreground" : "bg-muted hover:bg-accent"
            )}
          >
            {status}
          </button>
        ))}
      </div>

      {/* Playbooks List */}
      <div className="rounded-lg border bg-background">
        {isLoading ? (
          <div className="p-6 text-center text-muted-foreground">Loading playbooks...</div>
        ) : playbooks?.length === 0 ? (
          <div className="p-12 text-center text-muted-foreground">
            <Play size={48} className="mx-auto mb-4 opacity-20" />
            <p>No playbooks configured</p>
            <p className="text-sm mt-2">Create a playbook to automate alert responses</p>
          </div>
        ) : (
          <div className="divide-y">
            {playbooks?.map((playbook) => (
              <div key={playbook.id} className="p-4 hover:bg-muted/50">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <Link
                        to={`/playbooks/${playbook.id}`}
                        className="font-semibold hover:underline"
                      >
                        {playbook.name}
                      </Link>
                      <span className={cn(
                        "px-2 py-0.5 rounded text-xs font-medium",
                        statusConfig[playbook.status].color
                      )}>
                        {statusConfig[playbook.status].label}
                      </span>
                      {playbook.auto_execute && (
                        <span className="px-2 py-0.5 rounded text-xs font-medium bg-purple-500/20 text-purple-400">
                          Auto
                        </span>
                      )}
                    </div>
                    {playbook.description && (
                      <p className="text-sm text-muted-foreground mb-2">{playbook.description}</p>
                    )}
                    <div className="flex flex-wrap gap-2">
                      {playbook.actions.map((action, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-0.5 rounded text-xs bg-muted"
                        >
                          {actionTypeLabels[action.type] || action.type}
                        </span>
                      ))}
                    </div>
                    {playbook.trigger_conditions && (
                      <div className="mt-2 text-xs text-muted-foreground">
                        {playbook.trigger_conditions.severities && (
                          <span>Severities: {playbook.trigger_conditions.severities.join(', ')}</span>
                        )}
                        {playbook.trigger_conditions.rule_ids && (
                          <span className="ml-2">Rules: {playbook.trigger_conditions.rule_ids.length}</span>
                        )}
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleToggleStatus(playbook)}
                      className="p-2 hover:bg-accent rounded"
                      title={playbook.status === 'active' ? 'Deactivate' : 'Activate'}
                    >
                      {playbook.status === 'active' ? (
                        <Pause size={16} />
                      ) : (
                        <CheckCircle size={16} className="text-green-400" />
                      )}
                    </button>
                    <Link
                      to={`/playbooks/${playbook.id}/edit`}
                      className="p-2 hover:bg-accent rounded"
                      title="Edit"
                    >
                      <Edit2 size={16} />
                    </Link>
                    <button
                      onClick={() => handleDelete(playbook.id)}
                      className="p-2 hover:bg-accent rounded text-red-400"
                      title="Delete"
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>
                </div>
                <div className="mt-2 text-xs text-muted-foreground">
                  Created by {playbook.created_by} on {new Date(playbook.created_at).toLocaleDateString()}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
