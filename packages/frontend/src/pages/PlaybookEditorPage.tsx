import { useState, useEffect } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, Plus, Trash2, GripVertical, Save, Play } from 'lucide-react'
import {
  useGetPlaybookQuery,
  useCreatePlaybookMutation,
  useUpdatePlaybookMutation,
  ActionType,
  ActionConfig,
  TriggerConditions,
} from '../api/pantherApi'
import { cn } from '../lib/utils'

const actionTypes: { type: ActionType; label: string; description: string }[] = [
  { type: 'webhook', label: 'Webhook', description: 'Send to Slack, Teams, PagerDuty, or custom URL' },
  { type: 'jira_ticket', label: 'Jira Ticket', description: 'Create a Jira issue' },
  { type: 'servicenow_ticket', label: 'ServiceNow', description: 'Create a ServiceNow incident' },
  { type: 'update_alert', label: 'Update Alert', description: 'Change alert status or assignee' },
  { type: 'run_query', label: 'Run Query', description: 'Execute a Data Lake query' },
  { type: 'crowdstrike_isolate', label: 'CrowdStrike Isolate', description: 'Isolate host via CrowdStrike' },
  { type: 'sentinelone_isolate', label: 'SentinelOne Isolate', description: 'Isolate host via SentinelOne' },
  { type: 'firewall_block', label: 'Firewall Block', description: 'Block IP at firewall' },
  { type: 'soar_trigger', label: 'SOAR Trigger', description: 'Trigger external SOAR playbook' },
]

const severityOptions = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

interface FormData {
  name: string
  description: string
  trigger_conditions: TriggerConditions
  actions: ActionConfig[]
  auto_execute: boolean
}

export default function PlaybookEditorPage() {
  const navigate = useNavigate()
  const { playbookId } = useParams()
  const isEditing = !!playbookId && playbookId !== 'new'

  const { data: existingPlaybook, isLoading: isLoadingPlaybook } = useGetPlaybookQuery(playbookId!, {
    skip: !isEditing,
  })

  const [createPlaybook, { isLoading: isCreating }] = useCreatePlaybookMutation()
  const [updatePlaybook, { isLoading: isUpdating }] = useUpdatePlaybookMutation()

  const [formData, setFormData] = useState<FormData>({
    name: '',
    description: '',
    trigger_conditions: {},
    actions: [],
    auto_execute: false,
  })

  const [showActionPicker, setShowActionPicker] = useState(false)

  useEffect(() => {
    if (existingPlaybook) {
      setFormData({
        name: existingPlaybook.name,
        description: existingPlaybook.description || '',
        trigger_conditions: existingPlaybook.trigger_conditions || {},
        actions: existingPlaybook.actions || [],
        auto_execute: existingPlaybook.auto_execute,
      })
    }
  }, [existingPlaybook])

  const handleAddAction = (type: ActionType) => {
    setFormData((prev) => ({
      ...prev,
      actions: [
        ...prev.actions,
        {
          type,
          name: actionTypes.find((a) => a.type === type)?.label || type,
          config: {},
          stop_on_failure: false,
        },
      ],
    }))
    setShowActionPicker(false)
  }

  const handleUpdateAction = (index: number, updates: Partial<ActionConfig>) => {
    setFormData((prev) => ({
      ...prev,
      actions: prev.actions.map((action, i) =>
        i === index ? { ...action, ...updates } : action
      ),
    }))
  }

  const handleRemoveAction = (index: number) => {
    setFormData((prev) => ({
      ...prev,
      actions: prev.actions.filter((_, i) => i !== index),
    }))
  }

  const handleSubmit = async () => {
    if (!formData.name.trim() || formData.actions.length === 0) return

    try {
      if (isEditing) {
        await updatePlaybook({
          id: playbookId!,
          update: formData,
        }).unwrap()
      } else {
        await createPlaybook(formData).unwrap()
      }
      navigate('/playbooks')
    } catch (err) {
      console.error('Failed to save playbook:', err)
    }
  }

  const handleToggleSeverity = (severity: string) => {
    setFormData((prev) => {
      const current = prev.trigger_conditions.severities || []
      const updated = current.includes(severity)
        ? current.filter((s) => s !== severity)
        : [...current, severity]
      return {
        ...prev,
        trigger_conditions: {
          ...prev.trigger_conditions,
          severities: updated.length > 0 ? updated : undefined,
        },
      }
    })
  }

  if (isEditing && isLoadingPlaybook) {
    return <div className="p-6 text-center text-muted-foreground">Loading playbook...</div>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <button
          onClick={() => navigate('/playbooks')}
          className="p-2 hover:bg-accent rounded-md"
        >
          <ArrowLeft size={20} />
        </button>
        <div>
          <h1 className="text-3xl font-bold">
            {isEditing ? 'Edit Playbook' : 'Create Playbook'}
          </h1>
          <p className="text-muted-foreground">
            Define automated response actions for alerts
          </p>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Main Form */}
        <div className="lg:col-span-2 space-y-6">
          {/* Basic Info */}
          <div className="rounded-lg border bg-background p-6">
            <h2 className="font-semibold mb-4">Basic Information</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Name *</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData((p) => ({ ...p, name: e.target.value }))}
                  placeholder="Playbook name"
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Description</label>
                <textarea
                  value={formData.description}
                  onChange={(e) => setFormData((p) => ({ ...p, description: e.target.value }))}
                  placeholder="Describe what this playbook does"
                  rows={3}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                />
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="auto_execute"
                  checked={formData.auto_execute}
                  onChange={(e) => setFormData((p) => ({ ...p, auto_execute: e.target.checked }))}
                  className="rounded"
                />
                <label htmlFor="auto_execute" className="text-sm">
                  Auto-execute when trigger conditions match
                </label>
              </div>
            </div>
          </div>

          {/* Trigger Conditions */}
          <div className="rounded-lg border bg-background p-6">
            <h2 className="font-semibold mb-4">Trigger Conditions</h2>
            <p className="text-sm text-muted-foreground mb-4">
              Define when this playbook should be available or auto-executed
            </p>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2">Severities</label>
                <div className="flex flex-wrap gap-2">
                  {severityOptions.map((severity) => (
                    <button
                      key={severity}
                      onClick={() => handleToggleSeverity(severity)}
                      className={cn(
                        "px-3 py-1 rounded text-sm font-medium transition-colors",
                        formData.trigger_conditions.severities?.includes(severity)
                          ? "bg-primary text-primary-foreground"
                          : "bg-muted hover:bg-accent"
                      )}
                    >
                      {severity}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Title Pattern (regex)</label>
                <input
                  type="text"
                  value={formData.trigger_conditions.title_pattern || ''}
                  onChange={(e) => setFormData((p) => ({
                    ...p,
                    trigger_conditions: {
                      ...p.trigger_conditions,
                      title_pattern: e.target.value || undefined,
                    },
                  }))}
                  placeholder="e.g., .*brute.*force.*"
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                />
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="rounded-lg border bg-background p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-semibold">Actions</h2>
              <button
                onClick={() => setShowActionPicker(true)}
                className="flex items-center gap-1 px-3 py-1.5 text-sm bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
              >
                <Plus size={16} />
                Add Action
              </button>
            </div>

            {formData.actions.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <Play size={32} className="mx-auto mb-2 opacity-20" />
                <p>No actions configured</p>
                <p className="text-sm">Add actions to define what this playbook does</p>
              </div>
            ) : (
              <div className="space-y-3">
                {formData.actions.map((action, index) => (
                  <div
                    key={index}
                    className="flex items-start gap-3 p-4 rounded-lg border bg-muted/30"
                  >
                    <div className="p-1 text-muted-foreground cursor-move">
                      <GripVertical size={16} />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <span className="text-xs bg-muted px-2 py-0.5 rounded">
                          {index + 1}
                        </span>
                        <span className="font-medium text-sm">
                          {actionTypes.find((a) => a.type === action.type)?.label || action.type}
                        </span>
                      </div>
                      {/* Action-specific config fields */}
                      {action.type === 'webhook' && (
                        <div className="space-y-2">
                          <select
                            value={(action.config.webhook_type as string) || 'generic'}
                            onChange={(e) => handleUpdateAction(index, {
                              config: { ...action.config, webhook_type: e.target.value },
                            })}
                            className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                          >
                            <option value="generic">Generic</option>
                            <option value="slack">Slack</option>
                            <option value="teams">Microsoft Teams</option>
                            <option value="pagerduty">PagerDuty</option>
                          </select>
                          <input
                            type="url"
                            value={(action.config.url as string) || ''}
                            onChange={(e) => handleUpdateAction(index, {
                              config: { ...action.config, url: e.target.value },
                            })}
                            placeholder="Webhook URL"
                            className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                          />
                        </div>
                      )}
                      {action.type === 'update_alert' && (
                        <select
                          value={(action.config.status as string) || ''}
                          onChange={(e) => handleUpdateAction(index, {
                            config: { ...action.config, status: e.target.value },
                          })}
                          className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                        >
                          <option value="">Select new status</option>
                          <option value="TRIAGED">Triaged</option>
                          <option value="RESOLVED">Resolved</option>
                          <option value="CLOSED">Closed</option>
                        </select>
                      )}
                      {(action.type === 'jira_ticket' || action.type === 'servicenow_ticket') && (
                        <p className="text-xs text-muted-foreground">
                          Uses system configuration. Override in config if needed.
                        </p>
                      )}
                      {(action.type === 'crowdstrike_isolate' || action.type === 'sentinelone_isolate') && (
                        <select
                          value={(action.config.action as string) || 'contain'}
                          onChange={(e) => handleUpdateAction(index, {
                            config: { ...action.config, action: e.target.value },
                          })}
                          className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                        >
                          <option value="contain">Isolate/Contain</option>
                          <option value="lift_containment">Lift Containment</option>
                        </select>
                      )}
                      <div className="flex items-center gap-2 mt-2">
                        <input
                          type="checkbox"
                          id={`stop_on_failure_${index}`}
                          checked={action.stop_on_failure}
                          onChange={(e) => handleUpdateAction(index, { stop_on_failure: e.target.checked })}
                          className="rounded"
                        />
                        <label htmlFor={`stop_on_failure_${index}`} className="text-xs text-muted-foreground">
                          Stop playbook if this action fails
                        </label>
                      </div>
                    </div>
                    <button
                      onClick={() => handleRemoveAction(index)}
                      className="p-1 hover:bg-accent rounded text-red-400"
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          <div className="rounded-lg border bg-background p-6 sticky top-20">
            <h3 className="font-semibold mb-4">Save Playbook</h3>
            <button
              onClick={handleSubmit}
              disabled={isCreating || isUpdating || !formData.name.trim() || formData.actions.length === 0}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md font-medium hover:bg-primary/90 disabled:opacity-50"
            >
              <Save size={16} />
              {isEditing ? 'Update' : 'Create'} Playbook
            </button>
            <p className="text-xs text-muted-foreground mt-2">
              Playbooks are created in draft status. Activate them when ready.
            </p>
          </div>
        </div>
      </div>

      {/* Action Picker Modal */}
      {showActionPicker && (
        <>
          <div
            className="fixed inset-0 bg-black/50 z-40"
            onClick={() => setShowActionPicker(false)}
          />
          <div className="fixed inset-x-4 top-1/2 -translate-y-1/2 max-w-lg mx-auto rounded-lg border bg-background p-6 z-50">
            <h3 className="font-semibold mb-4">Add Action</h3>
            <div className="space-y-2 max-h-96 overflow-auto">
              {actionTypes.map((action) => (
                <button
                  key={action.type}
                  onClick={() => handleAddAction(action.type)}
                  className="w-full text-left p-3 rounded-lg border hover:bg-muted transition-colors"
                >
                  <div className="font-medium text-sm">{action.label}</div>
                  <div className="text-xs text-muted-foreground">{action.description}</div>
                </button>
              ))}
            </div>
            <button
              onClick={() => setShowActionPicker(false)}
              className="w-full mt-4 px-4 py-2 border rounded-md hover:bg-accent"
            >
              Cancel
            </button>
          </div>
        </>
      )}
    </div>
  )
}
