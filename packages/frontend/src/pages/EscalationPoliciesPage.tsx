import { useState } from 'react'
import {
  Bell,
  Plus,
  Trash2,
  ChevronDown,
  ChevronUp,
  Clock,
  Mail,
  MessageSquare,
  Webhook,
  Phone,
  Users,
} from 'lucide-react'
import {
  useListEscalationPoliciesQuery,
  useCreateEscalationPolicyMutation,
  useUpdateEscalationPolicyMutation,
  useDeleteEscalationPolicyMutation,
  useListActiveEscalationsQuery,
  useAddEscalationStepMutation,
  EscalationPolicyCreate,
  EscalationStepCreate,
} from '../api/pantherApi'
import { cn } from '../lib/utils'
import { getApiErrorMessage } from '../lib/apiError'
import { useToast } from '../components/common/Toast'

const notificationIcons: Record<string, React.ElementType> = {
  email: Mail,
  slack: MessageSquare,
  pagerduty: Phone,
  teams: Users,
  webhook: Webhook,
  phone_call: Phone,
  sms: MessageSquare,
}

export default function EscalationPoliciesPage() {
  const toast = useToast()
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [expandedPolicy, setExpandedPolicy] = useState<string | null>(null)

  const { data: policies, isLoading } = useListEscalationPoliciesQuery({})
  const { data: activeEscalations } = useListActiveEscalationsQuery()
  const [createPolicy, { isLoading: isCreating }] = useCreateEscalationPolicyMutation()
  const [updatePolicy] = useUpdateEscalationPolicyMutation()
  const [deletePolicy] = useDeleteEscalationPolicyMutation()
  const [addStep] = useAddEscalationStepMutation()

  const [newPolicy, setNewPolicy] = useState<EscalationPolicyCreate & { severity_filter: string[]; steps: EscalationStepCreate[] }>({
    name: '',
    description: '',
    severity_filter: [],
    rule_filter: [],
    is_active: true,
    steps: [],
    call_message_template: 'Alert from {source}: {title}. Severity: {severity}. {description}',
    sms_message_template: '[{source}] {severity} Alert: {title}. ID: {id}',
  })

  const [newStep, setNewStep] = useState<EscalationStepCreate>({
    step_order: 1,
    delay_minutes: 15,
    notification_type: 'email',
    targets: [''],
  })

  const handleCreate = async () => {
    try {
      await createPolicy(newPolicy).unwrap()
      setShowCreateModal(false)
      setNewPolicy({
        name: '',
        description: '',
        severity_filter: [],
        rule_filter: [],
        is_active: true,
        steps: [],
        call_message_template: 'Alert from {source}: {title}. Severity: {severity}. {description}',
        sms_message_template: '[{source}] {severity} Alert: {title}. ID: {id}',
      })
      toast.success('Escalation policy created.')
    } catch (err) {
      // The modal stays open on failure so the entered policy is not lost.
      console.error('Failed to create policy:', err)
      toast.error(`Could not create the policy. ${getApiErrorMessage(err)}`)
    }
  }

  const handleToggleActive = async (policyId: string, isActive: boolean) => {
    try {
      await updatePolicy({ id: policyId, update: { is_active: !isActive } }).unwrap()
      toast.success(isActive ? 'Policy disabled.' : 'Policy enabled.')
    } catch (err) {
      console.error('Failed to toggle policy:', err)
      toast.error(
        `Could not ${isActive ? 'disable' : 'enable'} the policy. ${getApiErrorMessage(err)}`
      )
    }
  }

  const handleDelete = async (policyId: string) => {
    if (!confirm('Are you sure you want to delete this policy?')) return
    try {
      await deletePolicy(policyId).unwrap()
      toast.success('Policy deleted.')
    } catch (err) {
      console.error('Failed to delete policy:', err)
      toast.error(`Could not delete the policy. ${getApiErrorMessage(err)}`)
    }
  }

  const handleAddStep = async (policyId: string) => {
    try {
      const policy = policies?.find((p) => p.id === policyId)
      await addStep({
        policyId,
        step: {
          ...newStep,
          step_order: (policy?.steps?.length || 0) + 1,
        },
      }).unwrap()
      setNewStep({
        step_order: 1,
        delay_minutes: 15,
        notification_type: 'email',
        targets: [''],
      })
      toast.success('Escalation step added.')
    } catch (err) {
      console.error('Failed to add step:', err)
      toast.error(`Could not add the escalation step. ${getApiErrorMessage(err)}`)
    }
  }

  const addStepToNewPolicy = () => {
    setNewPolicy((prev) => ({
      ...prev,
      steps: [
        ...prev.steps,
        {
          ...newStep,
          step_order: prev.steps.length + 1,
        },
      ],
    }))
    setNewStep({
      step_order: 1,
      delay_minutes: 15,
      notification_type: 'email',
      targets: [''],
    })
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Bell className="text-primary" />
            Escalation Policies
          </h1>
          <p className="text-muted-foreground mt-1">
            Configure time-based escalation chains for unacknowledged alerts
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
        >
          <Plus size={16} />
          Create Policy
        </button>
      </div>

      {/* Active Escalations Summary */}
      {activeEscalations && activeEscalations.length > 0 && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
          <h3 className="font-medium text-red-400 flex items-center gap-2">
            <Bell size={16} />
            {activeEscalations.length} Active Escalation{activeEscalations.length > 1 ? 's' : ''}
          </h3>
          <p className="text-sm text-muted-foreground mt-1">
            There are alerts currently being escalated. Review them in the alerts page.
          </p>
        </div>
      )}

      {/* Policies List */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
        </div>
      ) : !policies?.length ? (
        <div className="text-center py-12 bg-card rounded-lg border">
          <Bell className="mx-auto text-muted-foreground mb-4" size={48} />
          <h3 className="text-lg font-medium">No escalation policies</h3>
          <p className="text-muted-foreground mt-1">
            Create your first policy to start escalating unacknowledged alerts
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {policies.map((policy) => (
            <div key={policy.id} className="bg-card rounded-lg border">
              <div
                className="flex items-center justify-between p-4 cursor-pointer"
                onClick={() => setExpandedPolicy(expandedPolicy === policy.id ? null : policy.id)}
              >
                <div className="flex items-center gap-4">
                  <div
                    className={cn(
                      'w-3 h-3 rounded-full',
                      policy.is_active ? 'bg-green-500' : 'bg-gray-500'
                    )}
                  />
                  <div>
                    <h3 className="font-medium">{policy.name}</h3>
                    <p className="text-sm text-muted-foreground">
                      {policy.steps?.length || 0} steps
                      {policy.severity_filter?.length > 0 &&
                        ` | Severities: ${policy.severity_filter.join(', ')}`}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      handleToggleActive(policy.id, policy.is_active)
                    }}
                    className={cn(
                      'px-3 py-1 rounded text-sm',
                      policy.is_active
                        ? 'bg-green-500/20 text-green-400'
                        : 'bg-gray-500/20 text-gray-400'
                    )}
                  >
                    {policy.is_active ? 'Active' : 'Inactive'}
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      handleDelete(policy.id)
                    }}
                    className="p-2 hover:bg-destructive/20 rounded text-destructive"
                  >
                    <Trash2 size={16} />
                  </button>
                  {expandedPolicy === policy.id ? (
                    <ChevronUp size={20} />
                  ) : (
                    <ChevronDown size={20} />
                  )}
                </div>
              </div>

              {expandedPolicy === policy.id && (
                <div className="border-t p-4 space-y-4">
                  {policy.description && (
                    <p className="text-sm text-muted-foreground">{policy.description}</p>
                  )}

                  {/* Message Templates */}
                  {(policy.call_message_template || policy.sms_message_template) && (
                    <div className="bg-accent/50 rounded-lg p-3 space-y-2">
                      <h4 className="font-medium text-sm flex items-center gap-2">
                        <MessageSquare size={14} />
                        Message Templates
                      </h4>
                      {policy.call_message_template && (
                        <div>
                          <span className="text-xs text-muted-foreground">Voice Call:</span>
                          <p className="text-sm font-mono bg-background/50 p-2 rounded mt-1">
                            {policy.call_message_template}
                          </p>
                        </div>
                      )}
                      {policy.sms_message_template && (
                        <div>
                          <span className="text-xs text-muted-foreground">SMS:</span>
                          <p className="text-sm font-mono bg-background/50 p-2 rounded mt-1">
                            {policy.sms_message_template}
                          </p>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Steps Timeline */}
                  <div className="space-y-3">
                    <h4 className="font-medium text-sm">Escalation Steps</h4>
                    {policy.steps?.map((step, index) => {
                      const Icon = notificationIcons[step.notification_type] || Bell
                      return (
                        <div key={step.id} className="flex items-start gap-4 pl-4">
                          <div className="flex flex-col items-center">
                            <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center">
                              <Icon size={16} className="text-primary" />
                            </div>
                            {index < (policy.steps?.length || 0) - 1 && (
                              <div className="w-0.5 h-8 bg-border mt-2" />
                            )}
                          </div>
                          <div className="flex-1">
                            <div className="flex items-center gap-2">
                              <span className="font-medium">Step {step.step_order}</span>
                              <span className="text-xs text-muted-foreground flex items-center gap-1">
                                <Clock size={12} />
                                After {step.delay_minutes} min
                              </span>
                            </div>
                            <p className="text-sm text-muted-foreground mt-1">
                              {step.notification_type.charAt(0).toUpperCase() +
                                step.notification_type.slice(1)}{' '}
                              to: {step.targets?.join(', ') || 'On-call'}
                            </p>
                          </div>
                        </div>
                      )
                    })}
                  </div>

                  {/* Add Step Form */}
                  <div className="border-t pt-4">
                    <h4 className="font-medium text-sm mb-3">Add New Step</h4>
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                      <div>
                        <label className="text-xs text-muted-foreground">Delay (minutes)</label>
                        <input
                          type="number"
                          value={newStep.delay_minutes}
                          onChange={(e) =>
                            setNewStep({ ...newStep, delay_minutes: parseInt(e.target.value) })
                          }
                          className="w-full px-3 py-2 bg-background border rounded-md"
                        />
                      </div>
                      <div>
                        <label className="text-xs text-muted-foreground">Notification Type</label>
                        <select
                          value={newStep.notification_type}
                          onChange={(e) =>
                            setNewStep({ ...newStep, notification_type: e.target.value })
                          }
                          className="w-full px-3 py-2 bg-background border rounded-md"
                        >
                          <option value="email">Email</option>
                          <option value="phone_call">Phone Call</option>
                          <option value="sms">SMS</option>
                          <option value="slack">Slack</option>
                          <option value="pagerduty">PagerDuty</option>
                          <option value="teams">Teams</option>
                          <option value="webhook">Webhook</option>
                        </select>
                      </div>
                      <div>
                        <label className="text-xs text-muted-foreground">Target</label>
                        <input
                          type="text"
                          value={newStep.targets[0]}
                          onChange={(e) => setNewStep({ ...newStep, targets: [e.target.value] })}
                          placeholder={
                            newStep.notification_type === 'phone_call' || newStep.notification_type === 'sms'
                              ? '+1234567890'
                              : 'email@example.com'
                          }
                          className="w-full px-3 py-2 bg-background border rounded-md"
                        />
                      </div>
                      <div className="flex items-end">
                        <button
                          onClick={() => handleAddStep(policy.id)}
                          className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
                        >
                          Add Step
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Create Policy Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
            <h2 className="text-lg font-semibold mb-4">Create Escalation Policy</h2>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Policy Name</label>
                <input
                  type="text"
                  value={newPolicy.name}
                  onChange={(e) => setNewPolicy({ ...newPolicy, name: e.target.value })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                  placeholder="Critical Alert Escalation"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">Description</label>
                <textarea
                  value={newPolicy.description || ''}
                  onChange={(e) => setNewPolicy({ ...newPolicy, description: e.target.value })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                  rows={2}
                  placeholder="Escalate critical alerts if not acknowledged..."
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">Severity Filter</label>
                <div className="flex flex-wrap gap-2">
                  {['critical', 'high', 'medium', 'low'].map((sev) => (
                    <label key={sev} className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={newPolicy.severity_filter.includes(sev)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setNewPolicy({
                              ...newPolicy,
                              severity_filter: [...newPolicy.severity_filter, sev],
                            })
                          } else {
                            setNewPolicy({
                              ...newPolicy,
                              severity_filter: newPolicy.severity_filter.filter((s) => s !== sev),
                            })
                          }
                        }}
                        className="rounded"
                      />
                      <span className="text-sm capitalize">{sev}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Message Templates */}
              <div className="border-t pt-4 mt-4">
                <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                  <MessageSquare size={16} />
                  Custom Message Templates
                </h4>
                <p className="text-xs text-muted-foreground mb-3">
                  Use placeholders: {'{title}'}, {'{severity}'}, {'{id}'}, {'{description}'}, {'{rule}'}, {'{time}'}, {'{source}'}
                </p>

                <div className="space-y-3">
                  <div>
                    <label className="block text-xs text-muted-foreground mb-1">
                      Voice Call Message
                    </label>
                    <textarea
                      value={newPolicy.call_message_template || ''}
                      onChange={(e) => setNewPolicy({ ...newPolicy, call_message_template: e.target.value })}
                      className="w-full px-3 py-2 bg-background border rounded-md text-sm font-mono"
                      rows={2}
                      placeholder="Alert from {source}: {title}. Severity: {severity}. {description}"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-muted-foreground mb-1">
                      SMS Message
                    </label>
                    <textarea
                      value={newPolicy.sms_message_template || ''}
                      onChange={(e) => setNewPolicy({ ...newPolicy, sms_message_template: e.target.value })}
                      className="w-full px-3 py-2 bg-background border rounded-md text-sm font-mono"
                      rows={2}
                      placeholder="[{source}] {severity} Alert: {title}. ID: {id}"
                    />
                  </div>
                </div>
              </div>

              {/* Steps */}
              <div>
                <label className="block text-sm font-medium mb-2">Escalation Steps</label>
                {newPolicy.steps.length > 0 && (
                  <div className="space-y-2 mb-3">
                    {newPolicy.steps.map((step, index) => (
                      <div
                        key={index}
                        className="flex items-center justify-between p-2 bg-accent rounded"
                      >
                        <span className="text-sm">
                          Step {index + 1}: {step.notification_type} after {step.delay_minutes}min
                          to {step.targets.join(', ')}
                        </span>
                        <button
                          onClick={() =>
                            setNewPolicy({
                              ...newPolicy,
                              steps: newPolicy.steps.filter((_, i) => i !== index),
                            })
                          }
                          className="text-destructive hover:text-destructive/80"
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
                  <input
                    type="number"
                    value={newStep.delay_minutes}
                    onChange={(e) =>
                      setNewStep({ ...newStep, delay_minutes: parseInt(e.target.value) })
                    }
                    placeholder="Delay (min)"
                    className="px-3 py-2 bg-background border rounded-md"
                  />
                  <select
                    value={newStep.notification_type}
                    onChange={(e) =>
                      setNewStep({ ...newStep, notification_type: e.target.value })
                    }
                    className="px-3 py-2 bg-background border rounded-md"
                  >
                    <option value="email">Email</option>
                    <option value="phone_call">Phone Call</option>
                    <option value="sms">SMS</option>
                    <option value="slack">Slack</option>
                    <option value="pagerduty">PagerDuty</option>
                    <option value="teams">Teams</option>
                    <option value="webhook">Webhook</option>
                  </select>
                  <input
                    type="text"
                    value={newStep.targets[0]}
                    onChange={(e) => setNewStep({ ...newStep, targets: [e.target.value] })}
                    placeholder={
                      newStep.notification_type === 'phone_call' || newStep.notification_type === 'sms'
                        ? '+1234567890'
                        : 'Target'
                    }
                    className="px-3 py-2 bg-background border rounded-md"
                  />
                  <button
                    onClick={addStepToNewPolicy}
                    className="px-3 py-2 border rounded-md hover:bg-accent"
                  >
                    Add Step
                  </button>
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => setShowCreateModal(false)}
                className="px-4 py-2 border rounded-md hover:bg-accent"
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                disabled={isCreating || !newPolicy.name}
                className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
              >
                {isCreating ? 'Creating...' : 'Create Policy'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
