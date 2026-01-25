import { useState } from 'react'
import {
  useListCorrelationRulesQuery,
  useCreateCorrelationRuleMutation,
  useUpdateCorrelationRuleMutation,
  useDeleteCorrelationRuleMutation,
  type CorrelationRuleResponse,
  type CorrelationRuleCreate,
  type CorrelationConditions,
} from '../api/pantherApi'

export default function CorrelationRulesPage() {
  const [showActiveOnly, setShowActiveOnly] = useState(false)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [editingRule, setEditingRule] = useState<CorrelationRuleResponse | null>(null)

  const { data: rules, isLoading, error } = useListCorrelationRulesQuery({
    activeOnly: showActiveOnly,
  })

  const [createRule] = useCreateCorrelationRuleMutation()
  const [updateRule] = useUpdateCorrelationRuleMutation()
  const [deleteRule] = useDeleteCorrelationRuleMutation()

  const handleCreate = async (ruleData: CorrelationRuleCreate) => {
    try {
      await createRule(ruleData).unwrap()
      setShowCreateModal(false)
    } catch (err) {
      console.error('Failed to create correlation rule:', err)
    }
  }

  const handleUpdate = async (id: string, update: Partial<CorrelationRuleCreate>) => {
    try {
      await updateRule({ id, update }).unwrap()
      setEditingRule(null)
    } catch (err) {
      console.error('Failed to update correlation rule:', err)
    }
  }

  const handleToggleActive = async (rule: CorrelationRuleResponse) => {
    try {
      await updateRule({
        id: rule.id,
        update: { is_active: !rule.is_active },
      }).unwrap()
    } catch (err) {
      console.error('Failed to toggle rule:', err)
    }
  }

  const handleDelete = async (id: string) => {
    if (confirm('Are you sure you want to delete this correlation rule?')) {
      try {
        await deleteRule(id).unwrap()
      } catch (err) {
        console.error('Failed to delete correlation rule:', err)
      }
    }
  }

  if (error) {
    return (
      <div className="p-4">
        <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4 text-destructive">
          Failed to load correlation rules
        </div>
      </div>
    )
  }

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Correlation Rules</h1>
          <p className="text-muted-foreground mt-1">
            Define rules to automatically correlate alerts and create incidents
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors"
        >
          Create Rule
        </button>
      </div>

      {/* Filter */}
      <div className="mb-6">
        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          <input
            type="checkbox"
            checked={showActiveOnly}
            onChange={(e) => setShowActiveOnly(e.target.checked)}
            className="rounded border-border bg-background text-primary focus:ring-primary"
          />
          Show active rules only
        </label>
      </div>

      {/* Rules List */}
      {isLoading ? (
        <div className="flex justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      ) : (
        <div className="space-y-4">
          {rules?.map((rule) => (
            <div key={rule.id} className="bg-card border border-border rounded-lg shadow-sm p-6">
              <div className="flex justify-between items-start">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="text-lg font-semibold text-foreground">{rule.name}</h3>
                    <span
                      className={`px-2 py-0.5 text-xs font-medium rounded-full ${
                        rule.is_active
                          ? 'bg-green-500/20 text-green-400'
                          : 'bg-muted text-muted-foreground'
                      }`}
                    >
                      {rule.is_active ? 'Active' : 'Inactive'}
                    </span>
                    {rule.auto_create_incident && (
                      <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-blue-500/20 text-blue-400">
                        Auto-create incident
                      </span>
                    )}
                  </div>
                  {rule.description && (
                    <p className="text-muted-foreground mb-4">{rule.description}</p>
                  )}

                  {/* Conditions */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div>
                      <span className="text-muted-foreground">Time Window:</span>
                      <span className="ml-2 font-medium text-foreground">
                        {rule.conditions.time_window_minutes} min
                      </span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Min Alerts:</span>
                      <span className="ml-2 font-medium text-foreground">{rule.conditions.min_alerts}</span>
                    </div>
                    {rule.conditions.field_matches && rule.conditions.field_matches.length > 0 && (
                      <div>
                        <span className="text-muted-foreground">Match Fields:</span>
                        <span className="ml-2 font-medium text-foreground">
                          {rule.conditions.field_matches.join(', ')}
                        </span>
                      </div>
                    )}
                    {rule.conditions.severity_filter && rule.conditions.severity_filter.length > 0 && (
                      <div>
                        <span className="text-muted-foreground">Severities:</span>
                        <span className="ml-2 font-medium text-foreground">
                          {rule.conditions.severity_filter.join(', ')}
                        </span>
                      </div>
                    )}
                  </div>

                  <p className="text-xs text-muted-foreground mt-4">
                    Created by {rule.created_by} on {new Date(rule.created_at).toLocaleDateString()}
                  </p>
                </div>

                <div className="flex items-center gap-2 ml-4">
                  <button
                    onClick={() => handleToggleActive(rule)}
                    className={`px-3 py-1.5 text-sm rounded border transition-colors ${
                      rule.is_active
                        ? 'border-border text-muted-foreground hover:bg-muted'
                        : 'border-green-500/50 text-green-400 hover:bg-green-500/10'
                    }`}
                  >
                    {rule.is_active ? 'Disable' : 'Enable'}
                  </button>
                  <button
                    onClick={() => setEditingRule(rule)}
                    className="px-3 py-1.5 text-sm border border-border rounded text-muted-foreground hover:bg-muted transition-colors"
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => handleDelete(rule.id)}
                    className="px-3 py-1.5 text-sm border border-destructive/50 rounded text-destructive hover:bg-destructive/10 transition-colors"
                  >
                    Delete
                  </button>
                </div>
              </div>
            </div>
          ))}
          {rules?.length === 0 && (
            <div className="bg-card border border-border rounded-lg shadow-sm p-12 text-center text-muted-foreground">
              No correlation rules found. Create one to start automatically grouping related alerts.
            </div>
          )}
        </div>
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <CorrelationRuleModal
          onClose={() => setShowCreateModal(false)}
          onSave={handleCreate}
        />
      )}

      {/* Edit Modal */}
      {editingRule && (
        <CorrelationRuleModal
          rule={editingRule}
          onClose={() => setEditingRule(null)}
          onSave={(data) => handleUpdate(editingRule.id, data)}
        />
      )}
    </div>
  )
}

function CorrelationRuleModal({
  rule,
  onClose,
  onSave,
}: {
  rule?: CorrelationRuleResponse
  onClose: () => void
  onSave: (data: CorrelationRuleCreate) => void
}) {
  const [name, setName] = useState(rule?.name || '')
  const [description, setDescription] = useState(rule?.description || '')
  const [timeWindow, setTimeWindow] = useState(rule?.conditions.time_window_minutes || 60)
  const [minAlerts, setMinAlerts] = useState(rule?.conditions.min_alerts || 2)
  const [fieldMatches, setFieldMatches] = useState(
    rule?.conditions.field_matches?.join(', ') || ''
  )
  const [severityFilter, setSeverityFilter] = useState(
    rule?.conditions.severity_filter?.join(', ') || ''
  )
  const [ruleIdFilter, setRuleIdFilter] = useState(
    rule?.conditions.rule_id_filter?.join(', ') || ''
  )
  const [isActive, setIsActive] = useState(rule?.is_active ?? true)
  const [autoCreateIncident, setAutoCreateIncident] = useState(rule?.auto_create_incident ?? false)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    const conditions: CorrelationConditions = {
      time_window_minutes: timeWindow,
      min_alerts: minAlerts,
    }

    if (fieldMatches.trim()) {
      conditions.field_matches = fieldMatches.split(',').map((f) => f.trim())
    }
    if (severityFilter.trim()) {
      conditions.severity_filter = severityFilter.split(',').map((s) => s.trim())
    }
    if (ruleIdFilter.trim()) {
      conditions.rule_id_filter = ruleIdFilter.split(',').map((r) => r.trim())
    }

    onSave({
      name,
      description: description || undefined,
      conditions,
      is_active: isActive,
      auto_create_incident: autoCreateIncident,
    })
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-card border border-border rounded-lg shadow-xl w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex justify-between items-center px-6 py-4 border-b border-border sticky top-0 bg-card">
          <h2 className="text-lg font-semibold text-foreground">
            {rule ? 'Edit Correlation Rule' : 'Create Correlation Rule'}
          </h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M6 18L18 6M6 6l12 12"
              />
            </svg>
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-6">
          {/* Basic Info */}
          <div className="space-y-4">
            <h3 className="font-medium text-foreground">Basic Information</h3>

            <div>
              <label className="block text-sm font-medium text-foreground mb-1">Name *</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
                placeholder="Enter rule name"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-foreground mb-1">Description</label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={2}
                className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
                placeholder="Enter rule description"
              />
            </div>
          </div>

          {/* Conditions */}
          <div className="space-y-4">
            <h3 className="font-medium text-foreground">Correlation Conditions</h3>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-foreground mb-1">
                  Time Window (minutes) *
                </label>
                <input
                  type="number"
                  value={timeWindow}
                  onChange={(e) => setTimeWindow(parseInt(e.target.value) || 60)}
                  min={1}
                  required
                  className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Alerts within this time window will be correlated
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-foreground mb-1">
                  Minimum Alerts *
                </label>
                <input
                  type="number"
                  value={minAlerts}
                  onChange={(e) => setMinAlerts(parseInt(e.target.value) || 2)}
                  min={2}
                  required
                  className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Minimum number of alerts to trigger correlation
                </p>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-foreground mb-1">
                Field Matches
              </label>
              <input
                type="text"
                value={fieldMatches}
                onChange={(e) => setFieldMatches(e.target.value)}
                className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
                placeholder="e.g., source_ip, destination_ip, user"
              />
              <p className="text-xs text-muted-foreground mt-1">
                Comma-separated field names that must match across alerts
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-foreground mb-1">
                Severity Filter
              </label>
              <input
                type="text"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
                placeholder="e.g., HIGH, CRITICAL"
              />
              <p className="text-xs text-muted-foreground mt-1">
                Only correlate alerts with these severities (comma-separated)
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-foreground mb-1">
                Rule ID Filter
              </label>
              <input
                type="text"
                value={ruleIdFilter}
                onChange={(e) => setRuleIdFilter(e.target.value)}
                className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
                placeholder="e.g., rule-123, rule-456"
              />
              <p className="text-xs text-muted-foreground mt-1">
                Only correlate alerts from these rules (comma-separated)
              </p>
            </div>
          </div>

          {/* Options */}
          <div className="space-y-4">
            <h3 className="font-medium text-foreground">Options</h3>

            <div className="space-y-3">
              <label className="flex items-center gap-3">
                <input
                  type="checkbox"
                  checked={isActive}
                  onChange={(e) => setIsActive(e.target.checked)}
                  className="rounded border-border bg-background text-primary focus:ring-primary"
                />
                <span className="text-sm text-foreground">Rule is active</span>
              </label>

              <label className="flex items-center gap-3">
                <input
                  type="checkbox"
                  checked={autoCreateIncident}
                  onChange={(e) => setAutoCreateIncident(e.target.checked)}
                  className="rounded border-border bg-background text-primary focus:ring-primary"
                />
                <span className="text-sm text-foreground">
                  Automatically create incident when correlation is triggered
                </span>
              </label>
            </div>
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t border-border">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 border border-border rounded-lg text-foreground hover:bg-muted transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!name}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50 transition-colors"
            >
              {rule ? 'Save Changes' : 'Create Rule'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
