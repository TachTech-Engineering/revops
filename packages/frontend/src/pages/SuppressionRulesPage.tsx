import { useState } from 'react'
import { VolumeX, Plus, Trash2, Edit2, Check, X } from 'lucide-react'
import {
  useListSuppressionRulesQuery,
  useCreateSuppressionRuleMutation,
  useUpdateSuppressionRuleMutation,
  useDeleteSuppressionRuleMutation,
} from '../api/pantherApi'

interface RuleFormData {
  name: string
  description: string
  rule_id: string
  severity: string
  title_pattern: string
  expires_at: string
}

export default function SuppressionRulesPage() {
  const [showForm, setShowForm] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [formData, setFormData] = useState<RuleFormData>({
    name: '',
    description: '',
    rule_id: '',
    severity: '',
    title_pattern: '',
    expires_at: '',
  })

  const { data: rules, isLoading } = useListSuppressionRulesQuery({})
  const [createRule, { isLoading: isCreating }] = useCreateSuppressionRuleMutation()
  const [updateRule] = useUpdateSuppressionRuleMutation()
  const [deleteRule] = useDeleteSuppressionRuleMutation()

  const handleSubmit = async () => {
    if (!formData.name.trim()) return

    const payload = {
      name: formData.name,
      description: formData.description || undefined,
      rule_id: formData.rule_id || undefined,
      severity: formData.severity || undefined,
      title_pattern: formData.title_pattern || undefined,
      expires_at: formData.expires_at || undefined,
    }

    if (editingId) {
      await updateRule({ id: editingId, update: payload })
      setEditingId(null)
    } else {
      await createRule(payload)
    }

    setFormData({
      name: '',
      description: '',
      rule_id: '',
      severity: '',
      title_pattern: '',
      expires_at: '',
    })
    setShowForm(false)
  }

  const handleEdit = (rule: typeof rules extends (infer T)[] | undefined ? T : never) => {
    if (!rule) return
    setFormData({
      name: rule.name,
      description: rule.description || '',
      rule_id: rule.rule_id || '',
      severity: rule.severity || '',
      title_pattern: rule.title_pattern || '',
      expires_at: rule.expires_at ? rule.expires_at.split('T')[0] : '',
    })
    setEditingId(rule.id)
    setShowForm(true)
  }

  const handleToggleActive = async (rule: NonNullable<typeof rules>[0]) => {
    await updateRule({ id: rule.id, update: { is_active: !rule.is_active } })
  }

  const handleDelete = async (id: string) => {
    if (confirm('Are you sure you want to delete this suppression rule?')) {
      await deleteRule(id)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Suppression Rules</h1>
          <p className="text-muted-foreground">Manage rules to suppress noisy alerts</p>
        </div>
        <button
          onClick={() => {
            setShowForm(true)
            setEditingId(null)
            setFormData({
              name: '',
              description: '',
              rule_id: '',
              severity: '',
              title_pattern: '',
              expires_at: '',
            })
          }}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md font-medium hover:bg-primary/90"
        >
          <Plus size={18} />
          New Rule
        </button>
      </div>

      {/* Form */}
      {showForm && (
        <div className="rounded-lg border bg-background p-6">
          <h3 className="font-semibold mb-4">
            {editingId ? 'Edit Suppression Rule' : 'Create Suppression Rule'}
          </h3>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="block text-sm font-medium mb-1">Name *</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData((p) => ({ ...p, name: e.target.value }))}
                placeholder="Rule name"
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Description</label>
              <input
                type="text"
                value={formData.description}
                onChange={(e) => setFormData((p) => ({ ...p, description: e.target.value }))}
                placeholder="Optional description"
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Detection Rule ID</label>
              <input
                type="text"
                value={formData.rule_id}
                onChange={(e) => setFormData((p) => ({ ...p, rule_id: e.target.value }))}
                placeholder="Specific rule ID to suppress"
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Severity</label>
              <select
                value={formData.severity}
                onChange={(e) => setFormData((p) => ({ ...p, severity: e.target.value }))}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              >
                <option value="">Any severity</option>
                <option value="INFO">INFO</option>
                <option value="LOW">LOW</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="HIGH">HIGH</option>
                <option value="CRITICAL">CRITICAL</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Title Pattern (regex)</label>
              <input
                type="text"
                value={formData.title_pattern}
                onChange={(e) => setFormData((p) => ({ ...p, title_pattern: e.target.value }))}
                placeholder="e.g., .*test.*"
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Expires At</label>
              <input
                type="date"
                value={formData.expires_at}
                onChange={(e) => setFormData((p) => ({ ...p, expires_at: e.target.value }))}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              />
            </div>
          </div>
          <div className="flex justify-end gap-2 mt-4">
            <button
              onClick={() => setShowForm(false)}
              className="px-4 py-2 border rounded-md hover:bg-accent"
            >
              Cancel
            </button>
            <button
              onClick={handleSubmit}
              disabled={isCreating || !formData.name.trim()}
              className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md font-medium hover:bg-primary/90 disabled:opacity-50"
            >
              <Check size={16} />
              {editingId ? 'Update' : 'Create'}
            </button>
          </div>
        </div>
      )}

      {/* Rules List */}
      <div className="rounded-lg border bg-background">
        {isLoading ? (
          <div className="p-6 text-center text-muted-foreground">Loading rules...</div>
        ) : rules?.length === 0 ? (
          <div className="p-12 text-center text-muted-foreground">
            <VolumeX size={48} className="mx-auto mb-4 opacity-20" />
            <p>No suppression rules configured</p>
            <p className="text-sm mt-2">Create a rule to suppress noisy alerts</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="px-4 py-3 text-left text-sm font-medium">Name</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Conditions</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Expires</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Status</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {rules?.map((rule) => (
                <tr key={rule.id} className="hover:bg-muted/50">
                  <td className="px-4 py-3">
                    <div className="font-medium">{rule.name}</div>
                    {rule.description && (
                      <div className="text-sm text-muted-foreground">{rule.description}</div>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    <div className="space-y-1">
                      {rule.rule_id && (
                        <div>
                          <span className="text-muted-foreground">Rule:</span> {rule.rule_id}
                        </div>
                      )}
                      {rule.severity && (
                        <div>
                          <span className="text-muted-foreground">Severity:</span> {rule.severity}
                        </div>
                      )}
                      {rule.title_pattern && (
                        <div>
                          <span className="text-muted-foreground">Pattern:</span>{' '}
                          <code className="bg-muted px-1 rounded">{rule.title_pattern}</code>
                        </div>
                      )}
                      {!rule.rule_id && !rule.severity && !rule.title_pattern && (
                        <span className="text-muted-foreground">All alerts</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {rule.expires_at ? new Date(rule.expires_at).toLocaleDateString() : 'Never'}
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => handleToggleActive(rule)}
                      className={`px-2 py-1 rounded text-xs font-medium ${
                        rule.is_active
                          ? 'bg-green-500/20 text-green-400'
                          : 'bg-gray-500/20 text-gray-400'
                      }`}
                    >
                      {rule.is_active ? 'Active' : 'Inactive'}
                    </button>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleEdit(rule)}
                        className="p-1 hover:bg-accent rounded"
                        title="Edit"
                      >
                        <Edit2 size={16} />
                      </button>
                      <button
                        onClick={() => handleDelete(rule.id)}
                        className="p-1 hover:bg-accent rounded text-red-400"
                        title="Delete"
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
