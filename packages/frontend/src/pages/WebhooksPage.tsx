import { useState } from 'react'
import { Webhook, Plus, Trash2, Edit2, Check, X, Play, AlertCircle } from 'lucide-react'
import {
  useListWebhooksQuery,
  useCreateWebhookMutation,
  useUpdateWebhookMutation,
  useDeleteWebhookMutation,
  useTestWebhookMutation,
} from '../api/pantherApi'

interface WebhookFormData {
  name: string
  description: string
  webhook_type: string
  url: string
  severity_filter: string[]
}

const WEBHOOK_TYPES = [
  { value: 'slack', label: 'Slack' },
  { value: 'teams', label: 'Microsoft Teams' },
  { value: 'pagerduty', label: 'PagerDuty' },
  { value: 'generic', label: 'Generic Webhook' },
]

export default function WebhooksPage() {
  const [showForm, setShowForm] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<{ id: string; success: boolean; message: string } | null>(null)
  const [formData, setFormData] = useState<WebhookFormData>({
    name: '',
    description: '',
    webhook_type: 'slack',
    url: '',
    severity_filter: ['CRITICAL', 'HIGH'],
  })

  const { data: webhooks, isLoading } = useListWebhooksQuery()
  const [createWebhook, { isLoading: isCreating }] = useCreateWebhookMutation()
  const [updateWebhook] = useUpdateWebhookMutation()
  const [deleteWebhook] = useDeleteWebhookMutation()
  const [testWebhook, { isLoading: isTesting }] = useTestWebhookMutation()

  const handleSubmit = async () => {
    if (!formData.name.trim() || !formData.url.trim()) return

    const payload = {
      name: formData.name,
      description: formData.description || undefined,
      webhook_type: formData.webhook_type,
      url: formData.url,
      severity_filter: formData.severity_filter,
    }

    if (editingId) {
      await updateWebhook({ id: editingId, update: payload })
      setEditingId(null)
    } else {
      await createWebhook(payload)
    }

    setFormData({
      name: '',
      description: '',
      webhook_type: 'slack',
      url: '',
      severity_filter: ['CRITICAL', 'HIGH'],
    })
    setShowForm(false)
  }

  const handleEdit = (webhook: NonNullable<typeof webhooks>[0]) => {
    setFormData({
      name: webhook.name,
      description: webhook.description || '',
      webhook_type: webhook.webhook_type,
      url: webhook.url,
      severity_filter: webhook.severity_filter,
    })
    setEditingId(webhook.id)
    setShowForm(true)
  }

  const handleToggleActive = async (webhook: NonNullable<typeof webhooks>[0]) => {
    await updateWebhook({ id: webhook.id, update: { is_active: !webhook.is_active } })
  }

  const handleDelete = async (id: string) => {
    if (confirm('Are you sure you want to delete this webhook?')) {
      await deleteWebhook(id)
    }
  }

  const handleTest = async (id: string) => {
    const result = await testWebhook(id).unwrap()
    setTestResult({ id, success: result.success, message: result.message })
    setTimeout(() => setTestResult(null), 5000)
  }

  const toggleSeverity = (severity: string) => {
    setFormData((prev) => ({
      ...prev,
      severity_filter: prev.severity_filter.includes(severity)
        ? prev.severity_filter.filter((s) => s !== severity)
        : [...prev.severity_filter, severity],
    }))
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Webhooks</h1>
          <p className="text-muted-foreground">Configure alert notifications to external services</p>
        </div>
        <button
          onClick={() => {
            setShowForm(true)
            setEditingId(null)
            setFormData({
              name: '',
              description: '',
              webhook_type: 'slack',
              url: '',
              severity_filter: ['CRITICAL', 'HIGH'],
            })
          }}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md font-medium hover:bg-primary/90"
        >
          <Plus size={18} />
          New Webhook
        </button>
      </div>

      {/* Form */}
      {showForm && (
        <div className="rounded-lg border bg-background p-6">
          <h3 className="font-semibold mb-4">
            {editingId ? 'Edit Webhook' : 'Create Webhook'}
          </h3>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="block text-sm font-medium mb-1">Name *</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData((p) => ({ ...p, name: e.target.value }))}
                placeholder="Webhook name"
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Type</label>
              <select
                value={formData.webhook_type}
                onChange={(e) => setFormData((p) => ({ ...p, webhook_type: e.target.value }))}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              >
                {WEBHOOK_TYPES.map((type) => (
                  <option key={type.value} value={type.value}>
                    {type.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="md:col-span-2">
              <label className="block text-sm font-medium mb-1">URL *</label>
              <input
                type="url"
                value={formData.url}
                onChange={(e) => setFormData((p) => ({ ...p, url: e.target.value }))}
                placeholder="https://hooks.slack.com/services/..."
                className="w-full rounded-md border bg-background px-3 py-2 text-sm font-mono"
              />
            </div>
            <div className="md:col-span-2">
              <label className="block text-sm font-medium mb-1">Description</label>
              <input
                type="text"
                value={formData.description}
                onChange={(e) => setFormData((p) => ({ ...p, description: e.target.value }))}
                placeholder="Optional description"
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              />
            </div>
            <div className="md:col-span-2">
              <label className="block text-sm font-medium mb-2">Severity Filter</label>
              <div className="flex flex-wrap gap-2">
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((severity) => (
                  <button
                    key={severity}
                    type="button"
                    onClick={() => toggleSeverity(severity)}
                    className={`px-3 py-1 rounded text-sm ${
                      formData.severity_filter.includes(severity)
                        ? severity === 'CRITICAL'
                          ? 'bg-red-500/20 text-red-400 border border-red-500'
                          : severity === 'HIGH'
                          ? 'bg-orange-500/20 text-orange-400 border border-orange-500'
                          : severity === 'MEDIUM'
                          ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500'
                          : severity === 'LOW'
                          ? 'bg-green-500/20 text-green-400 border border-green-500'
                          : 'bg-blue-500/20 text-blue-400 border border-blue-500'
                        : 'bg-muted hover:bg-accent'
                    }`}
                  >
                    {severity}
                  </button>
                ))}
              </div>
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
              disabled={isCreating || !formData.name.trim() || !formData.url.trim()}
              className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md font-medium hover:bg-primary/90 disabled:opacity-50"
            >
              <Check size={16} />
              {editingId ? 'Update' : 'Create'}
            </button>
          </div>
        </div>
      )}

      {/* Webhooks List */}
      <div className="rounded-lg border bg-background">
        {isLoading ? (
          <div className="p-6 text-center text-muted-foreground">Loading webhooks...</div>
        ) : webhooks?.length === 0 ? (
          <div className="p-12 text-center text-muted-foreground">
            <Webhook size={48} className="mx-auto mb-4 opacity-20" />
            <p>No webhooks configured</p>
            <p className="text-sm mt-2">Create a webhook to send alerts to Slack, Teams, or other services</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="px-4 py-3 text-left text-sm font-medium">Name</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Type</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Severities</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Status</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {webhooks?.map((webhook) => (
                <tr key={webhook.id} className="hover:bg-muted/50">
                  <td className="px-4 py-3">
                    <div className="font-medium">{webhook.name}</div>
                    {webhook.description && (
                      <div className="text-sm text-muted-foreground">{webhook.description}</div>
                    )}
                    <div className="text-xs text-muted-foreground font-mono truncate max-w-xs">
                      {webhook.url}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-1 bg-muted rounded text-xs">
                      {WEBHOOK_TYPES.find((t) => t.value === webhook.webhook_type)?.label || webhook.webhook_type}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {webhook.severity_filter.map((sev) => (
                        <span
                          key={sev}
                          className={`px-1.5 py-0.5 rounded text-xs ${
                            sev === 'CRITICAL'
                              ? 'bg-red-500/20 text-red-400'
                              : sev === 'HIGH'
                              ? 'bg-orange-500/20 text-orange-400'
                              : sev === 'MEDIUM'
                              ? 'bg-yellow-500/20 text-yellow-400'
                              : sev === 'LOW'
                              ? 'bg-green-500/20 text-green-400'
                              : 'bg-blue-500/20 text-blue-400'
                          }`}
                        >
                          {sev}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => handleToggleActive(webhook)}
                      className={`px-2 py-1 rounded text-xs font-medium ${
                        webhook.is_active
                          ? 'bg-green-500/20 text-green-400'
                          : 'bg-gray-500/20 text-gray-400'
                      }`}
                    >
                      {webhook.is_active ? 'Active' : 'Inactive'}
                    </button>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleTest(webhook.id)}
                        disabled={isTesting}
                        className="p-1 hover:bg-accent rounded"
                        title="Test webhook"
                      >
                        <Play size={16} />
                      </button>
                      <button
                        onClick={() => handleEdit(webhook)}
                        className="p-1 hover:bg-accent rounded"
                        title="Edit"
                      >
                        <Edit2 size={16} />
                      </button>
                      <button
                        onClick={() => handleDelete(webhook.id)}
                        className="p-1 hover:bg-accent rounded text-red-400"
                        title="Delete"
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                    {testResult?.id === webhook.id && (
                      <div
                        className={`mt-2 text-xs flex items-center gap-1 ${
                          testResult.success ? 'text-green-400' : 'text-red-400'
                        }`}
                      >
                        {testResult.success ? <Check size={12} /> : <AlertCircle size={12} />}
                        {testResult.message}
                      </div>
                    )}
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
