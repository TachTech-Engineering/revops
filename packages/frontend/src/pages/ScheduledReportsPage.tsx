import { useState } from 'react'
import { FileBarChart, Plus, Trash2, Edit2, Play, Check, X, Pause } from 'lucide-react'
import {
  useListScheduledReportsQuery,
  useCreateScheduledReportMutation,
  useUpdateScheduledReportMutation,
  useDeleteScheduledReportMutation,
  useRunScheduledReportMutation,
  ReportFrequency,
} from '../api/pantherApi'
import { cn } from '../lib/utils'

interface ReportFormData {
  name: string
  description: string
  report_type: string
  frequency: ReportFrequency
  recipients: string
  is_active: boolean
}

const reportTypes = [
  { id: 'alert_summary', name: 'Alert Summary', description: 'Summary of alerts by severity and status' },
  { id: 'rule_summary', name: 'Rule Summary', description: 'Summary of rule triggers' },
  { id: 'sla_metrics', name: 'SLA Metrics', description: 'SLA compliance metrics' },
]

const frequencyLabels: Record<ReportFrequency, string> = {
  daily: 'Daily',
  weekly: 'Weekly',
  monthly: 'Monthly',
}

export default function ScheduledReportsPage() {
  const [showForm, setShowForm] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [formData, setFormData] = useState<ReportFormData>({
    name: '',
    description: '',
    report_type: 'alert_summary',
    frequency: 'weekly',
    recipients: '',
    is_active: true,
  })

  const { data: reports, isLoading } = useListScheduledReportsQuery({})
  const [createReport, { isLoading: isCreating }] = useCreateScheduledReportMutation()
  const [updateReport] = useUpdateScheduledReportMutation()
  const [deleteReport] = useDeleteScheduledReportMutation()
  const [runReport, { isLoading: isRunning }] = useRunScheduledReportMutation()

  const handleSubmit = async () => {
    if (!formData.name.trim()) return

    const payload = {
      name: formData.name,
      description: formData.description || undefined,
      report_type: formData.report_type,
      frequency: formData.frequency,
      recipients: formData.recipients.split(',').map(e => e.trim()).filter(Boolean),
      is_active: formData.is_active,
    }

    try {
      if (editingId) {
        await updateReport({ id: editingId, update: payload }).unwrap()
        setEditingId(null)
      } else {
        await createReport(payload).unwrap()
      }

      setFormData({
        name: '',
        description: '',
        report_type: 'alert_summary',
        frequency: 'weekly',
        recipients: '',
        is_active: true,
      })
      setShowForm(false)
    } catch (err) {
      console.error('Failed to save report:', err)
    }
  }

  const handleEdit = (report: NonNullable<typeof reports>[0]) => {
    setFormData({
      name: report.name,
      description: report.description || '',
      report_type: report.report_type,
      frequency: report.frequency,
      recipients: report.recipients.join(', '),
      is_active: report.is_active,
    })
    setEditingId(report.id)
    setShowForm(true)
  }

  const handleToggleActive = async (report: NonNullable<typeof reports>[0]) => {
    await updateReport({ id: report.id, update: { is_active: !report.is_active } })
  }

  const handleDelete = async (id: string) => {
    if (confirm('Are you sure you want to delete this scheduled report?')) {
      await deleteReport(id)
    }
  }

  const handleRunNow = async (id: string) => {
    try {
      const result = await runReport(id).unwrap()
      alert(`Report generated: ${result.filename}\nEmail sent: ${result.email_sent ? 'Yes' : 'No'}`)
    } catch (err) {
      console.error('Failed to run report:', err)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Scheduled Reports</h1>
          <p className="text-muted-foreground">Configure automated report generation and delivery</p>
        </div>
        <button
          onClick={() => {
            setShowForm(true)
            setEditingId(null)
            setFormData({
              name: '',
              description: '',
              report_type: 'alert_summary',
              frequency: 'weekly',
              recipients: '',
              is_active: true,
            })
          }}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md font-medium hover:bg-primary/90"
        >
          <Plus size={18} />
          New Report
        </button>
      </div>

      {/* Form */}
      {showForm && (
        <div className="rounded-lg border bg-background p-6">
          <h3 className="font-semibold mb-4">
            {editingId ? 'Edit Scheduled Report' : 'Create Scheduled Report'}
          </h3>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="block text-sm font-medium mb-1">Name *</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData((p) => ({ ...p, name: e.target.value }))}
                placeholder="Report name"
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
              <label className="block text-sm font-medium mb-1">Report Type</label>
              <select
                value={formData.report_type}
                onChange={(e) => setFormData((p) => ({ ...p, report_type: e.target.value }))}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              >
                {reportTypes.map((type) => (
                  <option key={type.id} value={type.id}>
                    {type.name}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Frequency</label>
              <select
                value={formData.frequency}
                onChange={(e) => setFormData((p) => ({ ...p, frequency: e.target.value as ReportFrequency }))}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              >
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
              </select>
            </div>
            <div className="md:col-span-2">
              <label className="block text-sm font-medium mb-1">Recipients (comma-separated emails)</label>
              <input
                type="text"
                value={formData.recipients}
                onChange={(e) => setFormData((p) => ({ ...p, recipients: e.target.value }))}
                placeholder="email1@example.com, email2@example.com"
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              />
            </div>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="is_active"
                checked={formData.is_active}
                onChange={(e) => setFormData((p) => ({ ...p, is_active: e.target.checked }))}
                className="rounded"
              />
              <label htmlFor="is_active" className="text-sm">Active</label>
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

      {/* Reports List */}
      <div className="rounded-lg border bg-background">
        {isLoading ? (
          <div className="p-6 text-center text-muted-foreground">Loading reports...</div>
        ) : reports?.length === 0 ? (
          <div className="p-12 text-center text-muted-foreground">
            <FileBarChart size={48} className="mx-auto mb-4 opacity-20" />
            <p>No scheduled reports configured</p>
            <p className="text-sm mt-2">Create a report to receive automated summaries</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="px-4 py-3 text-left text-sm font-medium">Name</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Type</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Frequency</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Recipients</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Last Run</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Status</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {reports?.map((report) => (
                <tr key={report.id} className="hover:bg-muted/50">
                  <td className="px-4 py-3">
                    <div className="font-medium">{report.name}</div>
                    {report.description && (
                      <div className="text-sm text-muted-foreground">{report.description}</div>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {reportTypes.find((t) => t.id === report.report_type)?.name || report.report_type}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {frequencyLabels[report.frequency]}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {report.recipients.length > 0 ? (
                      <span title={report.recipients.join(', ')}>
                        {report.recipients.length} recipient{report.recipients.length !== 1 ? 's' : ''}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">None</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {report.last_run_at
                      ? new Date(report.last_run_at).toLocaleString()
                      : <span className="text-muted-foreground">Never</span>
                    }
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => handleToggleActive(report)}
                      className={cn(
                        "px-2 py-1 rounded text-xs font-medium",
                        report.is_active
                          ? "bg-green-500/20 text-green-400"
                          : "bg-gray-500/20 text-gray-400"
                      )}
                    >
                      {report.is_active ? 'Active' : 'Inactive'}
                    </button>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleRunNow(report.id)}
                        disabled={isRunning}
                        className="p-1 hover:bg-accent rounded text-green-400"
                        title="Run Now"
                      >
                        <Play size={16} />
                      </button>
                      <button
                        onClick={() => handleEdit(report)}
                        className="p-1 hover:bg-accent rounded"
                        title="Edit"
                      >
                        <Edit2 size={16} />
                      </button>
                      <button
                        onClick={() => handleDelete(report.id)}
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
