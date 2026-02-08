import { useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  useGetIncidentQuery,
  useUpdateIncidentMutation,
  useDeleteIncidentMutation,
  useRemoveAlertFromIncidentMutation,
  useListAlertsQuery,
  type IncidentStatus,
  type IncidentSeverity,
  type IncidentUpdate,
} from '../api/pantherApi'

const statusColors: Record<IncidentStatus, string> = {
  open: 'bg-red-500/20 text-red-400',
  investigating: 'bg-yellow-500/20 text-yellow-400',
  contained: 'bg-blue-500/20 text-blue-400',
  resolved: 'bg-green-500/20 text-green-400',
  closed: 'bg-muted text-muted-foreground',
}

const severityColors: Record<IncidentSeverity, string> = {
  low: 'bg-muted text-muted-foreground',
  medium: 'bg-yellow-500/20 text-yellow-400',
  high: 'bg-orange-500/20 text-orange-400',
  critical: 'bg-red-500/20 text-red-400',
}

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [isEditing, setIsEditing] = useState(false)

  const { data: incident, isLoading, error } = useGetIncidentQuery(id!)
  const [updateIncident] = useUpdateIncidentMutation()
  const [deleteIncident] = useDeleteIncidentMutation()
  const [removeAlert] = useRemoveAlertFromIncidentMutation()

  // Fetch alert details for the incident's alerts
  const { data: alertsData } = useListAlertsQuery(
    { alertIds: incident?.alert_ids?.join(',') },
    { skip: !incident?.alert_ids?.length }
  )

  const handleUpdate = async (update: IncidentUpdate) => {
    try {
      await updateIncident({ id: id!, update }).unwrap()
      setIsEditing(false)
    } catch (err) {
      console.error('Failed to update incident:', err)
    }
  }

  const handleDelete = async () => {
    if (confirm('Are you sure you want to delete this incident?')) {
      try {
        await deleteIncident(id!).unwrap()
        navigate('/incidents')
      } catch (err) {
        console.error('Failed to delete incident:', err)
      }
    }
  }

  const handleRemoveAlert = async (alertId: string) => {
    try {
      await removeAlert({ incidentId: id!, alertId }).unwrap()
    } catch (err) {
      console.error('Failed to remove alert:', err)
    }
  }

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  if (error || !incident) {
    return (
      <div className="p-6">
        <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4 text-destructive">
          Failed to load incident
        </div>
      </div>
    )
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex justify-between items-start mb-6">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Link to="/incidents" className="text-primary hover:text-primary/80">
              Incidents
            </Link>
            <span className="text-muted-foreground">/</span>
            <span className="text-muted-foreground">{incident.id.slice(0, 8)}</span>
          </div>
          <h1 className="text-2xl font-bold text-foreground">{incident.title}</h1>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setIsEditing(true)}
            className="px-4 py-2 border border-border rounded-lg text-foreground hover:bg-muted transition-colors"
          >
            Edit
          </button>
          <button
            onClick={handleDelete}
            className="px-4 py-2 bg-destructive text-destructive-foreground rounded-lg hover:bg-destructive/90 transition-colors"
          >
            Delete
          </button>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Main Content */}
        <div className="col-span-2 space-y-6">
          {/* Description */}
          <div className="bg-card border border-border rounded-lg p-6">
            <h2 className="text-lg font-semibold text-foreground mb-4">Description</h2>
            <p className="text-muted-foreground whitespace-pre-wrap">
              {incident.description || 'No description provided'}
            </p>
          </div>

          {/* Alerts */}
          <div className="bg-card border border-border rounded-lg p-6">
            <h2 className="text-lg font-semibold text-foreground mb-4">
              Associated Alerts ({incident.alert_count})
            </h2>
            {incident.alert_ids.length > 0 ? (
              <div className="space-y-3">
                {incident.alert_ids.map((alertId) => {
                  const alert = alertsData?.items?.find(a => a.id === alertId)
                  return (
                    <div
                      key={alertId}
                      className="flex justify-between items-center p-3 bg-muted/50 rounded-lg"
                    >
                      <div>
                        <Link
                          to={`/alerts/${alertId}`}
                          className="text-primary hover:text-primary/80 font-medium"
                        >
                          {alert?.title || alertId}
                        </Link>
                        {alert && (
                          <p className="text-sm text-muted-foreground">
                            {alert.severity} - {new Date(alert.createdAt).toLocaleString()}
                          </p>
                        )}
                      </div>
                      <button
                        onClick={() => handleRemoveAlert(alertId)}
                        className="text-destructive hover:text-destructive/80 text-sm transition-colors"
                      >
                        Remove
                      </button>
                    </div>
                  )
                })}
              </div>
            ) : (
              <p className="text-muted-foreground">No alerts associated with this incident</p>
            )}
          </div>

          {/* Timeline placeholder */}
          <div className="bg-card border border-border rounded-lg p-6">
            <h2 className="text-lg font-semibold text-foreground mb-4">Activity Timeline</h2>
            <div className="space-y-4">
              <div className="flex gap-3">
                <div className="w-2 h-2 bg-primary rounded-full mt-2"></div>
                <div>
                  <p className="text-sm text-foreground">Incident created</p>
                  <p className="text-xs text-muted-foreground">
                    {new Date(incident.created_at).toLocaleString()} by {incident.created_by}
                  </p>
                </div>
              </div>
              {incident.updated_at !== incident.created_at && (
                <div className="flex gap-3">
                  <div className="w-2 h-2 bg-muted-foreground rounded-full mt-2"></div>
                  <div>
                    <p className="text-sm text-foreground">Incident updated</p>
                    <p className="text-xs text-muted-foreground">
                      {new Date(incident.updated_at).toLocaleString()}
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          <div className="bg-card border border-border rounded-lg p-6">
            <h2 className="text-lg font-semibold text-foreground mb-4">Details</h2>
            <dl className="space-y-4">
              <div>
                <dt className="text-sm text-muted-foreground">Status</dt>
                <dd className="mt-1">
                  <span className={`px-2 py-1 text-xs font-medium rounded-full ${statusColors[incident.status]}`}>
                    {incident.status}
                  </span>
                </dd>
              </div>
              <div>
                <dt className="text-sm text-muted-foreground">Severity</dt>
                <dd className="mt-1">
                  <span className={`px-2 py-1 text-xs font-medium rounded-full ${severityColors[incident.severity]}`}>
                    {incident.severity}
                  </span>
                </dd>
              </div>
              <div>
                <dt className="text-sm text-muted-foreground">Assignee</dt>
                <dd className="mt-1 text-foreground">{incident.assignee || 'Unassigned'}</dd>
              </div>
              <div>
                <dt className="text-sm text-muted-foreground">Created By</dt>
                <dd className="mt-1 text-foreground">{incident.created_by}</dd>
              </div>
              <div>
                <dt className="text-sm text-muted-foreground">Created At</dt>
                <dd className="mt-1 text-foreground">
                  {new Date(incident.created_at).toLocaleString()}
                </dd>
              </div>
              <div>
                <dt className="text-sm text-muted-foreground">Updated At</dt>
                <dd className="mt-1 text-foreground">
                  {new Date(incident.updated_at).toLocaleString()}
                </dd>
              </div>
            </dl>
          </div>

          {/* Tags */}
          {incident.tags.length > 0 && (
            <div className="bg-card border border-border rounded-lg p-6">
              <h2 className="text-lg font-semibold text-foreground mb-4">Tags</h2>
              <div className="flex flex-wrap gap-2">
                {incident.tags.map((tag) => (
                  <span
                    key={tag}
                    className="px-2 py-1 bg-muted text-muted-foreground text-sm rounded-full"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Edit Modal */}
      {isEditing && (
        <EditIncidentModal
          incident={incident}
          onClose={() => setIsEditing(false)}
          onSave={handleUpdate}
        />
      )}
    </div>
  )
}

function EditIncidentModal({
  incident,
  onClose,
  onSave,
}: {
  incident: {
    title: string
    description: string | null
    status: IncidentStatus
    severity: IncidentSeverity
    assignee: string | null
    tags: string[]
  }
  onClose: () => void
  onSave: (update: IncidentUpdate) => void
}) {
  const [title, setTitle] = useState(incident.title)
  const [description, setDescription] = useState(incident.description || '')
  const [status, setStatus] = useState<IncidentStatus>(incident.status)
  const [severity, setSeverity] = useState<IncidentSeverity>(incident.severity)
  const [assignee, setAssignee] = useState(incident.assignee || '')
  const [tags, setTags] = useState(incident.tags.join(', '))

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSave({
      title,
      description: description || undefined,
      status,
      severity,
      assignee: assignee || undefined,
      tags: tags ? tags.split(',').map(t => t.trim()) : [],
    })
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-card border border-border rounded-lg shadow-xl w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex justify-between items-center px-6 py-4 border-b border-border sticky top-0 bg-card">
          <h2 className="text-lg font-semibold text-foreground">Edit Incident</h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-foreground mb-1">Title</label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              required
              className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-foreground mb-1">Description</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-foreground mb-1">Status</label>
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value as IncidentStatus)}
                className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
              >
                <option value="open">Open</option>
                <option value="investigating">Investigating</option>
                <option value="contained">Contained</option>
                <option value="resolved">Resolved</option>
                <option value="closed">Closed</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-foreground mb-1">Severity</label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as IncidentSeverity)}
                className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-foreground mb-1">Assignee</label>
            <input
              type="email"
              value={assignee}
              onChange={(e) => setAssignee(e.target.value)}
              className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
              placeholder="user@example.com"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-foreground mb-1">Tags</label>
            <input
              type="text"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
              placeholder="Comma-separated tags"
            />
          </div>

          <div className="flex justify-end gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 border border-border rounded-lg text-foreground hover:bg-muted transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors"
            >
              Save Changes
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
