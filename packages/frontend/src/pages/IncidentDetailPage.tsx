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
  open: 'bg-red-100 text-red-800',
  investigating: 'bg-yellow-100 text-yellow-800',
  contained: 'bg-blue-100 text-blue-800',
  resolved: 'bg-green-100 text-green-800',
  closed: 'bg-gray-100 text-gray-800',
}

const severityColors: Record<IncidentSeverity, string> = {
  low: 'bg-gray-100 text-gray-800',
  medium: 'bg-yellow-100 text-yellow-800',
  high: 'bg-orange-100 text-orange-800',
  critical: 'bg-red-100 text-red-800',
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
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (error || !incident) {
    return (
      <div className="p-6">
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-red-700">
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
            <Link to="/incidents" className="text-blue-600 hover:text-blue-800">
              Incidents
            </Link>
            <span className="text-gray-400">/</span>
            <span className="text-gray-600">{incident.id.slice(0, 8)}</span>
          </div>
          <h1 className="text-2xl font-bold text-gray-900">{incident.title}</h1>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setIsEditing(true)}
            className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50"
          >
            Edit
          </button>
          <button
            onClick={handleDelete}
            className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
          >
            Delete
          </button>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Main Content */}
        <div className="col-span-2 space-y-6">
          {/* Description */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold mb-4">Description</h2>
            <p className="text-gray-700 whitespace-pre-wrap">
              {incident.description || 'No description provided'}
            </p>
          </div>

          {/* Alerts */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold mb-4">
              Associated Alerts ({incident.alert_count})
            </h2>
            {incident.alert_ids.length > 0 ? (
              <div className="space-y-3">
                {incident.alert_ids.map((alertId) => {
                  const alert = alertsData?.items?.find(a => a.id === alertId)
                  return (
                    <div
                      key={alertId}
                      className="flex justify-between items-center p-3 bg-gray-50 rounded-lg"
                    >
                      <div>
                        <Link
                          to={`/alerts/${alertId}`}
                          className="text-blue-600 hover:text-blue-800 font-medium"
                        >
                          {alert?.title || alertId}
                        </Link>
                        {alert && (
                          <p className="text-sm text-gray-500">
                            {alert.severity} - {new Date(alert.createdAt).toLocaleString()}
                          </p>
                        )}
                      </div>
                      <button
                        onClick={() => handleRemoveAlert(alertId)}
                        className="text-red-600 hover:text-red-800 text-sm"
                      >
                        Remove
                      </button>
                    </div>
                  )
                })}
              </div>
            ) : (
              <p className="text-gray-500">No alerts associated with this incident</p>
            )}
          </div>

          {/* Timeline placeholder */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold mb-4">Activity Timeline</h2>
            <div className="space-y-4">
              <div className="flex gap-3">
                <div className="w-2 h-2 bg-blue-500 rounded-full mt-2"></div>
                <div>
                  <p className="text-sm text-gray-900">Incident created</p>
                  <p className="text-xs text-gray-500">
                    {new Date(incident.created_at).toLocaleString()} by {incident.created_by}
                  </p>
                </div>
              </div>
              {incident.updated_at !== incident.created_at && (
                <div className="flex gap-3">
                  <div className="w-2 h-2 bg-gray-400 rounded-full mt-2"></div>
                  <div>
                    <p className="text-sm text-gray-900">Incident updated</p>
                    <p className="text-xs text-gray-500">
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
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold mb-4">Details</h2>
            <dl className="space-y-4">
              <div>
                <dt className="text-sm text-gray-500">Status</dt>
                <dd className="mt-1">
                  <span className={`px-2 py-1 text-xs font-medium rounded-full ${statusColors[incident.status]}`}>
                    {incident.status}
                  </span>
                </dd>
              </div>
              <div>
                <dt className="text-sm text-gray-500">Severity</dt>
                <dd className="mt-1">
                  <span className={`px-2 py-1 text-xs font-medium rounded-full ${severityColors[incident.severity]}`}>
                    {incident.severity}
                  </span>
                </dd>
              </div>
              <div>
                <dt className="text-sm text-gray-500">Assignee</dt>
                <dd className="mt-1 text-gray-900">{incident.assignee || 'Unassigned'}</dd>
              </div>
              <div>
                <dt className="text-sm text-gray-500">Created By</dt>
                <dd className="mt-1 text-gray-900">{incident.created_by}</dd>
              </div>
              <div>
                <dt className="text-sm text-gray-500">Created At</dt>
                <dd className="mt-1 text-gray-900">
                  {new Date(incident.created_at).toLocaleString()}
                </dd>
              </div>
              <div>
                <dt className="text-sm text-gray-500">Updated At</dt>
                <dd className="mt-1 text-gray-900">
                  {new Date(incident.updated_at).toLocaleString()}
                </dd>
              </div>
            </dl>
          </div>

          {/* Tags */}
          {incident.tags.length > 0 && (
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-lg font-semibold mb-4">Tags</h2>
              <div className="flex flex-wrap gap-2">
                {incident.tags.map((tag) => (
                  <span
                    key={tag}
                    className="px-2 py-1 bg-gray-100 text-gray-700 text-sm rounded-full"
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
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex justify-between items-center px-6 py-4 border-b sticky top-0 bg-white">
          <h2 className="text-lg font-semibold">Edit Incident</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Title</label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              required
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value as IncidentStatus)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              >
                <option value="open">Open</option>
                <option value="investigating">Investigating</option>
                <option value="contained">Contained</option>
                <option value="resolved">Resolved</option>
                <option value="closed">Closed</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as IncidentSeverity)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Assignee</label>
            <input
              type="email"
              value={assignee}
              onChange={(e) => setAssignee(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              placeholder="user@example.com"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Tags</label>
            <input
              type="text"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              placeholder="Comma-separated tags"
            />
          </div>

          <div className="flex justify-end gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              Save Changes
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
