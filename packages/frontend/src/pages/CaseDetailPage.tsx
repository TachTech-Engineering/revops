import { useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  useGetCaseQuery,
  useGetCaseTimelineQuery,
  useUpdateCaseMutation,
  useDeleteCaseMutation,
  useAddCaseCommentMutation,
  useUnlinkIncidentFromCaseMutation,
  type CaseStatus,
  type CasePriority,
  type CaseUpdate,
  type CaseActivityType,
} from '../api/pantherApi'

const statusColors: Record<CaseStatus, string> = {
  open: 'bg-red-100 text-red-800',
  in_progress: 'bg-yellow-100 text-yellow-800',
  pending: 'bg-purple-100 text-purple-800',
  resolved: 'bg-green-100 text-green-800',
  closed: 'bg-gray-100 text-gray-800',
}

const priorityColors: Record<CasePriority, string> = {
  low: 'bg-gray-100 text-gray-800',
  medium: 'bg-yellow-100 text-yellow-800',
  high: 'bg-orange-100 text-orange-800',
  critical: 'bg-red-100 text-red-800',
}

const activityTypeIcons: Record<CaseActivityType, string> = {
  created: 'bg-blue-500',
  status_changed: 'bg-yellow-500',
  priority_changed: 'bg-orange-500',
  assignee_changed: 'bg-purple-500',
  comment_added: 'bg-green-500',
  incident_linked: 'bg-indigo-500',
  incident_unlinked: 'bg-red-500',
  attachment_added: 'bg-teal-500',
  updated: 'bg-gray-500',
}

export default function CaseDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [isEditing, setIsEditing] = useState(false)
  const [newComment, setNewComment] = useState('')

  const { data: caseData, isLoading, error } = useGetCaseQuery(id!)
  const { data: timeline } = useGetCaseTimelineQuery({ caseId: id!, limit: 100 })
  const [updateCase] = useUpdateCaseMutation()
  const [deleteCase] = useDeleteCaseMutation()
  const [addComment, { isLoading: isAddingComment }] = useAddCaseCommentMutation()
  const [unlinkIncident] = useUnlinkIncidentFromCaseMutation()

  const handleUpdate = async (update: CaseUpdate) => {
    try {
      await updateCase({ id: id!, update }).unwrap()
      setIsEditing(false)
    } catch (err) {
      console.error('Failed to update case:', err)
    }
  }

  const handleDelete = async () => {
    if (confirm('Are you sure you want to delete this case?')) {
      try {
        await deleteCase(id!).unwrap()
        navigate('/cases')
      } catch (err) {
        console.error('Failed to delete case:', err)
      }
    }
  }

  const handleAddComment = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newComment.trim()) return

    try {
      await addComment({ caseId: id!, comment: newComment }).unwrap()
      setNewComment('')
    } catch (err) {
      console.error('Failed to add comment:', err)
    }
  }

  const handleUnlinkIncident = async (incidentId: string) => {
    try {
      await unlinkIncident({ caseId: id!, incidentId }).unwrap()
    } catch (err) {
      console.error('Failed to unlink incident:', err)
    }
  }

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (error || !caseData) {
    return (
      <div className="p-6">
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-red-700">
          Failed to load case
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
            <Link to="/cases" className="text-blue-600 hover:text-blue-800">
              Cases
            </Link>
            <span className="text-gray-400">/</span>
            <span className="text-gray-600">{caseData.case_number}</span>
          </div>
          <h1 className="text-2xl font-bold text-gray-900">{caseData.title}</h1>
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
              {caseData.description || 'No description provided'}
            </p>
          </div>

          {/* Linked Incidents */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold mb-4">
              Linked Incidents ({caseData.incident_count})
            </h2>
            {caseData.incident_ids.length > 0 ? (
              <div className="space-y-3">
                {caseData.incident_ids.map((incidentId) => (
                  <div
                    key={incidentId}
                    className="flex justify-between items-center p-3 bg-gray-50 rounded-lg"
                  >
                    <Link
                      to={`/incidents/${incidentId}`}
                      className="text-blue-600 hover:text-blue-800 font-medium"
                    >
                      {incidentId.slice(0, 8)}...
                    </Link>
                    <button
                      onClick={() => handleUnlinkIncident(incidentId)}
                      className="text-red-600 hover:text-red-800 text-sm"
                    >
                      Unlink
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-500">No incidents linked to this case</p>
            )}
          </div>

          {/* Add Comment */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold mb-4">Add Comment</h2>
            <form onSubmit={handleAddComment}>
              <textarea
                value={newComment}
                onChange={(e) => setNewComment(e.target.value)}
                rows={3}
                placeholder="Write a comment..."
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
              <div className="mt-3 flex justify-end">
                <button
                  type="submit"
                  disabled={!newComment.trim() || isAddingComment}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                >
                  {isAddingComment ? 'Adding...' : 'Add Comment'}
                </button>
              </div>
            </form>
          </div>

          {/* Timeline */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold mb-4">Activity Timeline</h2>
            {timeline && timeline.length > 0 ? (
              <div className="space-y-4">
                {timeline.map((activity) => (
                  <div key={activity.id} className="flex gap-3">
                    <div className={`w-2 h-2 rounded-full mt-2 ${activityTypeIcons[activity.activity_type]}`}></div>
                    <div className="flex-1">
                      <p className="text-sm text-gray-900">{activity.description}</p>
                      <p className="text-xs text-gray-500">
                        {new Date(activity.created_at).toLocaleString()} by {activity.user_email}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-500">No activity yet</p>
            )}
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold mb-4">Details</h2>
            <dl className="space-y-4">
              <div>
                <dt className="text-sm text-gray-500">Case Number</dt>
                <dd className="mt-1 text-gray-900 font-mono">{caseData.case_number}</dd>
              </div>
              <div>
                <dt className="text-sm text-gray-500">Status</dt>
                <dd className="mt-1">
                  <span className={`px-2 py-1 text-xs font-medium rounded-full ${statusColors[caseData.status]}`}>
                    {caseData.status.replace('_', ' ')}
                  </span>
                </dd>
              </div>
              <div>
                <dt className="text-sm text-gray-500">Priority</dt>
                <dd className="mt-1">
                  <span className={`px-2 py-1 text-xs font-medium rounded-full ${priorityColors[caseData.priority]}`}>
                    {caseData.priority}
                  </span>
                </dd>
              </div>
              <div>
                <dt className="text-sm text-gray-500">Assignee</dt>
                <dd className="mt-1 text-gray-900">{caseData.assignee || 'Unassigned'}</dd>
              </div>
              <div>
                <dt className="text-sm text-gray-500">Created By</dt>
                <dd className="mt-1 text-gray-900">{caseData.created_by}</dd>
              </div>
              <div>
                <dt className="text-sm text-gray-500">Created At</dt>
                <dd className="mt-1 text-gray-900">
                  {new Date(caseData.created_at).toLocaleString()}
                </dd>
              </div>
              {caseData.closed_at && (
                <div>
                  <dt className="text-sm text-gray-500">Closed At</dt>
                  <dd className="mt-1 text-gray-900">
                    {new Date(caseData.closed_at).toLocaleString()}
                  </dd>
                </div>
              )}
            </dl>
          </div>

          {/* Tags */}
          {caseData.tags.length > 0 && (
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-lg font-semibold mb-4">Tags</h2>
              <div className="flex flex-wrap gap-2">
                {caseData.tags.map((tag) => (
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
        <EditCaseModal
          caseData={caseData}
          onClose={() => setIsEditing(false)}
          onSave={handleUpdate}
        />
      )}
    </div>
  )
}

function EditCaseModal({
  caseData,
  onClose,
  onSave,
}: {
  caseData: {
    title: string
    description: string | null
    status: CaseStatus
    priority: CasePriority
    assignee: string | null
    tags: string[]
  }
  onClose: () => void
  onSave: (update: CaseUpdate) => void
}) {
  const [title, setTitle] = useState(caseData.title)
  const [description, setDescription] = useState(caseData.description || '')
  const [status, setStatus] = useState<CaseStatus>(caseData.status)
  const [priority, setPriority] = useState<CasePriority>(caseData.priority)
  const [assignee, setAssignee] = useState(caseData.assignee || '')
  const [tags, setTags] = useState(caseData.tags.join(', '))

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSave({
      title,
      description: description || undefined,
      status,
      priority,
      assignee: assignee || undefined,
      tags: tags ? tags.split(',').map(t => t.trim()) : [],
    })
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex justify-between items-center px-6 py-4 border-b sticky top-0 bg-white">
          <h2 className="text-lg font-semibold">Edit Case</h2>
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
                onChange={(e) => setStatus(e.target.value as CaseStatus)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              >
                <option value="open">Open</option>
                <option value="in_progress">In Progress</option>
                <option value="pending">Pending</option>
                <option value="resolved">Resolved</option>
                <option value="closed">Closed</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Priority</label>
              <select
                value={priority}
                onChange={(e) => setPriority(e.target.value as CasePriority)}
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
