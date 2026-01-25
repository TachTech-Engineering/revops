import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  useListDashboardsQuery,
  useCreateDashboardMutation,
  useDeleteDashboardMutation,
  useUpdateDashboardMutation,
  type DashboardCreate,
} from '../api/pantherApi'

export default function DashboardManagerPage() {
  const navigate = useNavigate()
  const [showCreateModal, setShowCreateModal] = useState(false)

  const { data: dashboards, isLoading, error } = useListDashboardsQuery()
  const [createDashboard] = useCreateDashboardMutation()
  const [deleteDashboard] = useDeleteDashboardMutation()
  const [updateDashboard] = useUpdateDashboardMutation()

  const handleCreate = async (data: DashboardCreate) => {
    try {
      const result = await createDashboard(data).unwrap()
      setShowCreateModal(false)
      navigate(`/dashboards/${result.id}`)
    } catch (err) {
      console.error('Failed to create dashboard:', err)
    }
  }

  const handleDelete = async (id: string) => {
    if (confirm('Are you sure you want to delete this dashboard?')) {
      try {
        await deleteDashboard(id).unwrap()
      } catch (err) {
        console.error('Failed to delete dashboard:', err)
      }
    }
  }

  const handleSetDefault = async (id: string) => {
    try {
      await updateDashboard({ id, update: { is_default: true } }).unwrap()
    } catch (err) {
      console.error('Failed to set default dashboard:', err)
    }
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4 text-destructive">
          Failed to load dashboards
        </div>
      </div>
    )
  }

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Dashboards</h1>
          <p className="text-muted-foreground mt-1">Create and manage custom dashboards</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors"
        >
          Create Dashboard
        </button>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {dashboards?.map((dashboard) => (
            <div
              key={dashboard.id}
              className="bg-card border border-border rounded-lg shadow-sm p-6 hover:border-primary/50 transition-colors"
            >
              <div className="flex justify-between items-start mb-4">
                <div>
                  <h3 className="font-semibold text-foreground">{dashboard.name}</h3>
                  {dashboard.description && (
                    <p className="text-sm text-muted-foreground mt-1">{dashboard.description}</p>
                  )}
                </div>
                <div className="flex gap-1">
                  {dashboard.is_default && (
                    <span className="px-2 py-0.5 text-xs bg-blue-500/20 text-blue-400 rounded-full">
                      Default
                    </span>
                  )}
                  {dashboard.is_shared && (
                    <span className="px-2 py-0.5 text-xs bg-green-500/20 text-green-400 rounded-full">
                      Shared
                    </span>
                  )}
                </div>
              </div>

              <div className="text-sm text-muted-foreground mb-4">
                <div>{dashboard.widgets.length} widget{dashboard.widgets.length !== 1 ? 's' : ''}</div>
                <div>Created: {new Date(dashboard.created_at).toLocaleDateString()}</div>
              </div>

              <div className="flex justify-between items-center">
                <Link
                  to={`/dashboards/${dashboard.id}`}
                  className="text-primary hover:text-primary/80 font-medium transition-colors"
                >
                  Open
                </Link>
                <div className="flex gap-3">
                  {!dashboard.is_default && (
                    <button
                      onClick={() => handleSetDefault(dashboard.id)}
                      className="text-sm text-muted-foreground hover:text-foreground transition-colors"
                    >
                      Set Default
                    </button>
                  )}
                  <button
                    onClick={() => handleDelete(dashboard.id)}
                    className="text-sm text-destructive hover:text-destructive/80 transition-colors"
                  >
                    Delete
                  </button>
                </div>
              </div>
            </div>
          ))}

          {dashboards?.length === 0 && (
            <div className="col-span-full bg-muted/50 border border-border rounded-lg p-12 text-center">
              <div className="text-muted-foreground text-4xl mb-2">📊</div>
              <p className="text-muted-foreground">No dashboards yet</p>
              <button
                onClick={() => setShowCreateModal(true)}
                className="mt-2 text-primary hover:text-primary/80 transition-colors"
              >
                Create your first dashboard
              </button>
            </div>
          )}
        </div>
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <CreateDashboardModal
          onClose={() => setShowCreateModal(false)}
          onCreate={handleCreate}
        />
      )}
    </div>
  )
}

function CreateDashboardModal({
  onClose,
  onCreate,
}: {
  onClose: () => void
  onCreate: (data: DashboardCreate) => void
}) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [isShared, setIsShared] = useState(false)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onCreate({
      name,
      description: description || undefined,
      is_shared: isShared,
      layout: [],
      widgets: [],
    })
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-card border border-border rounded-lg shadow-xl w-full max-w-md mx-4">
        <div className="flex justify-between items-center px-6 py-4 border-b border-border">
          <h2 className="text-lg font-semibold text-foreground">Create Dashboard</h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-foreground mb-1">Name *</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
              placeholder="My Dashboard"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-foreground mb-1">Description</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={2}
              className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
              placeholder="Dashboard description..."
            />
          </div>

          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={isShared}
              onChange={(e) => setIsShared(e.target.checked)}
              className="rounded border-border bg-background text-primary focus:ring-primary"
            />
            <span className="text-sm text-foreground">Share with team</span>
          </label>

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
              disabled={!name}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50 transition-colors"
            >
              Create
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
