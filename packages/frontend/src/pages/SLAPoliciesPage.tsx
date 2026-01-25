import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowLeft, Plus, Edit, Trash2, Star, X } from 'lucide-react'
import {
  useListSLAPoliciesQuery,
  useCreateSLAPolicyMutation,
  useUpdateSLAPolicyMutation,
  useDeleteSLAPolicyMutation,
  type SLAPolicyResponse,
  type SLAPolicyCreate,
} from '../api/pantherApi'
import { cn } from '../lib/utils'

export default function SLAPoliciesPage() {
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<SLAPolicyResponse | null>(null)

  const { data: policies, isLoading } = useListSLAPoliciesQuery({})
  const [createPolicy] = useCreateSLAPolicyMutation()
  const [updatePolicy] = useUpdateSLAPolicyMutation()
  const [deletePolicy] = useDeleteSLAPolicyMutation()

  const handleCreate = async (data: SLAPolicyCreate) => {
    try {
      await createPolicy(data).unwrap()
      setShowCreateModal(false)
    } catch (error) {
      console.error('Failed to create policy:', error)
    }
  }

  const handleUpdate = async (id: string, data: Partial<SLAPolicyCreate>) => {
    try {
      await updatePolicy({ id, update: data }).unwrap()
      setEditingPolicy(null)
    } catch (error) {
      console.error('Failed to update policy:', error)
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this SLA policy?')) return
    try {
      await deletePolicy(id).unwrap()
    } catch (error) {
      console.error('Failed to delete policy:', error)
    }
  }

  const handleSetDefault = async (policy: SLAPolicyResponse) => {
    try {
      await updatePolicy({ id: policy.id, update: { is_default: true } }).unwrap()
    } catch (error) {
      console.error('Failed to set default policy:', error)
    }
  }

  const formatTime = (minutes: number) => {
    if (minutes < 60) return `${minutes}m`
    const hours = minutes / 60
    if (hours < 24) return `${hours}h`
    return `${hours / 24}d`
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link
            to="/sla"
            className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
          >
            <ArrowLeft className="w-5 h-5 text-gray-500" />
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">SLA Policies</h1>
            <p className="text-gray-600 dark:text-gray-400">
              Define response time targets for alerts
            </p>
          </div>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <Plus className="w-4 h-4" />
          Create Policy
        </button>
      </div>

      {/* Policies List */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        {policies && policies.length > 0 ? (
          <div className="divide-y divide-gray-200 dark:divide-gray-700">
            {policies.map((policy) => (
              <div
                key={policy.id}
                className={cn(
                  'p-4 hover:bg-gray-50 dark:hover:bg-gray-700/50',
                  !policy.is_active && 'opacity-60'
                )}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                        {policy.name}
                      </h3>
                      {policy.is_default && (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300 rounded-full text-xs font-medium">
                          <Star className="w-3 h-3" />
                          Default
                        </span>
                      )}
                      {!policy.is_active && (
                        <span className="px-2 py-0.5 bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400 rounded-full text-xs font-medium">
                          Inactive
                        </span>
                      )}
                    </div>
                    {policy.description && (
                      <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                        {policy.description}
                      </p>
                    )}

                    <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-4">
                      {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((severity) => {
                        const ackKey = `ack_time_${severity.toLowerCase()}` as keyof SLAPolicyResponse
                        const resolveKey =
                          `resolve_time_${severity.toLowerCase()}` as keyof SLAPolicyResponse
                        const severityColors: Record<string, string> = {
                          CRITICAL: 'border-red-500',
                          HIGH: 'border-orange-500',
                          MEDIUM: 'border-yellow-500',
                          LOW: 'border-blue-500',
                        }

                        return (
                          <div
                            key={severity}
                            className={cn(
                              'p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg border-l-4',
                              severityColors[severity]
                            )}
                          >
                            <div className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
                              {severity}
                            </div>
                            <div className="text-sm">
                              <span className="text-gray-600 dark:text-gray-400">Ack:</span>{' '}
                              <span className="font-medium text-gray-900 dark:text-white">
                                {formatTime(policy[ackKey] as number)}
                              </span>
                            </div>
                            <div className="text-sm">
                              <span className="text-gray-600 dark:text-gray-400">Resolve:</span>{' '}
                              <span className="font-medium text-gray-900 dark:text-white">
                                {formatTime(policy[resolveKey] as number)}
                              </span>
                            </div>
                          </div>
                        )
                      })}
                    </div>

                    {policy.rule_ids.length > 0 && (
                      <div className="mt-3 text-sm text-gray-600 dark:text-gray-400">
                        <span className="font-medium">Applied to rules:</span>{' '}
                        {policy.rule_ids.length} rule{policy.rule_ids.length !== 1 ? 's' : ''}
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    {!policy.is_default && (
                      <button
                        onClick={() => handleSetDefault(policy)}
                        className="p-2 text-gray-400 hover:text-yellow-600 dark:hover:text-yellow-400"
                        title="Set as default"
                      >
                        <Star className="w-4 h-4" />
                      </button>
                    )}
                    <button
                      onClick={() => setEditingPolicy(policy)}
                      className="p-2 text-gray-400 hover:text-blue-600 dark:hover:text-blue-400"
                    >
                      <Edit className="w-4 h-4" />
                    </button>
                    {!policy.is_default && (
                      <button
                        onClick={() => handleDelete(policy.id)}
                        className="p-2 text-gray-400 hover:text-red-600 dark:hover:text-red-400"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-8 text-center text-gray-500 dark:text-gray-400">
            No SLA policies defined.{' '}
            <button
              onClick={() => setShowCreateModal(true)}
              className="text-blue-600 hover:text-blue-700"
            >
              Create one
            </button>
          </div>
        )}
      </div>

      {/* Create/Edit Modal */}
      {(showCreateModal || editingPolicy) && (
        <PolicyModal
          policy={editingPolicy}
          onClose={() => {
            setShowCreateModal(false)
            setEditingPolicy(null)
          }}
          onSave={(data) => {
            if (editingPolicy) {
              handleUpdate(editingPolicy.id, data)
            } else {
              handleCreate(data as SLAPolicyCreate)
            }
          }}
        />
      )}
    </div>
  )
}

interface PolicyModalProps {
  policy: SLAPolicyResponse | null
  onClose: () => void
  onSave: (data: Partial<SLAPolicyCreate>) => void
}

function PolicyModal({ policy, onClose, onSave }: PolicyModalProps) {
  const [formData, setFormData] = useState<Partial<SLAPolicyCreate>>({
    name: policy?.name || '',
    description: policy?.description || '',
    ack_time_critical: policy?.ack_time_critical || 15,
    ack_time_high: policy?.ack_time_high || 60,
    ack_time_medium: policy?.ack_time_medium || 240,
    ack_time_low: policy?.ack_time_low || 1440,
    resolve_time_critical: policy?.resolve_time_critical || 240,
    resolve_time_high: policy?.resolve_time_high || 480,
    resolve_time_medium: policy?.resolve_time_medium || 1440,
    resolve_time_low: policy?.resolve_time_low || 4320,
    is_default: policy?.is_default || false,
    is_active: policy?.is_active ?? true,
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSave(formData)
  }

  const timePresets = [
    { label: '15m', value: 15 },
    { label: '30m', value: 30 },
    { label: '1h', value: 60 },
    { label: '2h', value: 120 },
    { label: '4h', value: 240 },
    { label: '8h', value: 480 },
    { label: '24h', value: 1440 },
    { label: '48h', value: 2880 },
    { label: '72h', value: 4320 },
  ]

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            {policy ? 'Edit SLA Policy' : 'Create SLA Policy'}
          </h3>
          <button
            onClick={onClose}
            className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-4 space-y-6">
          <div className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Policy Name
              </label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                required
              />
            </div>

            <div className="col-span-2">
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Description
              </label>
              <textarea
                value={formData.description || ''}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                rows={2}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>

          {/* Time Targets */}
          <div>
            <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">
              Time to Acknowledge (minutes)
            </h4>
            <div className="grid grid-cols-4 gap-4">
              {['critical', 'high', 'medium', 'low'].map((severity) => {
                const key = `ack_time_${severity}` as keyof typeof formData
                return (
                  <div key={severity}>
                    <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1 uppercase">
                      {severity}
                    </label>
                    <select
                      value={formData[key] as number}
                      onChange={(e) =>
                        setFormData({ ...formData, [key]: Number(e.target.value) })
                      }
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                    >
                      {timePresets.map((preset) => (
                        <option key={preset.value} value={preset.value}>
                          {preset.label}
                        </option>
                      ))}
                    </select>
                  </div>
                )
              })}
            </div>
          </div>

          <div>
            <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">
              Time to Resolve (minutes)
            </h4>
            <div className="grid grid-cols-4 gap-4">
              {['critical', 'high', 'medium', 'low'].map((severity) => {
                const key = `resolve_time_${severity}` as keyof typeof formData
                return (
                  <div key={severity}>
                    <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1 uppercase">
                      {severity}
                    </label>
                    <select
                      value={formData[key] as number}
                      onChange={(e) =>
                        setFormData({ ...formData, [key]: Number(e.target.value) })
                      }
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                    >
                      {timePresets.map((preset) => (
                        <option key={preset.value} value={preset.value}>
                          {preset.label}
                        </option>
                      ))}
                    </select>
                  </div>
                )
              })}
            </div>
          </div>

          <div className="flex gap-4">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={formData.is_active}
                onChange={(e) => setFormData({ ...formData, is_active: e.target.checked })}
                className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500"
              />
              <span className="text-sm text-gray-700 dark:text-gray-300">Active</span>
            </label>

            {!policy?.is_default && (
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={formData.is_default}
                  onChange={(e) => setFormData({ ...formData, is_default: e.target.checked })}
                  className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-sm text-gray-700 dark:text-gray-300">Set as default</span>
              </label>
            )}
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              {policy ? 'Save Changes' : 'Create Policy'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
