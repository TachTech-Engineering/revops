import { useState } from 'react'
import {
  Shield,
  Plus,
  Trash2,
  Edit,
  Search,
  Server,
  Globe,
  User,
  Cpu,
  Filter,
} from 'lucide-react'
import {
  useListAssetCriticalityQuery,
  useCreateAssetCriticalityMutation,
  useUpdateAssetCriticalityMutation,
  useDeleteAssetCriticalityMutation,
  AssetCriticalityCreate,
} from '../api/pantherApi'
import { cn } from '../lib/utils'

const matchTypeIcons: Record<string, React.ElementType> = {
  hostname: Server,
  ip: Globe,
  user: User,
  service: Cpu,
}

const criticalityColors: Record<number, string> = {
  10: 'bg-red-500',
  9: 'bg-red-500',
  8: 'bg-orange-500',
  7: 'bg-orange-500',
  6: 'bg-yellow-500',
  5: 'bg-yellow-500',
  4: 'bg-blue-500',
  3: 'bg-blue-500',
  2: 'bg-gray-500',
  1: 'bg-gray-500',
}

export default function AssetCriticalityPage() {
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [editingAsset, setEditingAsset] = useState<string | null>(null)
  const [matchTypeFilter, setMatchTypeFilter] = useState<string>('')
  const [searchQuery, setSearchQuery] = useState('')

  const { data: assets, isLoading } = useListAssetCriticalityQuery({
    matchType: matchTypeFilter || undefined,
  })

  const [createAsset, { isLoading: isCreating }] = useCreateAssetCriticalityMutation()
  const [updateAsset] = useUpdateAssetCriticalityMutation()
  const [deleteAsset] = useDeleteAssetCriticalityMutation()

  const [formData, setFormData] = useState<AssetCriticalityCreate>({
    name: '',
    description: '',
    match_type: 'hostname',
    match_pattern: '',
    criticality_level: 5,
    business_unit: '',
    data_classification: '',
    is_active: true,
  })

  const handleCreate = async () => {
    try {
      await createAsset(formData).unwrap()
      setShowCreateModal(false)
      resetForm()
    } catch (err) {
      console.error('Failed to create asset rule:', err)
    }
  }

  const handleUpdate = async (assetId: string) => {
    try {
      await updateAsset({
        id: assetId,
        update: formData,
      }).unwrap()
      setEditingAsset(null)
      resetForm()
    } catch (err) {
      console.error('Failed to update asset rule:', err)
    }
  }

  const handleDelete = async (assetId: string) => {
    if (!confirm('Are you sure you want to delete this rule?')) return
    try {
      await deleteAsset(assetId).unwrap()
    } catch (err) {
      console.error('Failed to delete asset rule:', err)
    }
  }

  const handleToggleActive = async (assetId: string, currentStatus: boolean) => {
    try {
      await updateAsset({
        id: assetId,
        update: { is_active: !currentStatus },
      }).unwrap()
    } catch (err) {
      console.error('Failed to toggle status:', err)
    }
  }

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      match_type: 'hostname',
      match_pattern: '',
      criticality_level: 5,
      business_unit: '',
      data_classification: '',
      is_active: true,
    })
  }

  const startEdit = (asset: typeof assets extends (infer T)[] | undefined ? T : never) => {
    if (!asset) return
    setFormData({
      name: asset.name,
      description: asset.description || '',
      match_type: asset.match_type,
      match_pattern: asset.match_pattern,
      criticality_level: asset.criticality_level,
      business_unit: asset.business_unit || '',
      data_classification: asset.data_classification || '',
      is_active: asset.is_active,
    })
    setEditingAsset(asset.id)
  }

  const filteredAssets = assets?.filter(
    (asset) =>
      asset.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      asset.match_pattern.toLowerCase().includes(searchQuery.toLowerCase())
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="text-primary" />
            Asset Criticality
          </h1>
          <p className="text-muted-foreground mt-1">
            Define asset importance rules for AI-powered triage suggestions
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
        >
          <Plus size={16} />
          Add Rule
        </button>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" size={16} />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search rules..."
            className="w-full pl-10 pr-4 py-2 bg-background border rounded-md"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter size={16} className="text-muted-foreground" />
          <select
            value={matchTypeFilter}
            onChange={(e) => setMatchTypeFilter(e.target.value)}
            className="px-3 py-2 bg-background border rounded-md text-sm"
          >
            <option value="">All Types</option>
            <option value="hostname">Hostname</option>
            <option value="ip">IP Address</option>
            <option value="user">User</option>
            <option value="service">Service</option>
          </select>
        </div>
      </div>

      {/* Criticality Legend */}
      <div className="flex items-center gap-4 p-4 bg-card rounded-lg border">
        <span className="text-sm font-medium">Criticality Scale:</span>
        <div className="flex items-center gap-2">
          {[1, 3, 5, 7, 10].map((level) => (
            <div key={level} className="flex items-center gap-1">
              <div className={cn('w-3 h-3 rounded-full', criticalityColors[level])} />
              <span className="text-xs text-muted-foreground">{level}</span>
            </div>
          ))}
        </div>
        <span className="text-xs text-muted-foreground ml-auto">1 = Low, 10 = Critical</span>
      </div>

      {/* Assets List */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
        </div>
      ) : !filteredAssets?.length ? (
        <div className="text-center py-12 bg-card rounded-lg border">
          <Shield className="mx-auto text-muted-foreground mb-4" size={48} />
          <h3 className="text-lg font-medium">No asset rules found</h3>
          <p className="text-muted-foreground mt-1">
            Create rules to define asset criticality for triage suggestions
          </p>
        </div>
      ) : (
        <div className="bg-card rounded-lg border overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="text-left p-4 font-medium">Name</th>
                <th className="text-left p-4 font-medium">Type</th>
                <th className="text-left p-4 font-medium">Pattern</th>
                <th className="text-left p-4 font-medium">Criticality</th>
                <th className="text-left p-4 font-medium">Business Unit</th>
                <th className="text-left p-4 font-medium">Status</th>
                <th className="text-right p-4 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredAssets.map((asset) => {
                const Icon = matchTypeIcons[asset.match_type] || Server
                return (
                  <tr key={asset.id} className="border-b last:border-0 hover:bg-muted/30">
                    <td className="p-4">
                      <div>
                        <p className="font-medium">{asset.name}</p>
                        {asset.description && (
                          <p className="text-xs text-muted-foreground truncate max-w-xs">
                            {asset.description}
                          </p>
                        )}
                      </div>
                    </td>
                    <td className="p-4">
                      <div className="flex items-center gap-2">
                        <Icon size={14} className="text-muted-foreground" />
                        <span className="capitalize">{asset.match_type}</span>
                      </div>
                    </td>
                    <td className="p-4">
                      <code className="px-2 py-1 bg-muted rounded text-sm">
                        {asset.match_pattern}
                      </code>
                    </td>
                    <td className="p-4">
                      <div className="flex items-center gap-2">
                        <div
                          className={cn(
                            'w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold text-white',
                            criticalityColors[asset.criticality_level] || 'bg-gray-500'
                          )}
                        >
                          {asset.criticality_level}
                        </div>
                      </div>
                    </td>
                    <td className="p-4 text-muted-foreground">
                      {asset.business_unit || '-'}
                    </td>
                    <td className="p-4">
                      <button
                        onClick={() => handleToggleActive(asset.id, asset.is_active)}
                        className={cn(
                          'px-2 py-1 rounded text-xs',
                          asset.is_active
                            ? 'bg-green-500/20 text-green-400'
                            : 'bg-gray-500/20 text-gray-400'
                        )}
                      >
                        {asset.is_active ? 'Active' : 'Inactive'}
                      </button>
                    </td>
                    <td className="p-4">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => startEdit(asset)}
                          className="p-1.5 hover:bg-accent rounded"
                        >
                          <Edit size={14} />
                        </button>
                        <button
                          onClick={() => handleDelete(asset.id)}
                          className="p-1.5 hover:bg-destructive/20 rounded text-destructive"
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Create/Edit Modal */}
      {(showCreateModal || editingAsset) && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card rounded-lg p-6 max-w-lg w-full mx-4">
            <h2 className="text-lg font-semibold mb-4">
              {editingAsset ? 'Edit Asset Rule' : 'Create Asset Rule'}
            </h2>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Rule Name</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                  placeholder="Production Database Servers"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">Description</label>
                <textarea
                  value={formData.description || ''}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                  rows={2}
                  placeholder="Critical production database infrastructure"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1">Match Type</label>
                  <select
                    value={formData.match_type}
                    onChange={(e) => setFormData({ ...formData, match_type: e.target.value })}
                    className="w-full px-3 py-2 bg-background border rounded-md"
                  >
                    <option value="hostname">Hostname</option>
                    <option value="ip">IP Address</option>
                    <option value="user">User</option>
                    <option value="service">Service</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Match Pattern</label>
                  <input
                    type="text"
                    value={formData.match_pattern}
                    onChange={(e) => setFormData({ ...formData, match_pattern: e.target.value })}
                    className="w-full px-3 py-2 bg-background border rounded-md"
                    placeholder="prod-db-*"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">
                  Criticality Level: {formData.criticality_level}
                </label>
                <input
                  type="range"
                  min="1"
                  max="10"
                  value={formData.criticality_level}
                  onChange={(e) =>
                    setFormData({ ...formData, criticality_level: parseInt(e.target.value) })
                  }
                  className="w-full"
                />
                <div className="flex justify-between text-xs text-muted-foreground mt-1">
                  <span>1 (Low)</span>
                  <span>5 (Medium)</span>
                  <span>10 (Critical)</span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1">Business Unit</label>
                  <input
                    type="text"
                    value={formData.business_unit || ''}
                    onChange={(e) => setFormData({ ...formData, business_unit: e.target.value })}
                    className="w-full px-3 py-2 bg-background border rounded-md"
                    placeholder="Engineering"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Data Classification</label>
                  <select
                    value={formData.data_classification || ''}
                    onChange={(e) =>
                      setFormData({ ...formData, data_classification: e.target.value })
                    }
                    className="w-full px-3 py-2 bg-background border rounded-md"
                  >
                    <option value="">Select...</option>
                    <option value="public">Public</option>
                    <option value="internal">Internal</option>
                    <option value="confidential">Confidential</option>
                    <option value="restricted">Restricted</option>
                  </select>
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => {
                  setShowCreateModal(false)
                  setEditingAsset(null)
                  resetForm()
                }}
                className="px-4 py-2 border rounded-md hover:bg-accent"
              >
                Cancel
              </button>
              <button
                onClick={() => (editingAsset ? handleUpdate(editingAsset) : handleCreate())}
                disabled={isCreating || !formData.name || !formData.match_pattern}
                className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
              >
                {editingAsset ? 'Update Rule' : isCreating ? 'Creating...' : 'Create Rule'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
