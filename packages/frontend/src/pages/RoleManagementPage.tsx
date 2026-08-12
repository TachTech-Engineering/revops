import { useState } from 'react'
import { Users, Plus, Trash2, Edit2, Check, Shield } from 'lucide-react'
import {
  useListUserRolesQuery,
  useCreateUserRoleMutation,
  useUpdateUserRoleMutation,
  useDeleteUserRoleMutation,
} from '../api/pantherApi'

interface RoleFormData {
  email: string
  role: 'admin' | 'analyst' | 'viewer'
}

const roleColors = {
  admin: 'bg-red-500/20 text-red-400',
  analyst: 'bg-blue-500/20 text-blue-400',
  viewer: 'bg-gray-500/20 text-gray-400',
}

const roleDescriptions = {
  admin: 'Full access, can assign roles',
  analyst: 'Full operational access, no role management',
  viewer: 'Read-only access',
}

export default function RoleManagementPage() {
  const [showForm, setShowForm] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [formData, setFormData] = useState<RoleFormData>({
    email: '',
    role: 'viewer',
  })

  const { data: roles, isLoading, error } = useListUserRolesQuery()
  const [createRole, { isLoading: isCreating }] = useCreateUserRoleMutation()
  const [updateRole] = useUpdateUserRoleMutation()
  const [deleteRole] = useDeleteUserRoleMutation()

  const handleSubmit = async () => {
    if (!formData.email.trim()) return

    try {
      if (editingId) {
        await updateRole({ id: editingId, role: formData.role }).unwrap()
        setEditingId(null)
      } else {
        await createRole(formData).unwrap()
      }

      setFormData({ email: '', role: 'viewer' })
      setShowForm(false)
    } catch (err) {
      console.error('Failed to save role:', err)
    }
  }

  const handleEdit = (role: NonNullable<typeof roles>[0]) => {
    setFormData({
      email: role.email,
      role: role.role,
    })
    setEditingId(role.id)
    setShowForm(true)
  }

  const handleDelete = async (id: string) => {
    if (confirm('Are you sure you want to remove this role assignment?')) {
      await deleteRole(id)
    }
  }

  if (error) {
    return (
      <div className="p-6 text-center">
        <Shield size={48} className="mx-auto mb-4 text-red-400" />
        <h2 className="text-xl font-semibold mb-2">Access Denied</h2>
        <p className="text-muted-foreground">You need admin privileges to manage user roles.</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Role Management</h1>
          <p className="text-muted-foreground">Assign roles to users to control their access level</p>
        </div>
        <button
          onClick={() => {
            setShowForm(true)
            setEditingId(null)
            setFormData({ email: '', role: 'viewer' })
          }}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md font-medium hover:bg-primary/90"
        >
          <Plus size={18} />
          Add User
        </button>
      </div>

      {/* Role descriptions */}
      <div className="grid gap-4 md:grid-cols-3">
        {(['admin', 'analyst', 'viewer'] as const).map((role) => (
          <div key={role} className="rounded-lg border bg-background p-4">
            <div className="flex items-center gap-2 mb-2">
              <span className={`px-2 py-1 rounded text-xs font-medium uppercase ${roleColors[role]}`}>
                {role}
              </span>
            </div>
            <p className="text-sm text-muted-foreground">{roleDescriptions[role]}</p>
          </div>
        ))}
      </div>

      {/* Form */}
      {showForm && (
        <div className="rounded-lg border bg-background p-6">
          <h3 className="font-semibold mb-4">
            {editingId ? 'Edit User Role' : 'Add User Role'}
          </h3>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="block text-sm font-medium mb-1">Email *</label>
              <input
                type="email"
                value={formData.email}
                onChange={(e) => setFormData((p) => ({ ...p, email: e.target.value }))}
                placeholder="user@example.com"
                disabled={!!editingId}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm disabled:opacity-50"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Role *</label>
              <select
                value={formData.role}
                onChange={(e) => setFormData((p) => ({ ...p, role: e.target.value as RoleFormData['role'] }))}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              >
                <option value="viewer">Viewer - Read-only access</option>
                <option value="analyst">Analyst - Full operational access</option>
                <option value="admin">Admin - Full access + role management</option>
              </select>
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
              disabled={isCreating || !formData.email.trim()}
              className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md font-medium hover:bg-primary/90 disabled:opacity-50"
            >
              <Check size={16} />
              {editingId ? 'Update' : 'Add'}
            </button>
          </div>
        </div>
      )}

      {/* Roles List */}
      <div className="rounded-lg border bg-background">
        {isLoading ? (
          <div className="p-6 text-center text-muted-foreground">Loading roles...</div>
        ) : roles?.length === 0 ? (
          <div className="p-12 text-center text-muted-foreground">
            <Users size={48} className="mx-auto mb-4 opacity-20" />
            <p>No user roles assigned</p>
            <p className="text-sm mt-2">Users without explicit roles default to Viewer access</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="px-4 py-3 text-left text-sm font-medium">Email</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Role</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Assigned By</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Date</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {roles?.map((role) => (
                <tr key={role.id} className="hover:bg-muted/50">
                  <td className="px-4 py-3 font-medium">{role.email}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded text-xs font-medium uppercase ${roleColors[role.role]}`}>
                      {role.role}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">{role.created_by}</td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    {new Date(role.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleEdit(role)}
                        className="p-1 hover:bg-accent rounded"
                        title="Edit"
                      >
                        <Edit2 size={16} />
                      </button>
                      <button
                        onClick={() => handleDelete(role.id)}
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
