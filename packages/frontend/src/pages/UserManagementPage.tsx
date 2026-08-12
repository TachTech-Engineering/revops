import { useState } from 'react'
import { Users, Search, Shield, ShieldOff, Trash2, ChevronDown } from 'lucide-react'
import {
  useListUsersQuery,
  useUpdateUserMutation,
  useDeleteUserMutation,
} from '../api/pantherApi'
import { formatDate } from '../lib/utils'

const roleColors: Record<string, string> = {
  admin: 'bg-red-500/20 text-red-400',
  analyst: 'bg-blue-500/20 text-blue-400',
  viewer: 'bg-gray-500/20 text-gray-400',
}

export default function UserManagementPage() {
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [roleFilter, setRoleFilter] = useState<string>('')
  const [statusFilter, setStatusFilter] = useState<string>('')

  const { data: usersData, isLoading, error } = useListUsersQuery({
    page,
    page_size: 20,
    search: search || undefined,
    role: roleFilter || undefined,
    is_active: statusFilter === '' ? undefined : statusFilter === 'active',
  })

  const [updateUser] = useUpdateUserMutation()
  const [deleteUser] = useDeleteUserMutation()

  const handleRoleChange = async (userId: string, newRole: string) => {
    try {
      await updateUser({ id: userId, role: newRole }).unwrap()
    } catch (err) {
      console.error('Failed to update role:', err)
      alert('Failed to update user role')
    }
  }

  const handleToggleActive = async (userId: string, currentlyActive: boolean) => {
    const action = currentlyActive ? 'deactivate' : 'activate'
    if (!confirm(`Are you sure you want to ${action} this user?`)) return

    try {
      await updateUser({ id: userId, is_active: !currentlyActive }).unwrap()
    } catch (err: unknown) {
      console.error('Failed to toggle user status:', err)
      const errorMessage = err && typeof err === 'object' && 'data' in err
        ? (err.data as { detail?: string })?.detail || 'Failed to update user'
        : 'Failed to update user'
      alert(errorMessage)
    }
  }

  const handleDelete = async (userId: string, email: string) => {
    if (!confirm(`Are you sure you want to permanently delete ${email}? This cannot be undone.`)) return

    try {
      await deleteUser(userId).unwrap()
    } catch (err: unknown) {
      console.error('Failed to delete user:', err)
      const errorMessage = err && typeof err === 'object' && 'data' in err
        ? (err.data as { detail?: string })?.detail || 'Failed to delete user'
        : 'Failed to delete user'
      alert(errorMessage)
    }
  }

  if (error) {
    return (
      <div className="p-6 text-center">
        <Shield size={48} className="mx-auto mb-4 text-red-400" />
        <h2 className="text-xl font-semibold mb-2">Access Denied</h2>
        <p className="text-muted-foreground">You need admin privileges to manage users.</p>
      </div>
    )
  }

  const totalPages = usersData ? Math.ceil(usersData.total / usersData.page_size) : 0

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold flex items-center gap-3">
          <Users className="h-8 w-8" />
          User Management
        </h1>
        <p className="text-muted-foreground">
          View and manage user accounts in your organization
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-4">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search by name or email..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              setPage(1)
            }}
            className="w-full pl-10 pr-4 py-2 bg-background border rounded-md"
          />
        </div>

        <select
          value={roleFilter}
          onChange={(e) => {
            setRoleFilter(e.target.value)
            setPage(1)
          }}
          className="px-4 py-2 bg-background border rounded-md"
        >
          <option value="">All Roles</option>
          <option value="admin">Admin</option>
          <option value="analyst">Analyst</option>
          <option value="viewer">Viewer</option>
        </select>

        <select
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value)
            setPage(1)
          }}
          className="px-4 py-2 bg-background border rounded-md"
        >
          <option value="">All Status</option>
          <option value="active">Active</option>
          <option value="inactive">Inactive</option>
        </select>
      </div>

      {/* Users Table */}
      <div className="rounded-lg border bg-background">
        {isLoading ? (
          <div className="p-8 text-center text-muted-foreground">Loading users...</div>
        ) : !usersData?.items?.length ? (
          <div className="p-8 text-center text-muted-foreground">No users found</div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b bg-muted/50">
                    <th className="text-left p-4 font-medium">User</th>
                    <th className="text-left p-4 font-medium">Role</th>
                    <th className="text-left p-4 font-medium">Status</th>
                    <th className="text-left p-4 font-medium">SSO</th>
                    <th className="text-left p-4 font-medium">Created</th>
                    <th className="text-left p-4 font-medium">Last Login</th>
                    <th className="text-right p-4 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {usersData.items.map((user) => (
                    <tr key={user.id} className="border-b hover:bg-muted/30">
                      <td className="p-4">
                        <div>
                          <p className="font-medium">{user.name || 'No name'}</p>
                          <p className="text-sm text-muted-foreground">{user.email}</p>
                        </div>
                      </td>
                      <td className="p-4">
                        <div className="relative inline-block">
                          <select
                            value={user.role}
                            onChange={(e) => handleRoleChange(user.id, e.target.value)}
                            className={`appearance-none pr-8 pl-3 py-1 rounded-full text-sm font-medium cursor-pointer ${roleColors[user.role] || roleColors.viewer}`}
                          >
                            <option value="admin">Admin</option>
                            <option value="analyst">Analyst</option>
                            <option value="viewer">Viewer</option>
                          </select>
                          <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 h-4 w-4 pointer-events-none" />
                        </div>
                      </td>
                      <td className="p-4">
                        <span
                          className={`px-2 py-1 rounded-full text-xs font-medium ${
                            user.is_active
                              ? 'bg-green-500/20 text-green-400'
                              : 'bg-red-500/20 text-red-400'
                          }`}
                        >
                          {user.is_active ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td className="p-4">
                        {user.sso_provider ? (
                          <span className="px-2 py-1 rounded text-xs font-medium bg-purple-500/20 text-purple-400">
                            {user.sso_provider}
                          </span>
                        ) : (
                          <span className="text-muted-foreground text-sm">Password</span>
                        )}
                      </td>
                      <td className="p-4 text-sm text-muted-foreground">
                        {formatDate(user.created_at)}
                      </td>
                      <td className="p-4 text-sm text-muted-foreground">
                        {user.last_login_at ? formatDate(user.last_login_at) : 'Never'}
                      </td>
                      <td className="p-4">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => handleToggleActive(user.id, user.is_active)}
                            className={`p-2 rounded hover:bg-accent ${
                              user.is_active ? 'text-orange-400' : 'text-green-400'
                            }`}
                            title={user.is_active ? 'Deactivate user' : 'Activate user'}
                          >
                            {user.is_active ? <ShieldOff size={18} /> : <Shield size={18} />}
                          </button>
                          <button
                            onClick={() => handleDelete(user.id, user.email)}
                            className="p-2 rounded hover:bg-accent text-red-400"
                            title="Delete user"
                          >
                            <Trash2 size={18} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between p-4 border-t">
                <div className="text-sm text-muted-foreground">
                  Showing {(page - 1) * (usersData?.page_size || 20) + 1} to{' '}
                  {Math.min(page * (usersData?.page_size || 20), usersData?.total || 0)} of{' '}
                  {usersData?.total || 0} users
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setPage(page - 1)}
                    disabled={page === 1}
                    className="px-3 py-1 rounded-md bg-muted hover:bg-accent disabled:opacity-50"
                  >
                    Previous
                  </button>
                  <span className="text-sm">
                    Page {page} of {totalPages}
                  </span>
                  <button
                    onClick={() => setPage(page + 1)}
                    disabled={page >= totalPages}
                    className="px-3 py-1 rounded-md bg-muted hover:bg-accent disabled:opacity-50"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
