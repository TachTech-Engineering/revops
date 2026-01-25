import { useState } from 'react'
import { FileText, Search, ChevronLeft, ChevronRight, Shield } from 'lucide-react'
import {
  useListAuditLogsQuery,
  useGetAuditActionsQuery,
  useGetAuditResourceTypesQuery,
} from '../api/pantherApi'

interface Filters {
  user_email: string
  action: string
  resource_type: string
  start_date: string
  end_date: string
}

export default function AuditLogPage() {
  const [page, setPage] = useState(1)
  const [filters, setFilters] = useState<Filters>({
    user_email: '',
    action: '',
    resource_type: '',
    start_date: '',
    end_date: '',
  })
  const [appliedFilters, setAppliedFilters] = useState<Filters>(filters)

  const { data: logsData, isLoading, error } = useListAuditLogsQuery({
    page,
    page_size: 50,
    ...(appliedFilters.user_email && { user_email: appliedFilters.user_email }),
    ...(appliedFilters.action && { action: appliedFilters.action }),
    ...(appliedFilters.resource_type && { resource_type: appliedFilters.resource_type }),
    ...(appliedFilters.start_date && { start_date: appliedFilters.start_date }),
    ...(appliedFilters.end_date && { end_date: appliedFilters.end_date }),
  })

  const { data: actions } = useGetAuditActionsQuery()
  const { data: resourceTypes } = useGetAuditResourceTypesQuery()

  const handleSearch = () => {
    setAppliedFilters(filters)
    setPage(1)
  }

  const handleClearFilters = () => {
    const empty: Filters = {
      user_email: '',
      action: '',
      resource_type: '',
      start_date: '',
      end_date: '',
    }
    setFilters(empty)
    setAppliedFilters(empty)
    setPage(1)
  }

  const totalPages = logsData ? Math.ceil(logsData.total / logsData.page_size) : 0

  if (error) {
    return (
      <div className="p-6 text-center">
        <Shield size={48} className="mx-auto mb-4 text-red-400" />
        <h2 className="text-xl font-semibold mb-2">Access Denied</h2>
        <p className="text-muted-foreground">You need admin privileges to view audit logs.</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Audit Logs</h1>
        <p className="text-muted-foreground">Track all actions performed in the system</p>
      </div>

      {/* Filters */}
      <div className="rounded-lg border bg-background p-4">
        <div className="grid gap-4 md:grid-cols-5">
          <div>
            <label className="block text-sm font-medium mb-1">User Email</label>
            <input
              type="text"
              value={filters.user_email}
              onChange={(e) => setFilters((p) => ({ ...p, user_email: e.target.value }))}
              placeholder="Search by email"
              className="w-full rounded-md border bg-background px-3 py-2 text-sm"
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Action</label>
            <select
              value={filters.action}
              onChange={(e) => setFilters((p) => ({ ...p, action: e.target.value }))}
              className="w-full rounded-md border bg-background px-3 py-2 text-sm"
            >
              <option value="">All actions</option>
              {actions?.map((action) => (
                <option key={action} value={action}>
                  {action}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Resource Type</label>
            <select
              value={filters.resource_type}
              onChange={(e) => setFilters((p) => ({ ...p, resource_type: e.target.value }))}
              className="w-full rounded-md border bg-background px-3 py-2 text-sm"
            >
              <option value="">All types</option>
              {resourceTypes?.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Start Date</label>
            <input
              type="date"
              value={filters.start_date}
              onChange={(e) => setFilters((p) => ({ ...p, start_date: e.target.value }))}
              className="w-full rounded-md border bg-background px-3 py-2 text-sm"
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">End Date</label>
            <input
              type="date"
              value={filters.end_date}
              onChange={(e) => setFilters((p) => ({ ...p, end_date: e.target.value }))}
              className="w-full rounded-md border bg-background px-3 py-2 text-sm"
            />
          </div>
        </div>
        <div className="flex justify-end gap-2 mt-4">
          <button
            onClick={handleClearFilters}
            className="px-4 py-2 border rounded-md hover:bg-accent"
          >
            Clear
          </button>
          <button
            onClick={handleSearch}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md font-medium hover:bg-primary/90"
          >
            <Search size={16} />
            Search
          </button>
        </div>
      </div>

      {/* Logs List */}
      <div className="rounded-lg border bg-background">
        {isLoading ? (
          <div className="p-6 text-center text-muted-foreground">Loading audit logs...</div>
        ) : logsData?.items.length === 0 ? (
          <div className="p-12 text-center text-muted-foreground">
            <FileText size={48} className="mx-auto mb-4 opacity-20" />
            <p>No audit logs found</p>
            <p className="text-sm mt-2">Try adjusting your filters</p>
          </div>
        ) : (
          <>
            <table className="w-full">
              <thead>
                <tr className="border-b bg-muted/50">
                  <th className="px-4 py-3 text-left text-sm font-medium">Timestamp</th>
                  <th className="px-4 py-3 text-left text-sm font-medium">User</th>
                  <th className="px-4 py-3 text-left text-sm font-medium">Action</th>
                  <th className="px-4 py-3 text-left text-sm font-medium">Resource</th>
                  <th className="px-4 py-3 text-left text-sm font-medium">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {logsData?.items.map((log) => (
                  <tr key={log.id} className="hover:bg-muted/50">
                    <td className="px-4 py-3 text-sm">
                      {new Date(log.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <div className="font-medium text-sm">{log.user_email}</div>
                      {log.ip_address && (
                        <div className="text-xs text-muted-foreground">{log.ip_address}</div>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-1 rounded text-xs font-medium bg-blue-500/20 text-blue-400">
                        {log.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <div>{log.resource_type}</div>
                      {log.resource_id && (
                        <div className="text-xs text-muted-foreground font-mono">
                          {log.resource_id.length > 20
                            ? `${log.resource_id.substring(0, 20)}...`
                            : log.resource_id}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {Object.keys(log.details).length > 0 ? (
                        <details className="cursor-pointer">
                          <summary className="text-muted-foreground hover:text-foreground">
                            View details
                          </summary>
                          <pre className="mt-2 p-2 bg-muted rounded text-xs overflow-auto max-w-md">
                            {JSON.stringify(log.details, null, 2)}
                          </pre>
                        </details>
                      ) : (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {/* Pagination */}
            <div className="flex items-center justify-between p-4 border-t">
              <div className="text-sm text-muted-foreground">
                Showing {((page - 1) * 50) + 1} to {Math.min(page * 50, logsData?.total || 0)} of {logsData?.total || 0} entries
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="p-2 rounded-md hover:bg-accent disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <ChevronLeft size={16} />
                </button>
                <span className="text-sm">
                  Page {page} of {totalPages}
                </span>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages}
                  className="p-2 rounded-md hover:bg-accent disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <ChevronRight size={16} />
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
