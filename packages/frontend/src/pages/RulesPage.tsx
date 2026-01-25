import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Plus, ToggleLeft, ToggleRight } from 'lucide-react'
import { useListRulesQuery, useUpdateRuleMutation, useDeleteRuleMutation } from '../api/pantherApi'
import { getSeverityColor, formatDate } from '../lib/utils'
import type { Severity } from '../types'

export default function RulesPage() {
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('')
  const [enabledFilter, setEnabledFilter] = useState<boolean | null>(null)

  const { data, isLoading, error } = useListRulesQuery({
    severity: severityFilter || undefined,
    enabled: enabledFilter ?? undefined,
    pageSize: 50,
  })

  const [updateRule] = useUpdateRuleMutation()
  const [deleteRule] = useDeleteRuleMutation()

  const handleToggleEnabled = async (ruleId: string, currentEnabled: boolean) => {
    try {
      await updateRule({ id: ruleId, update: { enabled: !currentEnabled } }).unwrap()
    } catch (err) {
      console.error('Failed to toggle rule:', err)
    }
  }

  const handleDelete = async (ruleId: string) => {
    if (!confirm('Are you sure you want to delete this rule?')) return
    try {
      await deleteRule(ruleId).unwrap()
    } catch (err) {
      console.error('Failed to delete rule:', err)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Detection Rules</h1>
          <p className="text-muted-foreground">Manage Panther detection rules</p>
        </div>
        <Link
          to="/rules/new"
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90"
        >
          <Plus size={16} />
          New Rule
        </Link>
      </div>

      {/* Filters */}
      <div className="flex gap-4">
        <select
          value={enabledFilter === null ? '' : enabledFilter.toString()}
          onChange={(e) => setEnabledFilter(e.target.value === '' ? null : e.target.value === 'true')}
          className="rounded-md border bg-background px-3 py-2 text-sm"
        >
          <option value="">All Rules</option>
          <option value="true">Enabled Only</option>
          <option value="false">Disabled Only</option>
        </select>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as Severity | '')}
          className="rounded-md border bg-background px-3 py-2 text-sm"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="INFO">Info</option>
        </select>
      </div>

      {/* Rules Table */}
      <div className="rounded-lg border bg-background">
        {isLoading ? (
          <div className="p-6 text-center text-muted-foreground">Loading rules...</div>
        ) : error ? (
          <div className="p-6 text-center text-red-500">Error loading rules</div>
        ) : data?.results.length === 0 ? (
          <div className="p-6 text-center text-muted-foreground">No rules found</div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="px-4 py-3 text-left text-sm font-medium">Rule</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Severity</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Log Types</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Status</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Updated</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {data?.results.map((rule) => (
                <tr key={rule.id} className="hover:bg-muted/50">
                  <td className="px-4 py-3">
                    <Link
                      to={`/rules/${rule.id}`}
                      className="font-medium hover:text-primary hover:underline"
                    >
                      {rule.displayName || rule.id}
                    </Link>
                    <p className="text-sm text-muted-foreground">{rule.id}</p>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(rule.severity)}`}>
                      {rule.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm">
                    <div className="flex flex-wrap gap-1">
                      {rule.logTypes.slice(0, 2).map((lt) => (
                        <span key={lt} className="px-2 py-0.5 bg-muted rounded text-xs">
                          {lt}
                        </span>
                      ))}
                      {rule.logTypes.length > 2 && (
                        <span className="px-2 py-0.5 bg-muted rounded text-xs">
                          +{rule.logTypes.length - 2}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => handleToggleEnabled(rule.id, rule.enabled)}
                      className={`flex items-center gap-1 text-sm ${rule.enabled ? 'text-green-400' : 'text-muted-foreground'}`}
                    >
                      {rule.enabled ? <ToggleRight size={20} /> : <ToggleLeft size={20} />}
                      {rule.enabled ? 'Enabled' : 'Disabled'}
                    </button>
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    {formatDate(rule.updatedAt)}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-2">
                      <Link
                        to={`/rules/${rule.id}`}
                        className="px-2 py-1 text-sm hover:bg-accent rounded"
                      >
                        Edit
                      </Link>
                      <button
                        onClick={() => handleDelete(rule.id)}
                        className="px-2 py-1 text-sm text-red-400 hover:bg-red-500/10 rounded"
                      >
                        Delete
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
