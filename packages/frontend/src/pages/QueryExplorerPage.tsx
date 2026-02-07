import { useState } from 'react'
import { Play, Download, Copy, Check, Database, Save, Trash2, Star } from 'lucide-react'
import Editor from '@monaco-editor/react'
import {
  useExecuteQueryMutation,
  useListSavedQueriesQuery,
  useCreateSavedQueryMutation,
  useDeleteSavedQueryMutation,
} from '../api/pantherApi'
import NaturalQueryInput from '../components/queries/NaturalQueryInput'

const EXAMPLE_QUERIES = [
  {
    name: 'Recent CloudTrail Events',
    sql: `SELECT * FROM panther_logs.aws_cloudtrail
WHERE p_event_time > current_timestamp - interval '1' hour
LIMIT 100`,
  },
  {
    name: 'Failed Login Attempts',
    sql: `SELECT p_event_time, p_source_label, p_any_usernames, p_any_ip_addresses
FROM panther_logs.public.all_logs
WHERE p_event_time > current_timestamp - interval '24' hour
  AND (eventType LIKE '%fail%' OR outcome LIKE '%FAIL%')
LIMIT 100`,
  },
  {
    name: 'Top Source IPs',
    sql: `SELECT p_any_ip_addresses as ip, COUNT(*) as count
FROM panther_logs.public.all_logs
WHERE p_event_time > current_timestamp - interval '24' hour
GROUP BY p_any_ip_addresses
ORDER BY count DESC
LIMIT 20`,
  },
]

export default function QueryExplorerPage() {
  const [sql, setSql] = useState(EXAMPLE_QUERIES[0].sql)
  const [copied, setCopied] = useState(false)
  const [showSaveDialog, setShowSaveDialog] = useState(false)
  const [queryName, setQueryName] = useState('')
  const [queryDescription, setQueryDescription] = useState('')

  const [executeQuery, { data: result, isLoading, error }] = useExecuteQueryMutation()
  const { data: savedQueries } = useListSavedQueriesQuery()
  const [createSavedQuery, { isLoading: isSaving }] = useCreateSavedQueryMutation()
  const [deleteSavedQuery] = useDeleteSavedQueryMutation()

  const handleExecute = async () => {
    if (!sql.trim()) return
    try {
      await executeQuery({ sql, timeout: 300 }).unwrap()
    } catch (err) {
      console.error('Query failed:', err)
    }
  }

  const handleSaveQuery = async () => {
    if (!queryName.trim() || !sql.trim()) return
    try {
      await createSavedQuery({
        name: queryName,
        description: queryDescription || undefined,
        sql,
      }).unwrap()
      setShowSaveDialog(false)
      setQueryName('')
      setQueryDescription('')
    } catch (err) {
      console.error('Failed to save query:', err)
    }
  }

  const handleDeleteSavedQuery = async (id: string) => {
    if (confirm('Delete this saved query?')) {
      await deleteSavedQuery(id)
    }
  }

  const handleCopyResults = async () => {
    if (!result?.results) return
    await navigator.clipboard.writeText(JSON.stringify(result.results, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleDownloadCSV = () => {
    if (!result?.results || result.results.length === 0) return

    const headers = Object.keys(result.results[0])
    const csvContent = [
      headers.join(','),
      ...result.results.map(row =>
        headers.map(h => {
          const val = row[h]
          const str = typeof val === 'object' ? JSON.stringify(val) : String(val ?? '')
          return str.includes(',') || str.includes('"') ? `"${str.replace(/"/g, '""')}"` : str
        }).join(',')
      )
    ].join('\n')

    const blob = new Blob([csvContent], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'query_results.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Query Explorer</h1>
        <p className="text-muted-foreground">Run SQL queries against your Panther data lake</p>
      </div>

      {/* Natural Language Query Input */}
      <NaturalQueryInput
        onQueryResult={(results) => {
          // The NaturalQueryInput component handles its own result display
          console.log('NL Query results:', results)
        }}
        className="mb-2"
      />

      <div className="grid gap-6 lg:grid-cols-4">
        {/* Query Editor */}
        <div className="lg:col-span-3 space-y-4">
          <div className="rounded-lg border bg-background overflow-hidden">
            <div className="flex items-center justify-between border-b px-4 py-2 bg-muted/50">
              <div className="flex items-center gap-2">
                <Database size={16} />
                <span className="font-semibold text-sm">SQL Query</span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setShowSaveDialog(true)}
                  className="flex items-center gap-1 px-3 py-1.5 border rounded-md text-sm hover:bg-accent"
                >
                  <Save size={14} />
                  Save
                </button>
                <button
                  onClick={handleExecute}
                  disabled={isLoading || !sql.trim()}
                  className="flex items-center gap-2 px-4 py-1.5 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
                >
                  <Play size={14} />
                  {isLoading ? 'Running...' : 'Run Query'}
                </button>
              </div>
            </div>
            <Editor
              height="200px"
              defaultLanguage="sql"
              value={sql}
              onChange={(value) => setSql(value || '')}
              theme="vs-dark"
              options={{
                minimap: { enabled: false },
                fontSize: 13,
                lineNumbers: 'on',
                scrollBeyondLastLine: false,
                automaticLayout: true,
                wordWrap: 'on',
              }}
            />
          </div>

          {/* Save Dialog */}
          {showSaveDialog && (
            <div className="rounded-lg border bg-background p-4">
              <h4 className="font-medium mb-3">Save Query</h4>
              <div className="space-y-3">
                <div>
                  <label className="block text-sm font-medium mb-1">Name *</label>
                  <input
                    type="text"
                    value={queryName}
                    onChange={(e) => setQueryName(e.target.value)}
                    placeholder="Query name"
                    className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Description</label>
                  <input
                    type="text"
                    value={queryDescription}
                    onChange={(e) => setQueryDescription(e.target.value)}
                    placeholder="Optional description"
                    className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                  />
                </div>
                <div className="flex justify-end gap-2">
                  <button
                    onClick={() => setShowSaveDialog(false)}
                    className="px-3 py-1.5 border rounded-md text-sm hover:bg-accent"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleSaveQuery}
                    disabled={isSaving || !queryName.trim()}
                    className="px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
                  >
                    {isSaving ? 'Saving...' : 'Save'}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Results */}
          {error && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-red-400">
              <p className="font-medium">Query Error</p>
              <p className="text-sm">{'data' in error ? JSON.stringify((error as { data: unknown }).data) : 'Query execution failed'}</p>
            </div>
          )}

          {result && (
            <div className="rounded-lg border bg-background">
              <div className="flex items-center justify-between border-b px-4 py-2 bg-muted/50">
                <div className="flex items-center gap-4 text-sm">
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                    result.status === 'SUCCEEDED' ? 'bg-green-500/20 text-green-400' :
                    result.status === 'FAILED' ? 'bg-red-500/20 text-red-400' :
                    'bg-yellow-500/20 text-yellow-400'
                  }`}>
                    {result.status}
                  </span>
                  <span className="text-muted-foreground">
                    {result.results.length} rows
                  </span>
                  {result.rowsScanned && (
                    <span className="text-muted-foreground">
                      {result.rowsScanned.toLocaleString()} scanned
                    </span>
                  )}
                  {result.bytesScanned && (
                    <span className="text-muted-foreground">
                      {formatBytes(result.bytesScanned)}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleCopyResults}
                    className="flex items-center gap-1 px-2 py-1 text-sm hover:bg-accent rounded"
                  >
                    {copied ? <Check size={14} /> : <Copy size={14} />}
                    {copied ? 'Copied!' : 'Copy JSON'}
                  </button>
                  <button
                    onClick={handleDownloadCSV}
                    className="flex items-center gap-1 px-2 py-1 text-sm hover:bg-accent rounded"
                  >
                    <Download size={14} />
                    CSV
                  </button>
                </div>
              </div>

              {result.errorMessage ? (
                <div className="p-4 text-red-400">
                  <p className="font-medium">Error</p>
                  <p className="text-sm">{result.errorMessage}</p>
                </div>
              ) : result.results.length === 0 ? (
                <div className="p-6 text-center text-muted-foreground">
                  No results found
                </div>
              ) : (
                <div className="overflow-auto max-h-[400px]">
                  <table className="w-full text-sm">
                    <thead className="sticky top-0 bg-muted">
                      <tr>
                        {Object.keys(result.results[0]).map((col) => (
                          <th key={col} className="px-3 py-2 text-left font-medium whitespace-nowrap">
                            {col}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {result.results.slice(0, 100).map((row, i) => (
                        <tr key={i} className="hover:bg-muted/50">
                          {Object.values(row).map((val, j) => (
                            <td key={j} className="px-3 py-2 whitespace-nowrap max-w-xs truncate">
                              {typeof val === 'object' ? JSON.stringify(val) : String(val ?? '')}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {result.results.length > 100 && (
                    <div className="p-2 text-center text-sm text-muted-foreground border-t">
                      Showing first 100 of {result.results.length} results
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {!result && !error && (
            <div className="rounded-lg border bg-background p-12 text-center text-muted-foreground">
              <Database size={48} className="mx-auto mb-4 opacity-20" />
              <p>Write a SQL query and click Run to see results</p>
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          {/* Saved Queries */}
          {savedQueries && savedQueries.length > 0 && (
            <div className="rounded-lg border bg-background p-4">
              <h3 className="font-semibold mb-3 flex items-center gap-2">
                <Star size={16} />
                Saved Queries
              </h3>
              <div className="space-y-2">
                {savedQueries.map((query) => (
                  <div
                    key={query.id}
                    className="flex items-center gap-2 group"
                  >
                    <button
                      onClick={() => setSql(query.sql)}
                      className="flex-1 text-left px-3 py-2 rounded hover:bg-accent text-sm transition-colors truncate"
                      title={query.description || query.name}
                    >
                      {query.name}
                    </button>
                    <button
                      onClick={() => handleDeleteSavedQuery(query.id)}
                      className="p-1 hover:bg-accent rounded opacity-0 group-hover:opacity-100 transition-opacity text-red-400"
                      title="Delete"
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Example Queries */}
          <div className="rounded-lg border bg-background p-4">
            <h3 className="font-semibold mb-3">Example Queries</h3>
            <div className="space-y-2">
              {EXAMPLE_QUERIES.map((example, i) => (
                <button
                  key={i}
                  onClick={() => setSql(example.sql)}
                  className="w-full text-left px-3 py-2 rounded hover:bg-accent text-sm transition-colors"
                >
                  {example.name}
                </button>
              ))}
            </div>
          </div>

          <div className="rounded-lg border bg-background p-4">
            <h3 className="font-semibold mb-3">Tips</h3>
            <ul className="text-sm text-muted-foreground space-y-2">
              <li>• Use <code className="bg-muted px-1 rounded">LIMIT</code> to avoid large result sets</li>
              <li>• Filter by <code className="bg-muted px-1 rounded">p_event_time</code> for efficiency</li>
              <li>• Common tables: <code className="bg-muted px-1 rounded">panther_logs.public.all_logs</code></li>
              <li>• Query timeout: 5 minutes max</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}
