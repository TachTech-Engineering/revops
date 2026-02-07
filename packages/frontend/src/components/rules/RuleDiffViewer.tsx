import { useMemo } from 'react'
import { RefreshCw, Plus, Minus, Edit3 } from 'lucide-react'
import { useDiffRuleVersionsQuery } from '../../api/pantherApi'
import { cn } from '../../lib/utils'

interface RuleDiffViewerProps {
  ruleId: string
  fromVersion: number
  toVersion: number
}

interface DiffLine {
  type: 'added' | 'removed' | 'unchanged' | 'modified'
  field: string
  oldValue?: string
  newValue?: string
}

export default function RuleDiffViewer({
  ruleId,
  fromVersion,
  toVersion,
}: RuleDiffViewerProps) {
  const { data, isLoading } = useDiffRuleVersionsQuery({
    ruleId,
    fromVersion,
    toVersion,
  })

  const diffLines = useMemo(() => {
    if (!data) return []

    const lines: DiffLine[] = []

    // Process field changes
    if (data.field_changes) {
      for (const [field, changes] of Object.entries(data.field_changes)) {
        const change = changes as { old?: unknown; new?: unknown }
        if (change.old === undefined && change.new !== undefined) {
          lines.push({
            type: 'added',
            field,
            newValue: JSON.stringify(change.new, null, 2),
          })
        } else if (change.old !== undefined && change.new === undefined) {
          lines.push({
            type: 'removed',
            field,
            oldValue: JSON.stringify(change.old, null, 2),
          })
        } else if (JSON.stringify(change.old) !== JSON.stringify(change.new)) {
          lines.push({
            type: 'modified',
            field,
            oldValue: JSON.stringify(change.old, null, 2),
            newValue: JSON.stringify(change.new, null, 2),
          })
        }
      }
    }

    return lines
  }, [data])

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-8">
        <RefreshCw className="animate-spin text-muted-foreground" size={24} />
      </div>
    )
  }

  if (!data) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        Failed to load diff
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between text-sm">
        <div className="flex items-center gap-4">
          <span className="px-2 py-1 bg-red-500/20 text-red-400 rounded">
            v{fromVersion}
          </span>
          <span>&rarr;</span>
          <span className="px-2 py-1 bg-green-500/20 text-green-400 rounded">
            v{toVersion}
          </span>
        </div>
        {data.ai_summary && (
          <span className="text-muted-foreground">{data.ai_summary}</span>
        )}
      </div>

      {/* Summary Stats */}
      <div className="flex items-center gap-4 text-sm">
        <span className="flex items-center gap-1 text-green-400">
          <Plus size={14} />
          {diffLines.filter((l) => l.type === 'added').length} added
        </span>
        <span className="flex items-center gap-1 text-red-400">
          <Minus size={14} />
          {diffLines.filter((l) => l.type === 'removed').length} removed
        </span>
        <span className="flex items-center gap-1 text-yellow-400">
          <Edit3 size={14} />
          {diffLines.filter((l) => l.type === 'modified').length} modified
        </span>
      </div>

      {/* Diff Content */}
      {diffLines.length === 0 ? (
        <div className="text-center py-8 text-muted-foreground">
          No differences found
        </div>
      ) : (
        <div className="space-y-3">
          {diffLines.map((line, index) => (
            <div
              key={index}
              className={cn(
                'rounded-lg border p-3',
                line.type === 'added' && 'border-green-500/50 bg-green-500/5',
                line.type === 'removed' && 'border-red-500/50 bg-red-500/5',
                line.type === 'modified' && 'border-yellow-500/50 bg-yellow-500/5'
              )}
            >
              <div className="flex items-center gap-2 mb-2">
                {line.type === 'added' && (
                  <Plus size={14} className="text-green-400" />
                )}
                {line.type === 'removed' && (
                  <Minus size={14} className="text-red-400" />
                )}
                {line.type === 'modified' && (
                  <Edit3 size={14} className="text-yellow-400" />
                )}
                <span className="font-medium">{line.field}</span>
                <span
                  className={cn(
                    'text-xs px-2 py-0.5 rounded capitalize',
                    line.type === 'added' && 'bg-green-500/20 text-green-400',
                    line.type === 'removed' && 'bg-red-500/20 text-red-400',
                    line.type === 'modified' && 'bg-yellow-500/20 text-yellow-400'
                  )}
                >
                  {line.type}
                </span>
              </div>

              {line.type === 'modified' && (
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-xs text-red-400 mb-1">Old Value</p>
                    <pre className="text-sm bg-red-500/10 p-2 rounded overflow-x-auto">
                      {line.oldValue}
                    </pre>
                  </div>
                  <div>
                    <p className="text-xs text-green-400 mb-1">New Value</p>
                    <pre className="text-sm bg-green-500/10 p-2 rounded overflow-x-auto">
                      {line.newValue}
                    </pre>
                  </div>
                </div>
              )}

              {line.type === 'added' && (
                <pre className="text-sm bg-green-500/10 p-2 rounded overflow-x-auto">
                  {line.newValue}
                </pre>
              )}

              {line.type === 'removed' && (
                <pre className="text-sm bg-red-500/10 p-2 rounded overflow-x-auto">
                  {line.oldValue}
                </pre>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Code Diff for body changes */}
      {data.code_diff && (
        <div className="mt-4">
          <h4 className="font-medium mb-2">Code Changes</h4>
          <div className="bg-muted rounded-lg p-4 overflow-x-auto">
            <pre className="text-sm font-mono">
              {data.code_diff.split('\n').map((line, i) => {
                let bgColor = ''
                let textColor = ''
                if (line.startsWith('+')) {
                  bgColor = 'bg-green-500/20'
                  textColor = 'text-green-400'
                } else if (line.startsWith('-')) {
                  bgColor = 'bg-red-500/20'
                  textColor = 'text-red-400'
                } else if (line.startsWith('@')) {
                  textColor = 'text-blue-400'
                }
                return (
                  <div key={i} className={cn('px-2', bgColor, textColor)}>
                    {line}
                  </div>
                )
              })}
            </pre>
          </div>
        </div>
      )}
    </div>
  )
}
