import { useState } from 'react'
import {
  History,
  RefreshCw,
  ChevronRight,
  RotateCcw,
  GitCompare,
  User,
  Clock,
} from 'lucide-react'
import {
  useListRuleVersionsQuery,
  useRollbackRuleMutation,
} from '../../api/pantherApi'
import { cn } from '../../lib/utils'
import RuleDiffViewer from './RuleDiffViewer'

interface RuleVersionHistoryProps {
  ruleId: string
}

const changeTypeColors: Record<string, string> = {
  created: 'bg-green-500/20 text-green-400',
  updated: 'bg-blue-500/20 text-blue-400',
  enabled: 'bg-green-500/20 text-green-400',
  disabled: 'bg-gray-500/20 text-gray-400',
  rollback: 'bg-yellow-500/20 text-yellow-400',
}

export default function RuleVersionHistory({ ruleId }: RuleVersionHistoryProps) {
  const [selectedVersions, setSelectedVersions] = useState<[number, number] | null>(null)
  const [showDiff, setShowDiff] = useState(false)

  const { data, isLoading } = useListRuleVersionsQuery({ ruleId, limit: 50 })
  const [rollback, { isLoading: isRollingBack }] = useRollbackRuleMutation()

  const handleRollback = async (version: number) => {
    if (!confirm(`Are you sure you want to rollback to version ${version}?`)) return
    try {
      await rollback({ ruleId, version }).unwrap()
    } catch (err) {
      console.error('Failed to rollback:', err)
    }
  }

  const handleCompare = (fromVersion: number, toVersion: number) => {
    setSelectedVersions([fromVersion, toVersion])
    setShowDiff(true)
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-8">
        <RefreshCw className="animate-spin text-muted-foreground" size={24} />
      </div>
    )
  }

  if (!data?.versions?.length) {
    return (
      <div className="text-center py-8">
        <History className="mx-auto text-muted-foreground mb-4" size={48} />
        <h3 className="text-lg font-medium">No version history</h3>
        <p className="text-muted-foreground mt-1">
          Version history will appear here after rule updates
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="font-medium flex items-center gap-2">
          <History size={18} />
          Version History
        </h3>
        <span className="text-sm text-muted-foreground">
          {data.versions.length} versions
        </span>
      </div>

      {/* Version Timeline */}
      <div className="space-y-3">
        {data.versions.map((version, index) => {
          const isLatest = index === 0
          const prevVersion = data.versions[index + 1]

          return (
            <div key={version.id} className="flex gap-4">
              {/* Timeline Line */}
              <div className="flex flex-col items-center">
                <div
                  className={cn(
                    'w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold',
                    isLatest
                      ? 'bg-primary text-primary-foreground'
                      : 'bg-muted text-muted-foreground'
                  )}
                >
                  v{version.version_number}
                </div>
                {index < data.versions.length - 1 && (
                  <div className="w-0.5 h-full bg-border min-h-[40px]" />
                )}
              </div>

              {/* Version Content */}
              <div className="flex-1 pb-4">
                <div className="bg-card rounded-lg border p-3">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span
                        className={cn(
                          'px-2 py-0.5 rounded text-xs capitalize',
                          changeTypeColors[version.change_type] || changeTypeColors.updated
                        )}
                      >
                        {version.change_type}
                      </span>
                      {isLatest && (
                        <span className="px-2 py-0.5 bg-primary/20 text-primary text-xs rounded">
                          Current
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      {prevVersion && (
                        <button
                          onClick={() =>
                            handleCompare(prevVersion.version_number, version.version_number)
                          }
                          className="flex items-center gap-1 px-2 py-1 text-xs border rounded hover:bg-accent"
                          title="Compare with previous"
                        >
                          <GitCompare size={12} />
                          Diff
                        </button>
                      )}
                      {!isLatest && (
                        <button
                          onClick={() => handleRollback(version.version_number)}
                          disabled={isRollingBack}
                          className="flex items-center gap-1 px-2 py-1 text-xs border border-yellow-500/50 text-yellow-400 rounded hover:bg-yellow-500/10"
                          title="Rollback to this version"
                        >
                          <RotateCcw size={12} />
                          Rollback
                        </button>
                      )}
                    </div>
                  </div>

                  {version.change_summary && (
                    <p className="text-sm text-muted-foreground mb-2">
                      {version.change_summary}
                    </p>
                  )}

                  {version.changed_fields && version.changed_fields.length > 0 && (
                    <div className="flex flex-wrap gap-1 mb-2">
                      {version.changed_fields.map((field) => (
                        <span
                          key={field}
                          className="px-2 py-0.5 bg-muted rounded text-xs"
                        >
                          {field}
                        </span>
                      ))}
                    </div>
                  )}

                  <div className="flex items-center gap-4 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <User size={12} />
                      {version.created_by}
                    </span>
                    <span className="flex items-center gap-1">
                      <Clock size={12} />
                      {new Date(version.created_at).toLocaleString()}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {/* Diff Modal */}
      {showDiff && selectedVersions && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card rounded-lg p-6 max-w-4xl w-full mx-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold flex items-center gap-2">
                <GitCompare size={20} />
                Compare Versions
              </h2>
              <button
                onClick={() => setShowDiff(false)}
                className="p-2 hover:bg-accent rounded"
              >
                &times;
              </button>
            </div>
            <RuleDiffViewer
              ruleId={ruleId}
              fromVersion={selectedVersions[0]}
              toVersion={selectedVersions[1]}
            />
          </div>
        </div>
      )}
    </div>
  )
}
