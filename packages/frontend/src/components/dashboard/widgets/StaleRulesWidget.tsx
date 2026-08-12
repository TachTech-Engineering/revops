import { Link } from 'react-router-dom'
import {
  RefreshCw,
  CheckCircle,
  ChevronRight,
  Clock,
  TrendingDown,
} from 'lucide-react'
import { useListStaleRulesQuery, useGetRuleHealthStatsQuery } from '../../../api/pantherApi'
import { cn } from '../../../lib/utils'

interface StaleRulesWidgetProps {
  config?: {
    limit?: number
  }
}

export default function StaleRulesWidget({ config }: StaleRulesWidgetProps) {
  const { data: stats, isLoading: statsLoading } = useGetRuleHealthStatsQuery()
  const { data: staleRules, isLoading } = useListStaleRulesQuery({
    pageSize: config?.limit || 5,
  })

  if (isLoading || statsLoading) {
    return (
      <div className="h-full flex items-center justify-center">
        <RefreshCw className="animate-spin text-muted-foreground" size={24} />
      </div>
    )
  }

  const hasStaleRules = staleRules?.rules && staleRules.rules.length > 0

  return (
    <div className="h-full flex flex-col p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-medium flex items-center gap-2">
          <TrendingDown size={16} className="text-yellow-400" />
          Stale Rules
        </h3>
        <Link
          to="/rule-health"
          className="text-xs text-primary hover:underline flex items-center gap-1"
        >
          View All <ChevronRight size={12} />
        </Link>
      </div>

      {/* Summary Stats */}
      {stats && (
        <div className="grid grid-cols-2 gap-2 mb-4">
          <div className="bg-muted/50 rounded-lg p-2 text-center">
            <p className="text-xs text-muted-foreground">Total Rules</p>
            <p className="text-lg font-bold">{stats.total_rules}</p>
          </div>
          <div
            className={cn(
              'rounded-lg p-2 text-center',
              stats.stale_rules > 0
                ? 'bg-yellow-500/10 border border-yellow-500/30'
                : 'bg-green-500/10 border border-green-500/30'
            )}
          >
            <p className="text-xs text-muted-foreground">Stale</p>
            <p
              className={cn(
                'text-lg font-bold',
                stats.stale_rules > 0 ? 'text-yellow-400' : 'text-green-400'
              )}
            >
              {stats.stale_rules}
            </p>
          </div>
        </div>
      )}

      {!hasStaleRules ? (
        <div className="flex-1 flex flex-col items-center justify-center text-center">
          <CheckCircle className="text-green-400 mb-2" size={32} />
          <p className="text-sm text-muted-foreground">All rules are healthy</p>
          <p className="text-xs text-muted-foreground">
            No stale rules detected in the last 90 days
          </p>
        </div>
      ) : (
        <div className="flex-1 space-y-2 overflow-y-auto">
          {staleRules.rules.map((rule) => (
            <Link
              key={rule.id}
              to={`/rules/${rule.rule_id}`}
              className="block p-2 bg-muted/50 rounded-lg hover:bg-muted transition-colors"
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-medium truncate max-w-[70%]">
                  {rule.rule_name || rule.rule_id}
                </span>
                <span className="px-1.5 py-0.5 bg-yellow-500/20 text-yellow-400 text-xs rounded">
                  Stale
                </span>
              </div>
              <div className="flex items-center gap-3 text-xs text-muted-foreground">
                <span className="flex items-center gap-1">
                  <Clock size={10} />
                  {rule.last_triggered_at
                    ? `Last: ${new Date(rule.last_triggered_at).toLocaleDateString()}`
                    : 'Never triggered'}
                </span>
                <span>Score: {rule.health_score}</span>
              </div>
            </Link>
          ))}
        </div>
      )}

      {hasStaleRules && staleRules.total > (config?.limit || 5) && (
        <p className="text-xs text-muted-foreground text-center mt-2">
          +{staleRules.total - (config?.limit || 5)} more stale rules
        </p>
      )}
    </div>
  )
}
