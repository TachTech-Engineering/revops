import { useState } from 'react'
import {
  Activity,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Clock,
  TrendingDown,
  Filter,
  ChevronRight,
} from 'lucide-react'
import { Link } from 'react-router-dom'
import {
  useListRuleHealthQuery,
  useListStaleRulesQuery,
  useGetRuleHealthStatsQuery,
  useRefreshRuleHealthMutation,
} from '../api/pantherApi'
import { cn } from '../lib/utils'

const healthScoreColors = (score: number): string => {
  if (score >= 80) return 'text-green-400'
  if (score >= 60) return 'text-yellow-400'
  if (score >= 40) return 'text-orange-400'
  return 'text-red-400'
}

const healthScoreBg = (score: number): string => {
  if (score >= 80) return 'bg-green-500/20'
  if (score >= 60) return 'bg-yellow-500/20'
  if (score >= 40) return 'bg-orange-500/20'
  return 'bg-red-500/20'
}

export default function RuleHealthDashboardPage() {
  const [view, setView] = useState<'all' | 'stale'>('all')
  const [severityFilter, setSeverityFilter] = useState<string>('')

  const { data: stats, isLoading: statsLoading } = useGetRuleHealthStatsQuery()
  const { data: ruleHealth, isLoading: healthLoading, refetch } = useListRuleHealthQuery({
    isStale: view === 'stale' ? true : undefined,
    severity: severityFilter || undefined,
    page: 1,
    pageSize: 50,
  })
  const { data: staleRules } = useListStaleRulesQuery({ pageSize: 10 })
  const [refreshHealth, { isLoading: isRefreshing }] = useRefreshRuleHealthMutation()

  const handleRefresh = async () => {
    try {
      await refreshHealth().unwrap()
      refetch()
    } catch (err) {
      console.error('Failed to refresh health:', err)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Activity className="text-primary" />
            Rule Health Dashboard
          </h1>
          <p className="text-muted-foreground mt-1">
            Monitor rule effectiveness and detect stale rules
          </p>
        </div>
        <button
          onClick={handleRefresh}
          disabled={isRefreshing}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
        >
          <RefreshCw size={16} className={isRefreshing ? 'animate-spin' : ''} />
          Refresh Health Data
        </button>
      </div>

      {/* Stats Cards */}
      {statsLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="bg-card rounded-lg border p-4 animate-pulse">
              <div className="h-4 bg-muted rounded w-1/2 mb-2" />
              <div className="h-8 bg-muted rounded w-3/4" />
            </div>
          ))}
        </div>
      ) : stats && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-card rounded-lg border p-4">
            <p className="text-sm text-muted-foreground mb-1">Total Rules</p>
            <p className="text-3xl font-bold">{stats.total_rules}</p>
          </div>
          <div className="bg-card rounded-lg border p-4">
            <p className="text-sm text-muted-foreground mb-1">Healthy Rules</p>
            <p className="text-3xl font-bold text-green-400">{stats.healthy_rules}</p>
          </div>
          <div className="bg-card rounded-lg border p-4">
            <p className="text-sm text-muted-foreground mb-1">Stale Rules</p>
            <p className="text-3xl font-bold text-red-400">{stats.stale_rules}</p>
          </div>
          <div className="bg-card rounded-lg border p-4">
            <p className="text-sm text-muted-foreground mb-1">Average Health Score</p>
            <p className={cn('text-3xl font-bold', healthScoreColors(stats.average_health_score || 0))}>
              {(stats.average_health_score || 0).toFixed(0)}%
            </p>
          </div>
        </div>
      )}

      {/* Stale Rules Alert */}
      {staleRules && staleRules.rules && staleRules.rules.length > 0 && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <AlertTriangle className="text-yellow-400" />
              <div>
                <h3 className="font-medium text-yellow-400">
                  {staleRules.total} Stale Rules Detected
                </h3>
                <p className="text-sm text-muted-foreground">
                  These rules haven't triggered alerts in over 90 days
                </p>
              </div>
            </div>
            <button
              onClick={() => setView('stale')}
              className="flex items-center gap-1 px-3 py-1.5 text-sm border border-yellow-500/50 text-yellow-400 rounded hover:bg-yellow-500/10"
            >
              View All <ChevronRight size={14} />
            </button>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 bg-card rounded-lg border p-1">
          <button
            onClick={() => setView('all')}
            className={cn(
              'px-4 py-1.5 rounded text-sm transition-colors',
              view === 'all' ? 'bg-primary text-primary-foreground' : 'hover:bg-accent'
            )}
          >
            All Rules
          </button>
          <button
            onClick={() => setView('stale')}
            className={cn(
              'px-4 py-1.5 rounded text-sm transition-colors',
              view === 'stale' ? 'bg-primary text-primary-foreground' : 'hover:bg-accent'
            )}
          >
            Stale Only
          </button>
        </div>
        <div className="flex items-center gap-2">
          <Filter size={16} className="text-muted-foreground" />
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-1.5 bg-background border rounded-md text-sm"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* Rules List */}
      {healthLoading ? (
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="animate-spin text-muted-foreground" size={24} />
        </div>
      ) : !ruleHealth?.rules?.length ? (
        <div className="text-center py-12 bg-card rounded-lg border">
          <Activity className="mx-auto text-muted-foreground mb-4" size={48} />
          <h3 className="text-lg font-medium">No rules found</h3>
          <p className="text-muted-foreground mt-1">
            {view === 'stale' ? 'No stale rules detected' : 'No rule health data available'}
          </p>
        </div>
      ) : (
        <div className="bg-card rounded-lg border overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="text-left p-4 font-medium">Rule</th>
                <th className="text-left p-4 font-medium">Health Score</th>
                <th className="text-left p-4 font-medium">Last Triggered</th>
                <th className="text-left p-4 font-medium">30d Triggers</th>
                <th className="text-left p-4 font-medium">90d Triggers</th>
                <th className="text-left p-4 font-medium">Status</th>
                <th className="text-right p-4 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {ruleHealth.rules.map((rule) => (
                <tr key={rule.id} className="border-b last:border-0 hover:bg-muted/30">
                  <td className="p-4">
                    <div>
                      <p className="font-medium">{rule.rule_name || rule.rule_id}</p>
                      <p className="text-xs text-muted-foreground">{rule.rule_id}</p>
                    </div>
                  </td>
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      <div
                        className={cn(
                          'w-10 h-10 rounded-full flex items-center justify-center font-bold',
                          healthScoreBg(rule.health_score),
                          healthScoreColors(rule.health_score)
                        )}
                      >
                        {rule.health_score}
                      </div>
                    </div>
                  </td>
                  <td className="p-4">
                    {rule.last_triggered_at ? (
                      <div className="flex items-center gap-2 text-sm">
                        <Clock size={14} className="text-muted-foreground" />
                        {new Date(rule.last_triggered_at).toLocaleDateString()}
                      </div>
                    ) : (
                      <span className="text-muted-foreground text-sm">Never</span>
                    )}
                  </td>
                  <td className="p-4">
                    <span
                      className={cn(
                        'font-medium',
                        rule.trigger_count_30d > 0 ? 'text-green-400' : 'text-muted-foreground'
                      )}
                    >
                      {rule.trigger_count_30d}
                    </span>
                  </td>
                  <td className="p-4">
                    <span
                      className={cn(
                        'font-medium',
                        rule.trigger_count_90d > 0 ? 'text-green-400' : 'text-muted-foreground'
                      )}
                    >
                      {rule.trigger_count_90d}
                    </span>
                  </td>
                  <td className="p-4">
                    {rule.is_stale ? (
                      <span className="flex items-center gap-1 px-2 py-1 bg-red-500/20 text-red-400 text-xs rounded">
                        <TrendingDown size={12} />
                        Stale
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 px-2 py-1 bg-green-500/20 text-green-400 text-xs rounded">
                        <CheckCircle size={12} />
                        Healthy
                      </span>
                    )}
                  </td>
                  <td className="p-4">
                    <div className="flex items-center justify-end gap-2">
                      <Link
                        to={`/rules/${rule.rule_id}`}
                        className="flex items-center gap-1 px-3 py-1.5 text-sm border rounded hover:bg-accent"
                      >
                        View <ChevronRight size={14} />
                      </Link>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
