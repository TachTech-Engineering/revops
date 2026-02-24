import { useState, useMemo } from 'react'
import {
  BarChart3,
  TrendingUp,
  TrendingDown,
  Shield,
  AlertTriangle,
  Users,
  Target,
  CheckCircle,
  Download,
  RefreshCw,
  ChevronRight,
  Loader2,
} from 'lucide-react'
import { cn } from '../lib/utils'
import {
  useGetExecutiveMetricsQuery,
  useGetTopRiskAreasQuery,
  useGetTeamPerformanceQuery,
  useGetSLAComplianceQuery,
  useExportExecutiveReportMutation,
} from '../api/pantherApi'

interface MetricCard {
  title: string
  value: string | number
  change: number | null
  trend: 'up' | 'down' | 'stable'
  isGood: boolean
  description: string
}

function getDaysFromTimeRange(timeRange: string): number {
  switch (timeRange) {
    case '7d': return 7
    case '30d': return 30
    case '90d': return 90
    case 'ytd': {
      const now = new Date()
      const startOfYear = new Date(now.getFullYear(), 0, 1)
      return Math.ceil((now.getTime() - startOfYear.getTime()) / (1000 * 60 * 60 * 24))
    }
    default: return 30
  }
}

function formatHours(hours: number): string {
  if (hours < 1) {
    return `${Math.round(hours * 60)} min`
  } else if (hours >= 24) {
    return `${Math.round(hours / 24)} days`
  } else {
    return `${Math.round(hours)} hr`
  }
}

export default function ExecutiveSummaryPage() {
  const [timeRange, setTimeRange] = useState('30d')

  const days = getDaysFromTimeRange(timeRange)

  // Fetch executive metrics
  const {
    data: metricsData,
    isLoading: metricsLoading,
    error: metricsError,
  } = useGetExecutiveMetricsQuery({ days })

  // Fetch risk areas
  const {
    data: riskAreasData,
    isLoading: riskAreasLoading,
  } = useGetTopRiskAreasQuery({ days, limit: 5 })

  // Fetch team performance
  const {
    data: teamData,
    isLoading: teamLoading,
  } = useGetTeamPerformanceQuery({ days })

  // Fetch SLA compliance
  const {
    data: slaData,
    isLoading: slaLoading,
  } = useGetSLAComplianceQuery({ days })

  // Export mutation
  const [exportReport, { isLoading: isExporting }] = useExportExecutiveReportMutation()

  // Build metric cards from API data
  const metricCards: MetricCard[] = useMemo(() => {
    if (!metricsData) return []

    return [
      {
        title: 'Total Alerts',
        value: metricsData.total_alerts.value.toLocaleString(),
        change: metricsData.total_alerts.change_percent,
        trend: metricsData.total_alerts.trend,
        isGood: metricsData.total_alerts.trend === 'down',
        description: 'vs previous period',
      },
      {
        title: 'Mean Time to Resolve',
        value: formatHours(metricsData.mttr_hours.value),
        change: metricsData.mttr_hours.change_percent,
        trend: metricsData.mttr_hours.trend,
        isGood: metricsData.mttr_hours.trend === 'down',
        description: 'vs previous period',
      },
      {
        title: 'Critical Incidents',
        value: metricsData.critical_incidents.value,
        change: metricsData.critical_incidents.change_percent,
        trend: metricsData.critical_incidents.trend,
        isGood: metricsData.critical_incidents.trend === 'down',
        description: 'vs previous period',
      },
      {
        title: 'Compliance Score',
        value: `${Math.round(metricsData.compliance_score.value)}%`,
        change: metricsData.compliance_score.change_percent,
        trend: metricsData.compliance_score.trend,
        isGood: metricsData.compliance_score.trend === 'up' || metricsData.compliance_score.value >= 90,
        description: 'vs previous period',
      },
    ]
  }, [metricsData])

  const handleExport = async () => {
    const endDate = new Date()
    const startDate = new Date()
    startDate.setDate(startDate.getDate() - days)

    try {
      await exportReport({
        start_date: startDate.toISOString(),
        end_date: endDate.toISOString(),
        include_metrics: true,
        include_risk_areas: true,
        include_team_performance: true,
        include_sla_compliance: true,
        format: 'pdf',
      }).unwrap()
    } catch (error) {
      console.error('Export failed:', error)
    }
  }

  const isLoading = metricsLoading || riskAreasLoading || teamLoading || slaLoading

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <span className="ml-2 text-muted-foreground">Loading executive summary...</span>
      </div>
    )
  }

  if (metricsError) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <AlertTriangle className="h-12 w-12 text-yellow-500 mx-auto mb-4" />
          <h3 className="text-lg font-semibold">Failed to load executive summary</h3>
          <p className="text-muted-foreground">Please try refreshing the page.</p>
        </div>
      </div>
    )
  }

  // Calculate security posture score
  const securityScore = metricsData
    ? Math.round(
        (metricsData.compliance_score.value * 0.3) +
        (Math.max(0, 100 - metricsData.false_positive_rate.value) * 0.3) +
        (Math.min(100, (metricsData.resolved_incidents.value / Math.max(1, metricsData.open_incidents.value + metricsData.resolved_incidents.value)) * 100) * 0.4)
      )
    : 0

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <BarChart3 className="text-primary" />
            Executive Summary
          </h1>
          <p className="text-muted-foreground mt-1">
            High-level security metrics and insights
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="px-3 py-2 bg-background border rounded-md"
          >
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
            <option value="90d">Last 90 Days</option>
            <option value="ytd">Year to Date</option>
          </select>
          <button
            onClick={handleExport}
            disabled={isExporting}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
          >
            {isExporting ? (
              <>
                <RefreshCw size={16} className="animate-spin" />
                Exporting...
              </>
            ) : (
              <>
                <Download size={16} />
                Export PDF
              </>
            )}
          </button>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {metricCards.map((metric) => (
          <div key={metric.title} className="bg-card rounded-lg border p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-muted-foreground">{metric.title}</span>
              {metric.change !== null && (
                <div
                  className={cn(
                    'flex items-center gap-1 text-xs',
                    metric.isGood ? 'text-green-400' : 'text-red-400'
                  )}
                >
                  {metric.trend === 'up' ? (
                    <TrendingUp size={12} />
                  ) : metric.trend === 'down' ? (
                    <TrendingDown size={12} />
                  ) : null}
                  {Math.abs(metric.change)}%
                </div>
              )}
            </div>
            <p className="text-3xl font-bold">{metric.value}</p>
            <p className="text-xs text-muted-foreground mt-1">{metric.description}</p>
          </div>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Risk Overview */}
        <div className="bg-card rounded-lg border">
          <div className="p-4 border-b flex items-center justify-between">
            <h2 className="font-semibold flex items-center gap-2">
              <AlertTriangle size={18} />
              Top Risk Areas
            </h2>
            <button className="text-sm text-primary hover:underline flex items-center gap-1">
              View All <ChevronRight size={14} />
            </button>
          </div>
          <div className="p-4 space-y-3">
            {riskAreasData?.risk_areas && riskAreasData.risk_areas.length > 0 ? (
              riskAreasData.risk_areas.map((risk) => (
                <div
                  key={risk.category}
                  className="flex items-center justify-between p-3 bg-muted/50 rounded-lg"
                >
                  <div className="flex items-center gap-3">
                    <div
                      className={cn(
                        'w-2 h-2 rounded-full',
                        risk.severity_score >= 80
                          ? 'bg-red-500'
                          : risk.severity_score >= 60
                          ? 'bg-orange-500'
                          : 'bg-yellow-500'
                      )}
                    />
                    <div>
                      <span className="font-medium">{risk.category}</span>
                      <p className="text-xs text-muted-foreground">{risk.description}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <span className="text-lg font-bold">{risk.alert_count}</span>
                    {risk.trend === 'up' ? (
                      <TrendingUp size={14} className="text-red-400" />
                    ) : risk.trend === 'down' ? (
                      <TrendingDown size={14} className="text-green-400" />
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-4 text-muted-foreground">
                No risk areas identified
              </div>
            )}
          </div>
        </div>

        {/* Team Performance */}
        <div className="bg-card rounded-lg border">
          <div className="p-4 border-b flex items-center justify-between">
            <h2 className="font-semibold flex items-center gap-2">
              <Users size={18} />
              Team Performance
            </h2>
            <button className="text-sm text-primary hover:underline flex items-center gap-1">
              Full Report <ChevronRight size={14} />
            </button>
          </div>
          <div className="p-4">
            {teamData?.team_members && teamData.team_members.length > 0 ? (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-muted-foreground">
                    <th className="text-left pb-3">Analyst</th>
                    <th className="text-right pb-3">Resolved</th>
                    <th className="text-right pb-3">Avg MTTR</th>
                    <th className="text-right pb-3">Accuracy</th>
                  </tr>
                </thead>
                <tbody className="divide-y">
                  {teamData.team_members.slice(0, 5).map((member) => (
                    <tr key={member.user_id}>
                      <td className="py-3 font-medium">{member.display_name}</td>
                      <td className="py-3 text-right">{member.incidents_resolved}</td>
                      <td className="py-3 text-right">{formatHours(member.avg_resolution_hours)}</td>
                      <td className="py-3 text-right">
                        <span
                          className={cn(
                            member.accuracy_rate >= 95
                              ? 'text-green-400'
                              : member.accuracy_rate >= 90
                              ? 'text-yellow-400'
                              : 'text-red-400'
                          )}
                        >
                          {Math.round(member.accuracy_rate)}%
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="text-center py-4 text-muted-foreground">
                No team performance data available
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Compliance & Security Posture */}
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="bg-card rounded-lg border p-4">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="text-green-400" size={20} />
            <h3 className="font-semibold">Security Posture</h3>
          </div>
          <div className="relative w-32 h-32 mx-auto mb-4">
            <svg className="w-full h-full -rotate-90">
              <circle
                cx="64"
                cy="64"
                r="56"
                fill="none"
                stroke="currentColor"
                strokeWidth="8"
                className="text-muted"
              />
              <circle
                cx="64"
                cy="64"
                r="56"
                fill="none"
                stroke="currentColor"
                strokeWidth="8"
                strokeDasharray={`${(securityScore / 100) * 352} 352`}
                className={cn(
                  securityScore >= 80 ? 'text-green-500' :
                  securityScore >= 60 ? 'text-yellow-500' :
                  'text-red-500'
                )}
              />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="text-center">
                <span className="text-2xl font-bold">{securityScore}</span>
                <p className="text-xs text-muted-foreground">/ 100</p>
              </div>
            </div>
          </div>
          <p className="text-center text-sm text-muted-foreground">
            Your security score is{' '}
            <span className={cn(
              securityScore >= 80 ? 'text-green-400' :
              securityScore >= 60 ? 'text-yellow-400' :
              'text-red-400'
            )}>
              {securityScore >= 80 ? 'above average' :
               securityScore >= 60 ? 'average' :
               'below average'}
            </span>
          </p>
        </div>

        <div className="bg-card rounded-lg border p-4">
          <div className="flex items-center gap-2 mb-4">
            <Target className="text-primary" size={20} />
            <h3 className="font-semibold">Key Metrics</h3>
          </div>
          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span>Open Incidents</span>
                <span className="font-medium">{metricsData?.open_incidents.value || 0}</span>
              </div>
              <div className="h-2 bg-muted rounded-full overflow-hidden">
                <div
                  className="h-full bg-orange-500 rounded-full"
                  style={{ width: `${Math.min(100, (metricsData?.open_incidents.value || 0) / 10 * 100)}%` }}
                />
              </div>
            </div>
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span>Resolved This Period</span>
                <span className="font-medium">{metricsData?.resolved_incidents.value || 0}</span>
              </div>
              <div className="h-2 bg-muted rounded-full overflow-hidden">
                <div
                  className="h-full bg-green-500 rounded-full"
                  style={{ width: `${Math.min(100, (metricsData?.resolved_incidents.value || 0) / 50 * 100)}%` }}
                />
              </div>
            </div>
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span>False Positive Rate</span>
                <span className="font-medium">{Math.round(metricsData?.false_positive_rate.value || 0)}%</span>
              </div>
              <div className="h-2 bg-muted rounded-full overflow-hidden">
                <div
                  className={cn(
                    'h-full rounded-full',
                    (metricsData?.false_positive_rate.value || 0) <= 10 ? 'bg-green-500' :
                    (metricsData?.false_positive_rate.value || 0) <= 25 ? 'bg-yellow-500' :
                    'bg-red-500'
                  )}
                  style={{ width: `${metricsData?.false_positive_rate.value || 0}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        <div className="bg-card rounded-lg border p-4">
          <div className="flex items-center gap-2 mb-4">
            <CheckCircle className="text-green-400" size={20} />
            <h3 className="font-semibold">SLA Compliance</h3>
          </div>
          <div className="space-y-3">
            {slaData?.sla_metrics && slaData.sla_metrics.length > 0 ? (
              slaData.sla_metrics.slice(0, 4).map((sla) => (
                <div
                  key={sla.sla_name}
                  className={cn(
                    'flex items-center justify-between p-3 rounded-lg',
                    sla.compliance_rate >= 95 ? 'bg-green-500/10' :
                    sla.compliance_rate >= 80 ? 'bg-yellow-500/10' :
                    'bg-red-500/10'
                  )}
                >
                  <span className="text-sm">{sla.sla_name}</span>
                  <span className={cn(
                    'font-bold',
                    sla.compliance_rate >= 95 ? 'text-green-400' :
                    sla.compliance_rate >= 80 ? 'text-yellow-400' :
                    'text-red-400'
                  )}>
                    {Math.round(sla.compliance_rate)}%
                  </span>
                </div>
              ))
            ) : (
              <>
                <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                  <span className="text-sm">No SLA data</span>
                  <span className="font-bold text-muted-foreground">—</span>
                </div>
              </>
            )}
            {slaData && (
              <div className="pt-2 border-t">
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Overall Compliance</span>
                  <span className={cn(
                    'font-bold',
                    slaData.overall_compliance_rate >= 95 ? 'text-green-400' :
                    slaData.overall_compliance_rate >= 80 ? 'text-yellow-400' :
                    'text-red-400'
                  )}>
                    {Math.round(slaData.overall_compliance_rate)}%
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
