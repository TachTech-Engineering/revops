import { useState } from 'react'
import {
  BarChart3,
  TrendingUp,
  TrendingDown,
  Shield,
  AlertTriangle,
  Clock,
  Users,
  Target,
  CheckCircle,
  Download,
  RefreshCw,
  Calendar,
  ChevronRight,
} from 'lucide-react'
import { cn } from '../lib/utils'

interface MetricCard {
  title: string
  value: string | number
  change: number
  trend: 'up' | 'down'
  isGood: boolean
  description: string
}

const mockMetrics: MetricCard[] = [
  {
    title: 'Total Alerts',
    value: '12,847',
    change: 15,
    trend: 'up',
    isGood: false,
    description: 'vs last month',
  },
  {
    title: 'Mean Time to Resolve',
    value: '18 min',
    change: 12,
    trend: 'down',
    isGood: true,
    description: 'vs last month',
  },
  {
    title: 'Critical Incidents',
    value: 3,
    change: 50,
    trend: 'down',
    isGood: true,
    description: 'vs last month',
  },
  {
    title: 'Compliance Score',
    value: '92%',
    change: 3,
    trend: 'up',
    isGood: true,
    description: 'vs last month',
  },
]

const mockRiskAreas = [
  { name: 'Credential Access Attempts', count: 342, severity: 'high', trend: 'up' },
  { name: 'Data Exfiltration Risk', count: 28, severity: 'critical', trend: 'down' },
  { name: 'Misconfiguration Findings', count: 156, severity: 'medium', trend: 'stable' },
  { name: 'Compliance Gaps', count: 12, severity: 'high', trend: 'down' },
]

const mockTeamPerformance = [
  { name: 'Alice Chen', resolved: 142, mttr: 15, accuracy: 98 },
  { name: 'Bob Smith', resolved: 128, mttr: 18, accuracy: 95 },
  { name: 'Carol Davis', resolved: 115, mttr: 12, accuracy: 97 },
  { name: 'Dave Wilson', resolved: 98, mttr: 22, accuracy: 92 },
]

export default function ExecutiveSummaryPage() {
  const [timeRange, setTimeRange] = useState('30d')
  const [isExporting, setIsExporting] = useState(false)

  const handleExport = async () => {
    setIsExporting(true)
    await new Promise((resolve) => setTimeout(resolve, 2000))
    setIsExporting(false)
  }

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
        {mockMetrics.map((metric) => (
          <div key={metric.title} className="bg-card rounded-lg border p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-muted-foreground">{metric.title}</span>
              <div
                className={cn(
                  'flex items-center gap-1 text-xs',
                  metric.isGood ? 'text-green-400' : 'text-red-400'
                )}
              >
                {metric.trend === 'up' ? (
                  <TrendingUp size={12} />
                ) : (
                  <TrendingDown size={12} />
                )}
                {metric.change}%
              </div>
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
            {mockRiskAreas.map((risk) => (
              <div
                key={risk.name}
                className="flex items-center justify-between p-3 bg-muted/50 rounded-lg"
              >
                <div className="flex items-center gap-3">
                  <div
                    className={cn(
                      'w-2 h-2 rounded-full',
                      risk.severity === 'critical'
                        ? 'bg-red-500'
                        : risk.severity === 'high'
                        ? 'bg-orange-500'
                        : 'bg-yellow-500'
                    )}
                  />
                  <span className="font-medium">{risk.name}</span>
                </div>
                <div className="flex items-center gap-4">
                  <span className="text-lg font-bold">{risk.count}</span>
                  {risk.trend === 'up' ? (
                    <TrendingUp size={14} className="text-red-400" />
                  ) : risk.trend === 'down' ? (
                    <TrendingDown size={14} className="text-green-400" />
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </div>
              </div>
            ))}
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
                {mockTeamPerformance.map((member) => (
                  <tr key={member.name}>
                    <td className="py-3 font-medium">{member.name}</td>
                    <td className="py-3 text-right">{member.resolved}</td>
                    <td className="py-3 text-right">{member.mttr}m</td>
                    <td className="py-3 text-right">
                      <span
                        className={cn(
                          member.accuracy >= 95
                            ? 'text-green-400'
                            : member.accuracy >= 90
                            ? 'text-yellow-400'
                            : 'text-red-400'
                        )}
                      >
                        {member.accuracy}%
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
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
                strokeDasharray="308 352"
                className="text-green-500"
              />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="text-center">
                <span className="text-2xl font-bold">87</span>
                <p className="text-xs text-muted-foreground">/ 100</p>
              </div>
            </div>
          </div>
          <p className="text-center text-sm text-muted-foreground">
            Your security score is <span className="text-green-400">above average</span>
          </p>
        </div>

        <div className="bg-card rounded-lg border p-4">
          <div className="flex items-center gap-2 mb-4">
            <Target className="text-primary" size={20} />
            <h3 className="font-semibold">Detection Coverage</h3>
          </div>
          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span>MITRE ATT&CK</span>
                <span className="font-medium">78%</span>
              </div>
              <div className="h-2 bg-muted rounded-full overflow-hidden">
                <div className="h-full bg-primary rounded-full" style={{ width: '78%' }} />
              </div>
            </div>
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span>Log Sources</span>
                <span className="font-medium">92%</span>
              </div>
              <div className="h-2 bg-muted rounded-full overflow-hidden">
                <div className="h-full bg-green-500 rounded-full" style={{ width: '92%' }} />
              </div>
            </div>
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span>Active Rules</span>
                <span className="font-medium">156 / 180</span>
              </div>
              <div className="h-2 bg-muted rounded-full overflow-hidden">
                <div className="h-full bg-blue-500 rounded-full" style={{ width: '87%' }} />
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
            <div className="flex items-center justify-between p-3 bg-green-500/10 rounded-lg">
              <span className="text-sm">Critical (15m)</span>
              <span className="font-bold text-green-400">98%</span>
            </div>
            <div className="flex items-center justify-between p-3 bg-green-500/10 rounded-lg">
              <span className="text-sm">High (1h)</span>
              <span className="font-bold text-green-400">95%</span>
            </div>
            <div className="flex items-center justify-between p-3 bg-yellow-500/10 rounded-lg">
              <span className="text-sm">Medium (4h)</span>
              <span className="font-bold text-yellow-400">89%</span>
            </div>
            <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
              <span className="text-sm">Low (24h)</span>
              <span className="font-bold">100%</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
