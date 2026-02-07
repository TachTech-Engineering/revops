import { useState } from 'react'
import {
  Sparkles,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  TrendingUp,
  TrendingDown,
  AlertTriangle,
  Clock,
  Target,
  Copy,
  Check,
} from 'lucide-react'
import { cn } from '../../lib/utils'

interface AlertSummarizationPanelProps {
  timeRange?: '24h' | '7d' | '30d'
  className?: string
}

// Mock API hook - in production this would call a real endpoint
const useAlertSummary = (timeRange: string) => {
  return {
    data: {
      executive_summary: `Over the past ${timeRange === '24h' ? '24 hours' : timeRange === '7d' ? 'week' : 'month'}, the security operations team has processed 1,247 alerts with a 94% resolution rate. The most significant trend is a 35% increase in authentication-related alerts, primarily from the Okta and Azure AD integrations. Critical findings include 3 potential credential stuffing campaigns and 2 instances of anomalous data exfiltration patterns that warrant immediate investigation.`,
      key_findings: [
        {
          title: 'Credential Stuffing Campaign Detected',
          severity: 'critical',
          details: 'Multiple failed login attempts from 47 unique IPs targeting 12 executive accounts',
          recommendation: 'Enable MFA enforcement and implement IP-based rate limiting',
        },
        {
          title: 'Unusual Data Transfer Patterns',
          severity: 'high',
          details: 'Large file transfers detected outside business hours from engineering department',
          recommendation: 'Review DLP policies and investigate user activity',
        },
        {
          title: 'Cloud Misconfiguration Alerts Spike',
          severity: 'medium',
          details: '23 new S3 buckets created without encryption enabled',
          recommendation: 'Implement preventive controls via AWS Config rules',
        },
      ],
      metrics: {
        total_alerts: 1247,
        critical_alerts: 23,
        resolved_rate: 94,
        mttr_minutes: 18,
        trend: 'up',
        trend_percentage: 12,
      },
      top_attack_types: [
        { name: 'Credential Access', count: 342, percentage: 27 },
        { name: 'Initial Access', count: 256, percentage: 21 },
        { name: 'Execution', count: 189, percentage: 15 },
        { name: 'Exfiltration', count: 145, percentage: 12 },
        { name: 'Other', count: 315, percentage: 25 },
      ],
      generated_at: new Date().toISOString(),
    },
    isLoading: false,
    refetch: () => {},
  }
}

const severityColors = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/50',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/50',
}

export default function AlertSummarizationPanel({
  timeRange = '24h',
  className,
}: AlertSummarizationPanelProps) {
  const [expanded, setExpanded] = useState(true)
  const [selectedTimeRange, setSelectedTimeRange] = useState(timeRange)
  const [copied, setCopied] = useState(false)
  const { data, isLoading, refetch } = useAlertSummary(selectedTimeRange)

  const handleCopy = async () => {
    if (!data) return
    const text = `
Alert Summary (${selectedTimeRange})
========================
${data.executive_summary}

Key Findings:
${data.key_findings.map((f, i) => `${i + 1}. ${f.title} (${f.severity})\n   ${f.details}\n   Recommendation: ${f.recommendation}`).join('\n\n')}

Metrics:
- Total Alerts: ${data.metrics.total_alerts}
- Critical: ${data.metrics.critical_alerts}
- Resolution Rate: ${data.metrics.resolved_rate}%
- MTTR: ${data.metrics.mttr_minutes} minutes
    `.trim()
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  if (isLoading) {
    return (
      <div className={cn('bg-card rounded-lg border p-6', className)}>
        <div className="flex items-center justify-center py-8">
          <RefreshCw className="animate-spin text-muted-foreground" size={24} />
          <span className="ml-2 text-muted-foreground">Generating AI summary...</span>
        </div>
      </div>
    )
  }

  if (!data) return null

  return (
    <div className={cn('bg-card rounded-lg border overflow-hidden', className)}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b bg-gradient-to-r from-primary/10 to-transparent">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-full bg-primary/20 flex items-center justify-center">
            <Sparkles className="text-primary" size={20} />
          </div>
          <div>
            <h3 className="font-semibold">AI Alert Summary</h3>
            <p className="text-xs text-muted-foreground">
              Generated {new Date(data.generated_at).toLocaleString()}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={selectedTimeRange}
            onChange={(e) => setSelectedTimeRange(e.target.value as typeof selectedTimeRange)}
            className="text-sm bg-background border rounded-md px-2 py-1"
          >
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
          <button
            onClick={() => refetch()}
            className="p-2 hover:bg-accent rounded-md"
            title="Regenerate summary"
          >
            <RefreshCw size={16} />
          </button>
          <button
            onClick={handleCopy}
            className="p-2 hover:bg-accent rounded-md"
            title="Copy summary"
          >
            {copied ? <Check size={16} className="text-green-400" /> : <Copy size={16} />}
          </button>
          <button
            onClick={() => setExpanded(!expanded)}
            className="p-2 hover:bg-accent rounded-md"
          >
            {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>
        </div>
      </div>

      {expanded && (
        <div className="p-4 space-y-6">
          {/* Key Metrics */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-muted/50 rounded-lg p-3 text-center">
              <p className="text-2xl font-bold">{data.metrics.total_alerts.toLocaleString()}</p>
              <p className="text-xs text-muted-foreground">Total Alerts</p>
              <div className={cn(
                'flex items-center justify-center gap-1 text-xs mt-1',
                data.metrics.trend === 'up' ? 'text-red-400' : 'text-green-400'
              )}>
                {data.metrics.trend === 'up' ? <TrendingUp size={12} /> : <TrendingDown size={12} />}
                {data.metrics.trend_percentage}%
              </div>
            </div>
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-red-400">{data.metrics.critical_alerts}</p>
              <p className="text-xs text-muted-foreground">Critical</p>
            </div>
            <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-green-400">{data.metrics.resolved_rate}%</p>
              <p className="text-xs text-muted-foreground">Resolved</p>
            </div>
            <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-blue-400">{data.metrics.mttr_minutes}m</p>
              <p className="text-xs text-muted-foreground">Avg MTTR</p>
            </div>
          </div>

          {/* Executive Summary */}
          <div>
            <h4 className="font-medium mb-2 flex items-center gap-2">
              <Target size={16} />
              Executive Summary
            </h4>
            <p className="text-sm text-muted-foreground leading-relaxed">
              {data.executive_summary}
            </p>
          </div>

          {/* Key Findings */}
          <div>
            <h4 className="font-medium mb-3 flex items-center gap-2">
              <AlertTriangle size={16} />
              Key Findings
            </h4>
            <div className="space-y-3">
              {data.key_findings.map((finding, index) => (
                <div
                  key={index}
                  className={cn(
                    'p-3 rounded-lg border',
                    severityColors[finding.severity as keyof typeof severityColors]
                  )}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-medium">{finding.title}</span>
                    <span className="text-xs uppercase">{finding.severity}</span>
                  </div>
                  <p className="text-sm opacity-90 mb-2">{finding.details}</p>
                  <p className="text-xs opacity-75">
                    <strong>Recommendation:</strong> {finding.recommendation}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* Attack Type Distribution */}
          <div>
            <h4 className="font-medium mb-3 flex items-center gap-2">
              <Clock size={16} />
              Top Attack Types
            </h4>
            <div className="space-y-2">
              {data.top_attack_types.map((type) => (
                <div key={type.name} className="flex items-center gap-3">
                  <span className="text-sm w-32 truncate">{type.name}</span>
                  <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full bg-primary rounded-full"
                      style={{ width: `${type.percentage}%` }}
                    />
                  </div>
                  <span className="text-sm text-muted-foreground w-12 text-right">
                    {type.count}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
