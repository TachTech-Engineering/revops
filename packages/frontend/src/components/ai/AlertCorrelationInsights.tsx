import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  GitBranch,
  RefreshCw,
  ChevronRight,
  AlertTriangle,
  Clock,
  User,
  Server,
  Globe,
  Sparkles,
  ExternalLink,
} from 'lucide-react'
import { cn } from '../../lib/utils'

interface AlertCorrelationInsightsProps {
  alertId: string
  className?: string
}

// Mock API hook - in production this would call a real endpoint
const useAlertCorrelation = (alertId: string) => {
  return {
    data: {
      alert_id: alertId,
      correlation_summary: 'This alert is part of a potential attack chain involving credential access followed by lateral movement. 5 related alerts have been identified across 3 hosts within the same time window.',
      related_alerts: [
        {
          id: 'alert-001',
          title: 'Failed SSH Login Attempts',
          severity: 'medium',
          timestamp: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
          correlation_reason: 'Same source IP address',
          correlation_score: 0.95,
        },
        {
          id: 'alert-002',
          title: 'Suspicious PowerShell Execution',
          severity: 'high',
          timestamp: new Date(Date.now() - 25 * 60 * 1000).toISOString(),
          correlation_reason: 'Same target host',
          correlation_score: 0.88,
        },
        {
          id: 'alert-003',
          title: 'Unusual Process Creation',
          severity: 'medium',
          timestamp: new Date(Date.now() - 20 * 60 * 1000).toISOString(),
          correlation_reason: 'Same user account',
          correlation_score: 0.82,
        },
        {
          id: 'alert-004',
          title: 'Lateral Movement Detected',
          severity: 'critical',
          timestamp: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
          correlation_reason: 'Sequential attack pattern',
          correlation_score: 0.91,
        },
      ],
      common_entities: [
        { type: 'ip', value: '192.168.1.105', alerts_count: 4 },
        { type: 'user', value: 'admin@company.com', alerts_count: 3 },
        { type: 'host', value: 'WORKSTATION-42', alerts_count: 3 },
      ],
      attack_chain: {
        detected: true,
        stages: [
          { name: 'Initial Access', technique: 'T1078', status: 'confirmed' },
          { name: 'Execution', technique: 'T1059', status: 'confirmed' },
          { name: 'Persistence', technique: 'T1053', status: 'suspected' },
          { name: 'Lateral Movement', technique: 'T1021', status: 'confirmed' },
        ],
      },
      confidence: 0.89,
      suggested_incident: true,
    },
    isLoading: false,
  }
}

const severityColors = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/50',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/50',
}

const entityIcons = {
  ip: Globe,
  user: User,
  host: Server,
}

function timeAgo(timestamp: string): string {
  const seconds = Math.floor((Date.now() - new Date(timestamp).getTime()) / 1000)
  if (seconds < 60) return 'just now'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  return `${hours}h ago`
}

export default function AlertCorrelationInsights({
  alertId,
  className,
}: AlertCorrelationInsightsProps) {
  const [showAllAlerts, setShowAllAlerts] = useState(false)
  const { data, isLoading } = useAlertCorrelation(alertId)

  if (isLoading) {
    return (
      <div className={cn('bg-card rounded-lg border p-6', className)}>
        <div className="flex items-center justify-center py-8">
          <RefreshCw className="animate-spin text-muted-foreground" size={24} />
          <span className="ml-2 text-muted-foreground">Analyzing correlations...</span>
        </div>
      </div>
    )
  }

  if (!data) return null

  const displayedAlerts = showAllAlerts
    ? data.related_alerts
    : data.related_alerts.slice(0, 3)

  return (
    <div className={cn('bg-card rounded-lg border overflow-hidden', className)}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b bg-gradient-to-r from-purple-500/10 to-transparent">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-full bg-purple-500/20 flex items-center justify-center">
            <GitBranch className="text-purple-400" size={20} />
          </div>
          <div>
            <h3 className="font-semibold">AI Correlation Insights</h3>
            <p className="text-xs text-muted-foreground">
              {(data.confidence * 100).toFixed(0)}% confidence • {data.related_alerts.length} related alerts
            </p>
          </div>
        </div>
        {data.suggested_incident && (
          /* No /incidents/new route exists: the incidents page owns the
             create-incident modal and opens it on ?create=1. */
          <Link
            to="/incidents?create=1"
            className="flex items-center gap-2 px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm hover:bg-primary/90"
          >
            <AlertTriangle size={14} />
            Create Incident
          </Link>
        )}
      </div>

      <div className="p-4 space-y-6">
        {/* Summary */}
        <div className="flex items-start gap-3 p-3 bg-muted/50 rounded-lg">
          <Sparkles className="text-primary mt-0.5 flex-shrink-0" size={16} />
          <p className="text-sm">{data.correlation_summary}</p>
        </div>

        {/* Attack Chain */}
        {data.attack_chain.detected && (
          <div>
            <h4 className="font-medium mb-3 flex items-center gap-2">
              <AlertTriangle size={16} className="text-red-400" />
              Detected Attack Chain
            </h4>
            <div className="flex items-center gap-2 overflow-x-auto pb-2">
              {data.attack_chain.stages.map((stage, index) => (
                <div key={stage.name} className="flex items-center">
                  <div
                    className={cn(
                      'px-3 py-2 rounded-lg border text-sm whitespace-nowrap',
                      stage.status === 'confirmed'
                        ? 'bg-red-500/20 border-red-500/50 text-red-400'
                        : 'bg-yellow-500/20 border-yellow-500/50 text-yellow-400'
                    )}
                  >
                    <p className="font-medium">{stage.name}</p>
                    <p className="text-xs opacity-75">{stage.technique}</p>
                  </div>
                  {index < data.attack_chain.stages.length - 1 && (
                    <ChevronRight className="text-muted-foreground mx-1" size={16} />
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Common Entities */}
        <div>
          <h4 className="font-medium mb-3">Common Entities</h4>
          <div className="flex flex-wrap gap-2">
            {data.common_entities.map((entity) => {
              const Icon = entityIcons[entity.type as keyof typeof entityIcons] || Globe
              return (
                <div
                  key={entity.value}
                  className="flex items-center gap-2 px-3 py-1.5 bg-muted rounded-lg"
                >
                  <Icon size={14} className="text-muted-foreground" />
                  <span className="text-sm font-mono">{entity.value}</span>
                  <span className="text-xs text-muted-foreground">
                    ({entity.alerts_count} alerts)
                  </span>
                </div>
              )
            })}
          </div>
        </div>

        {/* Related Alerts */}
        <div>
          <h4 className="font-medium mb-3">Related Alerts</h4>
          <div className="space-y-2">
            {displayedAlerts.map((alert) => (
              <Link
                key={alert.id}
                to={`/alerts/${alert.id}`}
                className="flex items-center justify-between p-3 bg-muted/30 rounded-lg hover:bg-muted/50 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <span
                    className={cn(
                      'px-2 py-0.5 rounded text-xs border',
                      severityColors[alert.severity as keyof typeof severityColors]
                    )}
                  >
                    {alert.severity}
                  </span>
                  <div>
                    <p className="text-sm font-medium">{alert.title}</p>
                    <p className="text-xs text-muted-foreground">{alert.correlation_reason}</p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-muted-foreground flex items-center gap-1">
                    <Clock size={10} />
                    {timeAgo(alert.timestamp)}
                  </span>
                  <span className="text-xs text-primary">
                    {(alert.correlation_score * 100).toFixed(0)}%
                  </span>
                  <ExternalLink size={14} className="text-muted-foreground" />
                </div>
              </Link>
            ))}
          </div>
          {data.related_alerts.length > 3 && (
            <button
              onClick={() => setShowAllAlerts(!showAllAlerts)}
              className="w-full mt-2 py-2 text-sm text-primary hover:underline"
            >
              {showAllAlerts
                ? 'Show less'
                : `Show ${data.related_alerts.length - 3} more related alerts`}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
