import { Link } from 'react-router-dom'
import {
  Database,
  RefreshCw,
  ChevronRight,
  CheckCircle,
  AlertTriangle,
  XCircle,
  TrendingUp,
  Activity,
} from 'lucide-react'
import { cn } from '../../../lib/utils'

interface DataIngestionWidgetProps {
  config?: {
    showSources?: boolean
  }
}

// Mock data - in production this would come from an API
const useDataIngestion = () => {
  return {
    data: {
      total_events_24h: 15420000,
      total_events_change: 12.5,
      events_per_second: 178,
      sources: [
        { name: 'AWS CloudTrail', status: 'healthy', events_24h: 5200000, latency_ms: 45 },
        { name: 'Okta', status: 'healthy', events_24h: 850000, latency_ms: 120 },
        { name: 'CrowdStrike', status: 'healthy', events_24h: 3200000, latency_ms: 85 },
        { name: 'Microsoft 365', status: 'degraded', events_24h: 2100000, latency_ms: 350 },
        { name: 'GitHub', status: 'healthy', events_24h: 420000, latency_ms: 95 },
        { name: 'Palo Alto', status: 'unhealthy', events_24h: 0, latency_ms: 0 },
      ],
      hourly_volume: [
        { hour: '00:00', events: 580000 },
        { hour: '04:00', events: 420000 },
        { hour: '08:00', events: 890000 },
        { hour: '12:00', events: 1250000 },
        { hour: '16:00', events: 1100000 },
        { hour: '20:00', events: 780000 },
      ],
    },
    isLoading: false,
  }
}

const statusConfig = {
  healthy: { icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-500/20' },
  degraded: { icon: AlertTriangle, color: 'text-yellow-400', bg: 'bg-yellow-500/20' },
  unhealthy: { icon: XCircle, color: 'text-red-400', bg: 'bg-red-500/20' },
}

function formatNumber(num: number): string {
  if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`
  return num.toString()
}

export default function DataIngestionWidget({ config }: DataIngestionWidgetProps) {
  const { data, isLoading } = useDataIngestion()

  if (isLoading) {
    return (
      <div className="h-full flex items-center justify-center">
        <RefreshCw className="animate-spin text-muted-foreground" size={24} />
      </div>
    )
  }

  if (!data) return null

  const healthySources = data.sources.filter((s) => s.status === 'healthy').length
  const totalSources = data.sources.length

  return (
    <div className="h-full flex flex-col p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-medium flex items-center gap-2">
          <Database size={16} className="text-primary" />
          Data Ingestion
        </h3>
        <Link
          to="/connectors"
          className="text-xs text-primary hover:underline flex items-center gap-1"
        >
          Sources <ChevronRight size={12} />
        </Link>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-2 gap-2 mb-4">
        <div className="bg-muted/50 rounded-lg p-2 text-center">
          <p className="text-xs text-muted-foreground mb-1">Events (24h)</p>
          <p className="text-lg font-bold">{formatNumber(data.total_events_24h)}</p>
          <div className="flex items-center justify-center gap-1 text-xs text-green-400">
            <TrendingUp size={10} />
            +{data.total_events_change}%
          </div>
        </div>
        <div className="bg-muted/50 rounded-lg p-2 text-center">
          <p className="text-xs text-muted-foreground mb-1">Current Rate</p>
          <p className="text-lg font-bold flex items-center justify-center gap-1">
            <Activity size={14} className="text-green-400" />
            {data.events_per_second}
          </p>
          <p className="text-xs text-muted-foreground">events/sec</p>
        </div>
      </div>

      {/* Source Health Summary */}
      <div className="flex items-center justify-between p-2 bg-muted/30 rounded-lg mb-3">
        <span className="text-sm">Source Health</span>
        <span
          className={cn(
            'text-sm font-medium',
            healthySources === totalSources
              ? 'text-green-400'
              : healthySources > totalSources / 2
              ? 'text-yellow-400'
              : 'text-red-400'
          )}
        >
          {healthySources}/{totalSources} healthy
        </span>
      </div>

      {/* Source List */}
      {config?.showSources !== false && (
        <div className="flex-1 space-y-1.5 overflow-y-auto">
          {data.sources.map((source) => {
            const status = statusConfig[source.status as keyof typeof statusConfig]
            const StatusIcon = status.icon
            return (
              <div
                key={source.name}
                className={cn(
                  'flex items-center justify-between p-2 rounded',
                  status.bg
                )}
              >
                <div className="flex items-center gap-2">
                  <StatusIcon size={12} className={status.color} />
                  <span className="text-sm truncate max-w-[100px]">{source.name}</span>
                </div>
                <div className="flex items-center gap-3 text-xs text-muted-foreground">
                  <span>{formatNumber(source.events_24h)}</span>
                  {source.latency_ms > 0 && <span>{source.latency_ms}ms</span>}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
