import { Link } from 'react-router-dom'
import {
  Activity,
  RefreshCw,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Server,
  Database,
  Cpu,
  HardDrive,
  ChevronRight,
} from 'lucide-react'
import { cn } from '../../../lib/utils'

interface SystemHealthWidgetProps {
  config?: {
    showDetails?: boolean
  }
}

// Mock data - in production this would come from an API
const useSystemHealth = () => {
  return {
    data: {
      overall_status: 'healthy' as const,
      components: [
        { name: 'API Gateway', status: 'healthy', latency_ms: 45, uptime: 99.99 },
        { name: 'Data Pipeline', status: 'healthy', latency_ms: 120, uptime: 99.95 },
        { name: 'Detection Engine', status: 'healthy', latency_ms: 85, uptime: 99.98 },
        { name: 'Alert Service', status: 'degraded', latency_ms: 250, uptime: 99.5 },
        { name: 'Query Engine', status: 'healthy', latency_ms: 150, uptime: 99.9 },
      ],
      metrics: {
        cpu_usage: 42,
        memory_usage: 68,
        disk_usage: 55,
        active_connections: 1250,
      },
      last_updated: new Date().toISOString(),
    },
    isLoading: false,
  }
}

const statusConfig = {
  healthy: { icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-500/20' },
  degraded: { icon: AlertTriangle, color: 'text-yellow-400', bg: 'bg-yellow-500/20' },
  unhealthy: { icon: XCircle, color: 'text-red-400', bg: 'bg-red-500/20' },
}

export default function SystemHealthWidget({ config }: SystemHealthWidgetProps) {
  const { data, isLoading } = useSystemHealth()

  if (isLoading) {
    return (
      <div className="h-full flex items-center justify-center">
        <RefreshCw className="animate-spin text-muted-foreground" size={24} />
      </div>
    )
  }

  if (!data) return null

  const StatusIcon = statusConfig[data.overall_status].icon

  return (
    <div className="h-full flex flex-col p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-medium flex items-center gap-2">
          <Activity size={16} className="text-primary" />
          System Health
        </h3>
        <Link
          to="/settings"
          className="text-xs text-primary hover:underline flex items-center gap-1"
        >
          Details <ChevronRight size={12} />
        </Link>
      </div>

      {/* Overall Status */}
      <div
        className={cn(
          'flex items-center gap-3 p-3 rounded-lg mb-4',
          statusConfig[data.overall_status].bg
        )}
      >
        <StatusIcon className={statusConfig[data.overall_status].color} size={24} />
        <div>
          <p className="font-medium capitalize">{data.overall_status}</p>
          <p className="text-xs text-muted-foreground">All systems operational</p>
        </div>
      </div>

      {/* Resource Usage */}
      <div className="grid grid-cols-2 gap-2 mb-4">
        <div className="bg-muted/50 rounded-lg p-2">
          <div className="flex items-center gap-2 mb-1">
            <Cpu size={12} className="text-muted-foreground" />
            <span className="text-xs text-muted-foreground">CPU</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
              <div
                className={cn(
                  'h-full rounded-full',
                  data.metrics.cpu_usage > 80 ? 'bg-red-500' : 'bg-green-500'
                )}
                style={{ width: `${data.metrics.cpu_usage}%` }}
              />
            </div>
            <span className="text-xs font-medium">{data.metrics.cpu_usage}%</span>
          </div>
        </div>
        <div className="bg-muted/50 rounded-lg p-2">
          <div className="flex items-center gap-2 mb-1">
            <HardDrive size={12} className="text-muted-foreground" />
            <span className="text-xs text-muted-foreground">Memory</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
              <div
                className={cn(
                  'h-full rounded-full',
                  data.metrics.memory_usage > 80 ? 'bg-red-500' : 'bg-blue-500'
                )}
                style={{ width: `${data.metrics.memory_usage}%` }}
              />
            </div>
            <span className="text-xs font-medium">{data.metrics.memory_usage}%</span>
          </div>
        </div>
      </div>

      {/* Component Status */}
      {config?.showDetails !== false && (
        <div className="flex-1 space-y-1.5 overflow-y-auto">
          {data.components.map((component) => {
            const compStatus = statusConfig[component.status as keyof typeof statusConfig]
            const CompIcon = compStatus.icon
            return (
              <div
                key={component.name}
                className="flex items-center justify-between p-2 bg-muted/30 rounded"
              >
                <div className="flex items-center gap-2">
                  <CompIcon size={12} className={compStatus.color} />
                  <span className="text-sm">{component.name}</span>
                </div>
                <span className="text-xs text-muted-foreground">{component.latency_ms}ms</span>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
