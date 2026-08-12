import {
  AlertTriangle,
  RefreshCw,
  CheckCircle,
  ChevronRight,
  TrendingUp,
  TrendingDown,
} from 'lucide-react'
import {
  useListAnomaliesQuery,
  useAcknowledgeAnomalyMutation,
  useTriggerAnomalyDetectionMutation,
} from '../../../api/pantherApi'
import { cn } from '../../../lib/utils'

interface AnomalyDetectionWidgetProps {
  config?: {
    days?: number
    limit?: number
  }
}

const anomalyTypeIcons: Record<string, React.ElementType> = {
  volume_spike: TrendingUp,
  volume_drop: TrendingDown,
  unusual_pattern: AlertTriangle,
}

const severityColors: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/50',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/50',
}

export default function AnomalyDetectionWidget({ config }: AnomalyDetectionWidgetProps) {
  const { data: anomalies, isLoading, refetch } = useListAnomaliesQuery({
    acknowledged: false,
    days: config?.days || 7,
  })

  const [acknowledgeAnomaly] = useAcknowledgeAnomalyMutation()
  const [triggerDetection, { isLoading: isDetecting }] = useTriggerAnomalyDetectionMutation()

  const handleAcknowledge = async (anomalyId: string) => {
    try {
      await acknowledgeAnomaly(anomalyId).unwrap()
    } catch (err) {
      console.error('Failed to acknowledge:', err)
    }
  }

  const handleRefresh = async () => {
    try {
      await triggerDetection().unwrap()
      refetch()
    } catch (err) {
      console.error('Failed to run detection:', err)
    }
  }

  if (isLoading) {
    return (
      <div className="h-full flex items-center justify-center">
        <RefreshCw className="animate-spin text-muted-foreground" size={24} />
      </div>
    )
  }

  const displayedAnomalies = anomalies?.slice(0, config?.limit || 5)

  return (
    <div className="h-full flex flex-col p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-medium flex items-center gap-2">
          <AlertTriangle size={16} className="text-yellow-400" />
          Anomalies Detected
        </h3>
        <button
          onClick={handleRefresh}
          disabled={isDetecting}
          className="p-1.5 hover:bg-accent rounded-md"
          title="Run detection"
        >
          <RefreshCw size={14} className={isDetecting ? 'animate-spin' : ''} />
        </button>
      </div>

      {!displayedAnomalies?.length ? (
        <div className="flex-1 flex flex-col items-center justify-center text-center">
          <CheckCircle className="text-green-400 mb-2" size={32} />
          <p className="text-sm text-muted-foreground">No anomalies detected</p>
          <p className="text-xs text-muted-foreground">Alert patterns are within normal ranges</p>
        </div>
      ) : (
        <div className="flex-1 space-y-3 overflow-y-auto">
          {displayedAnomalies.map((anomaly) => {
            const Icon = anomalyTypeIcons[anomaly.anomaly_type] || AlertTriangle
            return (
              <div
                key={anomaly.id}
                className="p-3 bg-muted/50 rounded-lg border border-yellow-500/30"
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Icon size={14} className="text-yellow-400" />
                    <span
                      className={cn(
                        'px-2 py-0.5 rounded text-xs border',
                        severityColors[anomaly.severity] || severityColors.medium
                      )}
                    >
                      {anomaly.severity}
                    </span>
                  </div>
                  <button
                    onClick={() => handleAcknowledge(anomaly.id)}
                    className="text-xs text-muted-foreground hover:text-foreground"
                  >
                    Dismiss
                  </button>
                </div>
                <p className="text-sm font-medium capitalize">{anomaly.anomaly_type.replace(/_/g, ' ')}</p>
                <p className="text-xs text-muted-foreground mt-1">{anomaly.description}</p>
                <div className="flex items-center justify-between mt-2 text-xs text-muted-foreground">
                  <span>{new Date(anomaly.detected_at).toLocaleString()}</span>
                  {anomaly.related_rule_ids.length > 0 && (
                    <span>{anomaly.related_rule_ids.length} rules affected</span>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {anomalies && anomalies.length > (config?.limit || 5) && (
        <button className="flex items-center justify-center gap-1 mt-3 text-sm text-primary hover:underline">
          View all {anomalies.length} anomalies <ChevronRight size={14} />
        </button>
      )}
    </div>
  )
}
