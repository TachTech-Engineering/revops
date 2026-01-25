import { useGetAlertAnalyticsQuery } from '../../../api/pantherApi'

interface AlertsBySeverityWidgetProps {
  config?: { days?: number }
}

const severityColors: Record<string, string> = {
  CRITICAL: 'bg-red-500',
  HIGH: 'bg-orange-500',
  MEDIUM: 'bg-yellow-500',
  LOW: 'bg-blue-500',
  INFO: 'bg-gray-400',
}

export default function AlertsBySeverityWidget({ config }: AlertsBySeverityWidgetProps) {
  const { data, isLoading } = useGetAlertAnalyticsQuery({ days: config?.days || 7 })

  if (isLoading) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (!data) {
    return <div className="text-gray-500 text-center p-4">No data available</div>
  }

  const severities = Object.entries(data.bySeverity)
  const total = severities.reduce((sum, [, count]) => sum + count, 0)

  return (
    <div className="h-full p-4 flex flex-col">
      <div className="flex-1 flex items-center justify-center">
        {/* Simple bar chart */}
        <div className="w-full space-y-3">
          {severities.map(([severity, count]) => {
            const percentage = total > 0 ? (count / total) * 100 : 0
            return (
              <div key={severity}>
                <div className="flex justify-between text-sm mb-1">
                  <span className="font-medium">{severity}</span>
                  <span className="text-gray-500">{count} ({percentage.toFixed(1)}%)</span>
                </div>
                <div className="h-4 bg-gray-200 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${severityColors[severity] || 'bg-gray-400'} transition-all duration-500`}
                    style={{ width: `${percentage}%` }}
                  />
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
