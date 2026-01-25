import { useGetAlertAnalyticsQuery } from '../../../api/pantherApi'

interface AlertSummaryWidgetProps {
  config?: { days?: number }
}

export default function AlertSummaryWidget({ config }: AlertSummaryWidgetProps) {
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

  return (
    <div className="h-full flex flex-col justify-center p-4">
      <div className="text-4xl font-bold text-gray-900 mb-2">{data.totalAlerts}</div>
      <div className="text-sm text-gray-500 mb-4">Total Alerts (Last {config?.days || 7} days)</div>

      <div className="grid grid-cols-2 gap-2 text-sm">
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-red-500"></span>
          <span>Critical: {data.bySeverity.CRITICAL}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-orange-500"></span>
          <span>High: {data.bySeverity.HIGH}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-yellow-500"></span>
          <span>Medium: {data.bySeverity.MEDIUM}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-blue-500"></span>
          <span>Low: {data.bySeverity.LOW}</span>
        </div>
      </div>
    </div>
  )
}
