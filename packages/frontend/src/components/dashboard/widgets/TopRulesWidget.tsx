import { useGetAlertAnalyticsQuery } from '../../../api/pantherApi'

interface TopRulesWidgetProps {
  config?: { days?: number; limit?: number }
}

export default function TopRulesWidget({ config }: TopRulesWidgetProps) {
  const { data, isLoading } = useGetAlertAnalyticsQuery({ days: config?.days || 7 })

  if (isLoading) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (!data?.topRules?.length) {
    return <div className="text-gray-500 text-center p-4">No rules data available</div>
  }

  const rules = data.topRules.slice(0, config?.limit || 10)
  const maxCount = Math.max(...rules.map(r => r.count))

  return (
    <div className="h-full overflow-auto p-4">
      <div className="space-y-3">
        {rules.map((rule, index) => {
          const percentage = maxCount > 0 ? (rule.count / maxCount) * 100 : 0
          return (
            <div key={rule.name}>
              <div className="flex justify-between text-sm mb-1">
                <span className="font-medium truncate flex-1 mr-2" title={rule.name}>
                  {index + 1}. {rule.name}
                </span>
                <span className="text-gray-500 whitespace-nowrap">{rule.count}</span>
              </div>
              <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                <div
                  className="h-full bg-blue-500 transition-all duration-500"
                  style={{ width: `${percentage}%` }}
                />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
