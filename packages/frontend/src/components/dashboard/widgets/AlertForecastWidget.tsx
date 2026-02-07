import { TrendingUp, TrendingDown, Minus, RefreshCw } from 'lucide-react'
import { useGetForecastQuery } from '../../../api/pantherApi'
import { cn } from '../../../lib/utils'

interface AlertForecastWidgetProps {
  config?: {
    forecastDays?: number
  }
}

export default function AlertForecastWidget({ config }: AlertForecastWidgetProps) {
  const { data, isLoading } = useGetForecastQuery({
    forecastDays: config?.forecastDays || 7,
  })

  if (isLoading) {
    return (
      <div className="h-full flex items-center justify-center">
        <RefreshCw className="animate-spin text-muted-foreground" size={24} />
      </div>
    )
  }

  if (!data) {
    return (
      <div className="h-full flex items-center justify-center text-muted-foreground">
        No forecast data available
      </div>
    )
  }

  const trend = data.trend_direction || 'stable'
  const TrendIcon = trend === 'increasing' ? TrendingUp : trend === 'decreasing' ? TrendingDown : Minus
  const trendColor = trend === 'increasing' ? 'text-red-400' : trend === 'decreasing' ? 'text-green-400' : 'text-yellow-400'

  return (
    <div className="h-full flex flex-col p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-medium">Alert Volume Forecast</h3>
        <div className={cn('flex items-center gap-1', trendColor)}>
          <TrendIcon size={16} />
          <span className="text-sm capitalize">{trend}</span>
        </div>
      </div>

      {/* Forecast Summary */}
      <div className="grid grid-cols-2 gap-4 mb-4">
        <div className="bg-muted/50 rounded-lg p-3">
          <p className="text-xs text-muted-foreground">Predicted (next 7d)</p>
          <p className="text-2xl font-bold">{data.predicted_total || 0}</p>
        </div>
        <div className="bg-muted/50 rounded-lg p-3">
          <p className="text-xs text-muted-foreground">Avg Daily</p>
          <p className="text-2xl font-bold">{data.daily_average?.toFixed(0) || 0}</p>
        </div>
      </div>

      {/* Daily Predictions */}
      <div className="flex-1">
        <p className="text-xs text-muted-foreground mb-2">Daily Predictions</p>
        <div className="flex items-end gap-1 h-24">
          {data.daily_forecast?.map((day, index) => {
            const maxCount = Math.max(...(data.daily_forecast?.map((d) => d.predicted_count) || [1]))
            const height = (day.predicted_count / maxCount) * 100 || 10

            return (
              <div
                key={index}
                className="flex-1 flex flex-col items-center gap-1"
              >
                <div
                  className="w-full bg-primary/60 rounded-t transition-all"
                  style={{ height: `${height}%` }}
                  title={`${day.date}: ${day.predicted_count} alerts`}
                />
                <span className="text-[10px] text-muted-foreground">
                  {new Date(day.date).toLocaleDateString('en-US', { weekday: 'short' }).charAt(0)}
                </span>
              </div>
            )
          })}
        </div>
      </div>

      {/* Confidence */}
      {data.confidence_interval && (
        <p className="text-xs text-muted-foreground mt-2">
          Confidence: {((data.confidence_interval.confidence || 0.8) * 100).toFixed(0)}%
          (range: {data.confidence_interval.lower}-{data.confidence_interval.upper})
        </p>
      )}
    </div>
  )
}
