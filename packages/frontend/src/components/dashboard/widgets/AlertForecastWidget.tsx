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

  const forecastDays = config?.forecastDays || 7
  const predictedDaily = data.predicted_total / forecastDays
  const trend =
    predictedDaily > data.historical_average * 1.1
      ? 'increasing'
      : predictedDaily < data.historical_average * 0.9
        ? 'decreasing'
        : 'stable'
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
          <p className="text-xs text-muted-foreground">Predicted ({data.forecast_period})</p>
          <p className="text-2xl font-bold">{data.predicted_total || 0}</p>
        </div>
        <div className="bg-muted/50 rounded-lg p-3">
          <p className="text-xs text-muted-foreground">Historical Daily Avg</p>
          <p className="text-2xl font-bold">{data.historical_average.toFixed(0)}</p>
        </div>
      </div>

      {/* Method */}
      <div className="flex-1">
        <p className="text-xs text-muted-foreground">
          Prediction method: <span className="capitalize">{data.prediction_method.replace(/_/g, ' ')}</span>
        </p>
      </div>

      {/* Confidence */}
      {data.confidence_interval && (
        <p className="text-xs text-muted-foreground mt-2">
          Confidence: {data.confidence_interval.confidence_level}
          (range: {data.confidence_interval.lower}-{data.confidence_interval.upper})
        </p>
      )}
    </div>
  )
}
