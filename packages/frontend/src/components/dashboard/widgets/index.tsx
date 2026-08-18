import { type WidgetType, type WidgetConfig } from '../../../api/pantherApi'
import AlertSummaryWidget from './AlertSummaryWidget'
import AlertsBySeverityWidget from './AlertsBySeverityWidget'
import RecentAlertsWidget from './RecentAlertsWidget'
import TopRulesWidget from './TopRulesWidget'
import IncidentSummaryWidget from './IncidentSummaryWidget'
import CaseSummaryWidget from './CaseSummaryWidget'
import AlertForecastWidget from './AlertForecastWidget'
import AnomalyDetectionWidget from './AnomalyDetectionWidget'
import CoverageGapWidget from './CoverageGapWidget'
import StaleRulesWidget from './StaleRulesWidget'

/**
 * Widget types the renderer understands.
 *
 * alert_forecast, anomaly_detection, coverage_gap and stale_rules used to be
 * unreachable: they render real API data, but the backend `WidgetType` enum
 * did not list them, so `GET /dashboards/widget-types` never offered them and
 * saving a dashboard containing one came back 422. The enum was extended
 * (2026-08-18), so they are now selectable like any other.
 *
 * This alias stays until the generated schema is regenerated everywhere it is
 * consumed; `WidgetType` from the API types already includes the four.
 */
type ExtendedWidgetType = WidgetType | 'alert_forecast' | 'anomaly_detection' | 'coverage_gap' | 'stale_rules'

interface WidgetRendererProps {
  widget: WidgetConfig
}

export function WidgetRenderer({ widget }: WidgetRendererProps) {
  const config = widget.config as Record<string, unknown>
  const widgetType = widget.widget_type as ExtendedWidgetType

  switch (widgetType) {
    case 'alert_summary':
      return <AlertSummaryWidget config={config} />
    case 'alerts_by_severity':
      return <AlertsBySeverityWidget config={config} />
    case 'alerts_by_status':
      return <AlertsBySeverityWidget config={config} /> // Reuse for now
    case 'alerts_over_time':
      return <AlertsOverTimeWidget config={config} />
    case 'top_rules':
      return <TopRulesWidget config={config} />
    case 'recent_alerts':
      return <RecentAlertsWidget config={config} />
    case 'incident_summary':
      return <IncidentSummaryWidget />
    case 'case_summary':
      return <CaseSummaryWidget />
    case 'sla_status':
      return <PlaceholderWidget title="SLA Status" message="SLA tracking coming soon" />
    case 'custom_query':
      return <PlaceholderWidget title="Custom Query" message="Configure a custom query" />
    // Not selectable until the backend WidgetType enum gains them (see above).
    case 'alert_forecast':
      return <AlertForecastWidget config={config} />
    case 'anomaly_detection':
      return <AnomalyDetectionWidget config={config} />
    case 'coverage_gap':
      return <CoverageGapWidget config={config} />
    case 'stale_rules':
      return <StaleRulesWidget config={config} />
    default:
      return <PlaceholderWidget title="Unknown Widget" message={`Widget type: ${widget.widget_type}`} />
  }
}

function AlertsOverTimeWidget({ config: _config }: { config?: Record<string, unknown> }) {
  return (
    <div className="h-full flex items-center justify-center p-4">
      <div className="text-center text-gray-500">
        <div className="text-4xl mb-2">📈</div>
        <div>Alerts trend chart</div>
        <div className="text-xs mt-1">(Requires chart library)</div>
      </div>
    </div>
  )
}

function PlaceholderWidget({ title, message }: { title: string; message: string }) {
  return (
    <div className="h-full flex flex-col items-center justify-center p-4 text-center">
      <div className="text-gray-400 text-2xl mb-2">📊</div>
      <div className="font-medium text-gray-700">{title}</div>
      <div className="text-sm text-gray-500">{message}</div>
    </div>
  )
}

export const widgetTypeLabels: Record<string, string> = {
  alert_summary: 'Alert Summary',
  alerts_by_severity: 'Alerts by Severity',
  alerts_by_status: 'Alerts by Status',
  alerts_over_time: 'Alerts Over Time',
  top_rules: 'Top Alerting Rules',
  recent_alerts: 'Recent Alerts',
  incident_summary: 'Incident Summary',
  case_summary: 'Case Summary',
  sla_status: 'SLA Status',
  custom_query: 'Custom Query',
  // Rendered but not selectable until the backend WidgetType enum gains them.
  alert_forecast: 'Alert Volume Forecast',
  anomaly_detection: 'Anomaly Detection',
  coverage_gap: 'MITRE Coverage Gaps',
  stale_rules: 'Stale Rules',
}

export {
  AlertSummaryWidget,
  AlertsBySeverityWidget,
  RecentAlertsWidget,
  TopRulesWidget,
  IncidentSummaryWidget,
  CaseSummaryWidget,
  AlertForecastWidget,
  AnomalyDetectionWidget,
  CoverageGapWidget,
  StaleRulesWidget,
}
