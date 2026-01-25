import { type WidgetType, type WidgetConfig } from '../../../api/pantherApi'
import AlertSummaryWidget from './AlertSummaryWidget'
import AlertsBySeverityWidget from './AlertsBySeverityWidget'
import RecentAlertsWidget from './RecentAlertsWidget'
import TopRulesWidget from './TopRulesWidget'
import IncidentSummaryWidget from './IncidentSummaryWidget'
import CaseSummaryWidget from './CaseSummaryWidget'

interface WidgetRendererProps {
  widget: WidgetConfig
}

export function WidgetRenderer({ widget }: WidgetRendererProps) {
  const config = widget.config as Record<string, unknown>

  switch (widget.widget_type) {
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
    default:
      return <PlaceholderWidget title="Unknown Widget" message={`Widget type: ${widget.widget_type}`} />
  }
}

function AlertsOverTimeWidget({ config }: { config?: Record<string, unknown> }) {
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

export const widgetTypeLabels: Record<WidgetType, string> = {
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
}

export {
  AlertSummaryWidget,
  AlertsBySeverityWidget,
  RecentAlertsWidget,
  TopRulesWidget,
  IncidentSummaryWidget,
  CaseSummaryWidget,
}
