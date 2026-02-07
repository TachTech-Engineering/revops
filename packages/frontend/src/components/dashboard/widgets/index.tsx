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
import OnCallWidget from './OnCallWidget'
import SystemHealthWidget from './SystemHealthWidget'
import UserActivityWidget from './UserActivityWidget'
import ComplianceStatusWidget from './ComplianceStatusWidget'
import DataIngestionWidget from './DataIngestionWidget'
import TopAnalystsWidget from './TopAnalystsWidget'

// Extended widget types
type ExtendedWidgetType = WidgetType | 'alert_forecast' | 'anomaly_detection' | 'coverage_gap' | 'stale_rules' | 'oncall_status' | 'system_health' | 'user_activity' | 'compliance_status' | 'data_ingestion' | 'top_analysts'

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
    // New widgets
    case 'alert_forecast':
      return <AlertForecastWidget config={config} />
    case 'anomaly_detection':
      return <AnomalyDetectionWidget config={config} />
    case 'coverage_gap':
      return <CoverageGapWidget config={config} />
    case 'stale_rules':
      return <StaleRulesWidget config={config} />
    case 'oncall_status':
      return <OnCallWidget config={config} />
    case 'system_health':
      return <SystemHealthWidget config={config} />
    case 'user_activity':
      return <UserActivityWidget config={config} />
    case 'compliance_status':
      return <ComplianceStatusWidget config={config} />
    case 'data_ingestion':
      return <DataIngestionWidget config={config} />
    case 'top_analysts':
      return <TopAnalystsWidget config={config} />
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
  // New widgets
  alert_forecast: 'Alert Volume Forecast',
  anomaly_detection: 'Anomaly Detection',
  coverage_gap: 'MITRE Coverage Gaps',
  stale_rules: 'Stale Rules',
  oncall_status: 'On-Call Status',
  // Additional widgets
  system_health: 'System Health',
  user_activity: 'User Activity',
  compliance_status: 'Compliance Status',
  data_ingestion: 'Data Ingestion',
  top_analysts: 'Top Analysts',
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
  OnCallWidget,
  SystemHealthWidget,
  UserActivityWidget,
  ComplianceStatusWidget,
  DataIngestionWidget,
  TopAnalystsWidget,
}
