import { Routes, Route, Navigate } from 'react-router-dom'
import { useSelector } from 'react-redux'
import { RootState } from './store'
import Layout from './components/common/Layout'
import LoginPage from './pages/LoginPage'
import AuthCallbackPage from './pages/AuthCallbackPage'
import Dashboard from './pages/Dashboard'
import MigrationPage from './pages/MigrationPage'
import QueryExplorerPage from './pages/QueryExplorerPage'
import AnalyticsDashboardPage from './pages/AnalyticsDashboardPage'
import IOCSearchPage from './pages/IOCSearchPage'
import SettingsPage from './pages/SettingsPage'
import WebhooksPage from './pages/WebhooksPage'
import RoleManagementPage from './pages/RoleManagementPage'
import AuditLogPage from './pages/AuditLogPage'
import ScheduledReportsPage from './pages/ScheduledReportsPage'
import IncidentsPage from './pages/IncidentsPage'
import IncidentDetailPage from './pages/IncidentDetailPage'
import EnrichmentPipelinesPage from './pages/EnrichmentPipelinesPage'
import DashboardManagerPage from './pages/DashboardManagerPage'
import CustomDashboardPage from './pages/CustomDashboardPage'
import MitreCoveragePage from './pages/MitreCoveragePage'
import SLADashboardPage from './pages/SLADashboardPage'
import SLAPoliciesPage from './pages/SLAPoliciesPage'
import ThreatIntelPage from './pages/ThreatIntelPage'
import AISettingsPage from './pages/AISettingsPage'
import SSOSettingsPage from './pages/SSOSettingsPage'
// SecOps Platform: Connectors, Pipelines & Workflows
import ConnectorsPage from './pages/ConnectorsPage'
import ConnectorEditorPage from './pages/ConnectorEditorPage'
import PipelinesPage from './pages/PipelinesPage'
import PipelineEditorPage from './pages/PipelineEditorPage'
import WorkflowsPage from './pages/WorkflowsPage'
import WorkflowEditorPage from './pages/WorkflowEditorPage'
import AlertsPage from './pages/UnifiedAlertsPage'
import AlertDetailPage from './pages/AlertDetailPage'
// New Feature Pages
import ClusteredAlertsPage from './pages/ClusteredAlertsPage'
import EscalationPoliciesPage from './pages/EscalationPoliciesPage'
import OnCallSchedulesPage from './pages/OnCallSchedulesPage'
import AssetCriticalityPage from './pages/AssetCriticalityPage'
import RuleHealthDashboardPage from './pages/RuleHealthDashboardPage'
import PlaybookGeneratorPage from './pages/PlaybookGeneratorPage'
// AI Features
import ThreatHuntingPage from './pages/ThreatHuntingPage'
// Integrations
import IntegrationsPage from './pages/IntegrationsPage'
import SlackIntegrationPage from './pages/SlackIntegrationPage'
import JiraIntegrationPage from './pages/JiraIntegrationPage'
import PagerDutyIntegrationPage from './pages/PagerDutyIntegrationPage'
import TeamsIntegrationPage from './pages/TeamsIntegrationPage'
import ServiceNowIntegrationPage from './pages/ServiceNowIntegrationPage'
import EmailIntegrationPage from './pages/EmailIntegrationPage'
import OpsGenieIntegrationPage from './pages/OpsGenieIntegrationPage'
import FonosterIntegrationPage from './pages/FonosterIntegrationPage'
// Reporting & Compliance
import ComplianceDashboardPage from './pages/ComplianceDashboardPage'
import ReportBuilderPage from './pages/ReportBuilderPage'
import ExecutiveSummaryPage from './pages/ExecutiveSummaryPage'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, userEmail } = useSelector((state: RootState) => state.auth)

  // Require both authentication and userEmail for full functionality
  if (!isAuthenticated || !userEmail) {
    return <Navigate to="/login" replace />
  }

  return <>{children}</>
}

function App() {
  const isAuthenticated = useSelector((state: RootState) => state.auth.isAuthenticated)

  return (
    <Routes>
      <Route
        path="/login"
        element={isAuthenticated ? <Navigate to="/" replace /> : <LoginPage />}
      />
      <Route
        path="/auth/callback"
        element={<AuthCallbackPage />}
      />
      <Route
        path="/*"
        element={
          <ProtectedRoute>
            <Layout>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                {/* Security Operations */}
                <Route path="/alerts" element={<AlertsPage />} />
                <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
                <Route path="/alerts/clusters" element={<ClusteredAlertsPage />} />
                <Route path="/incidents" element={<IncidentsPage />} />
                <Route path="/incidents/:id" element={<IncidentDetailPage />} />
                {/* On-Call & Escalation */}
                <Route path="/oncall" element={<OnCallSchedulesPage />} />
                <Route path="/escalation-policies" element={<EscalationPoliciesPage />} />
                {/* Automation */}
                <Route path="/connectors" element={<ConnectorsPage />} />
                <Route path="/connectors/new" element={<ConnectorEditorPage />} />
                <Route path="/connectors/:connectorId" element={<ConnectorEditorPage />} />
                <Route path="/connectors/:connectorId/edit" element={<ConnectorEditorPage />} />
                <Route path="/pipelines" element={<PipelinesPage />} />
                <Route path="/pipelines/new" element={<PipelineEditorPage />} />
                <Route path="/pipelines/:pipelineId" element={<PipelineEditorPage />} />
                <Route path="/workflows" element={<WorkflowsPage />} />
                <Route path="/workflows/new" element={<WorkflowEditorPage />} />
                <Route path="/workflows/:workflowId" element={<WorkflowEditorPage />} />
                <Route path="/workflows/:workflowId/edit" element={<WorkflowEditorPage />} />
                {/* Investigation */}
                <Route path="/queries" element={<QueryExplorerPage />} />
                <Route path="/ioc-search" element={<IOCSearchPage />} />
                <Route path="/threat-intel" element={<ThreatIntelPage />} />
                <Route path="/migration" element={<MigrationPage />} />
                <Route path="/converter" element={<Navigate to="/migration" replace />} />
                {/* Analytics */}
                <Route path="/analytics" element={<AnalyticsDashboardPage />} />
                <Route path="/mitre" element={<MitreCoveragePage />} />
                <Route path="/sla" element={<SLADashboardPage />} />
                <Route path="/sla/policies" element={<SLAPoliciesPage />} />
                <Route path="/dashboards" element={<DashboardManagerPage />} />
                <Route path="/dashboards/:id" element={<CustomDashboardPage />} />
                <Route path="/reports" element={<ScheduledReportsPage />} />
                <Route path="/rule-health" element={<RuleHealthDashboardPage />} />
                {/* Administration */}
                <Route path="/webhooks" element={<WebhooksPage />} />
                <Route path="/enrichment" element={<EnrichmentPipelinesPage />} />
                <Route path="/roles" element={<RoleManagementPage />} />
                <Route path="/audit" element={<AuditLogPage />} />
                <Route path="/settings" element={<SettingsPage />} />
                <Route path="/settings/ai" element={<AISettingsPage />} />
                <Route path="/settings/sso" element={<SSOSettingsPage />} />
                <Route path="/asset-criticality" element={<AssetCriticalityPage />} />
                {/* AI Features */}
                <Route path="/playbook-generator" element={<PlaybookGeneratorPage />} />
                <Route path="/threat-hunting" element={<ThreatHuntingPage />} />
                {/* Integrations */}
                <Route path="/integrations" element={<IntegrationsPage />} />
                <Route path="/integrations/slack" element={<SlackIntegrationPage />} />
                <Route path="/integrations/jira" element={<JiraIntegrationPage />} />
                <Route path="/integrations/pagerduty" element={<PagerDutyIntegrationPage />} />
                <Route path="/integrations/teams" element={<TeamsIntegrationPage />} />
                <Route path="/integrations/servicenow" element={<ServiceNowIntegrationPage />} />
                <Route path="/integrations/email" element={<EmailIntegrationPage />} />
                <Route path="/integrations/opsgenie" element={<OpsGenieIntegrationPage />} />
                <Route path="/integrations/fonoster" element={<FonosterIntegrationPage />} />
                {/* Reporting & Compliance */}
                <Route path="/compliance" element={<ComplianceDashboardPage />} />
                <Route path="/report-builder" element={<ReportBuilderPage />} />
                <Route path="/executive-summary" element={<ExecutiveSummaryPage />} />
              </Routes>
            </Layout>
          </ProtectedRoute>
        }
      />
    </Routes>
  )
}

export default App
