import { Suspense, lazy } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { useSelector } from 'react-redux'
import { RootState } from './store'
import Layout from './components/common/Layout'
import ErrorBoundary from './components/common/ErrorBoundary'
// Auth/gate pages render synchronously: they are on the first-paint path
// (the login page must not wait on the authenticated app bundle).
import LoginPage from './pages/LoginPage'
import AuthCallbackPage from './pages/AuthCallbackPage'

// Authenticated pages are code-split so the login screen no longer downloads
// the whole app (including Monaco / ReactFlow). Each becomes its own chunk.
const Dashboard = lazy(() => import('./pages/Dashboard'))
const MigrationPage = lazy(() => import('./pages/MigrationPage'))
const QueryExplorerPage = lazy(() => import('./pages/QueryExplorerPage'))
const AnalyticsDashboardPage = lazy(() => import('./pages/AnalyticsDashboardPage'))
const IOCSearchPage = lazy(() => import('./pages/IOCSearchPage'))
const SettingsPage = lazy(() => import('./pages/SettingsPage'))
const WebhooksPage = lazy(() => import('./pages/WebhooksPage'))
const RoleManagementPage = lazy(() => import('./pages/RoleManagementPage'))
const UserManagementPage = lazy(() => import('./pages/UserManagementPage'))
const AuditLogPage = lazy(() => import('./pages/AuditLogPage'))
const ScheduledReportsPage = lazy(() => import('./pages/ScheduledReportsPage'))
const IncidentsPage = lazy(() => import('./pages/IncidentsPage'))
const IncidentDetailPage = lazy(() => import('./pages/IncidentDetailPage'))
const EnrichmentPipelinesPage = lazy(() => import('./pages/EnrichmentPipelinesPage'))
const DashboardManagerPage = lazy(() => import('./pages/DashboardManagerPage'))
const CustomDashboardPage = lazy(() => import('./pages/CustomDashboardPage'))
const MitreCoveragePage = lazy(() => import('./pages/MitreCoveragePage'))
const SLADashboardPage = lazy(() => import('./pages/SLADashboardPage'))
const SLAPoliciesPage = lazy(() => import('./pages/SLAPoliciesPage'))
const ThreatIntelPage = lazy(() => import('./pages/ThreatIntelPage'))
const AISettingsPage = lazy(() => import('./pages/AISettingsPage'))
const SSOSettingsPage = lazy(() => import('./pages/SSOSettingsPage'))
// SecOps Platform: Connectors, Pipelines & Workflows
const ConnectorsPage = lazy(() => import('./pages/ConnectorsPage'))
const ConnectorEditorPage = lazy(() => import('./pages/ConnectorEditorPage'))
const PipelinesPage = lazy(() => import('./pages/PipelinesPage'))
const PipelineEditorPage = lazy(() => import('./pages/PipelineEditorPage'))
const WorkflowsPage = lazy(() => import('./pages/WorkflowsPage'))
const WorkflowEditorPage = lazy(() => import('./pages/WorkflowEditorPage'))
const AlertsPage = lazy(() => import('./pages/UnifiedAlertsPage'))
const AlertDetailPage = lazy(() => import('./pages/AlertDetailPage'))
// New Feature Pages
const ClusteredAlertsPage = lazy(() => import('./pages/ClusteredAlertsPage'))
const ClusteredAlertDetailPage = lazy(() => import('./pages/ClusteredAlertDetailPage'))
const EscalationPoliciesPage = lazy(() => import('./pages/EscalationPoliciesPage'))
const OnCallSchedulesPage = lazy(() => import('./pages/OnCallSchedulesPage'))
const AssetCriticalityPage = lazy(() => import('./pages/AssetCriticalityPage'))
const RuleHealthDashboardPage = lazy(() => import('./pages/RuleHealthDashboardPage'))
const PlaybookGeneratorPage = lazy(() => import('./pages/PlaybookGeneratorPage'))
// AI Features
const ThreatHuntingPage = lazy(() => import('./pages/ThreatHuntingPage'))
// Integrations
const IntegrationsPage = lazy(() => import('./pages/IntegrationsPage'))
const SlackIntegrationPage = lazy(() => import('./pages/SlackIntegrationPage'))
const JiraIntegrationPage = lazy(() => import('./pages/JiraIntegrationPage'))
const PagerDutyIntegrationPage = lazy(() => import('./pages/PagerDutyIntegrationPage'))
const TeamsIntegrationPage = lazy(() => import('./pages/TeamsIntegrationPage'))
const ServiceNowIntegrationPage = lazy(() => import('./pages/ServiceNowIntegrationPage'))
const EmailIntegrationPage = lazy(() => import('./pages/EmailIntegrationPage'))
const OpsGenieIntegrationPage = lazy(() => import('./pages/OpsGenieIntegrationPage'))
const FonosterIntegrationPage = lazy(() => import('./pages/FonosterIntegrationPage'))
// Reporting & Compliance
const ComplianceDashboardPage = lazy(() => import('./pages/ComplianceDashboardPage'))
const ReportBuilderPage = lazy(() => import('./pages/ReportBuilderPage'))
const ExecutiveSummaryPage = lazy(() => import('./pages/ExecutiveSummaryPage'))

// Lightweight Suspense fallback: a centered spinner that respects
// prefers-reduced-motion (motion-reduce:animate-none disables the spin).
function PageLoader() {
  return (
    <div
      className="flex min-h-[60vh] items-center justify-center"
      role="status"
      aria-label="Loading"
    >
      <div className="h-8 w-8 rounded-full border-2 border-primary/30 border-t-primary animate-spin motion-reduce:animate-none" />
    </div>
  )
}

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
              {/* ErrorBoundary sits inside Layout so a page crash keeps the
                  nav/header usable; Suspense drives the code-split pages. */}
              <ErrorBoundary>
                <Suspense fallback={<PageLoader />}>
                  <Routes>
                    <Route path="/" element={<Dashboard />} />
                    {/* Security Operations */}
                    <Route path="/alerts" index element={<AlertsPage />} />
                    <Route path="/alerts/clusters" element={<ClusteredAlertsPage />} />
                    <Route path="/alerts/clusters/:id" element={<ClusteredAlertDetailPage />} />
                    <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
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
                    <Route path="/users" element={<UserManagementPage />} />
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
                </Suspense>
              </ErrorBoundary>
            </Layout>
          </ProtectedRoute>
        }
      />
    </Routes>
  )
}

export default App
