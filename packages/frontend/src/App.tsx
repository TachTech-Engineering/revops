import { Routes, Route, Navigate } from 'react-router-dom'
import { useSelector } from 'react-redux'
import { RootState } from './store'
import Layout from './components/common/Layout'
import LoginPage from './pages/LoginPage'
import Dashboard from './pages/Dashboard'
import ConverterPage from './pages/ConverterPage'
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
import CasesPage from './pages/CasesPage'
import CaseDetailPage from './pages/CaseDetailPage'
import EnrichmentPipelinesPage from './pages/EnrichmentPipelinesPage'
import DashboardManagerPage from './pages/DashboardManagerPage'
import CustomDashboardPage from './pages/CustomDashboardPage'
import MitreCoveragePage from './pages/MitreCoveragePage'
import SLADashboardPage from './pages/SLADashboardPage'
import SLAPoliciesPage from './pages/SLAPoliciesPage'
import ThreatIntelPage from './pages/ThreatIntelPage'
import AISettingsPage from './pages/AISettingsPage'
// SecOps Platform: Connectors & Workflows
import ConnectorsPage from './pages/ConnectorsPage'
import ConnectorEditorPage from './pages/ConnectorEditorPage'
import WorkflowsPage from './pages/WorkflowsPage'
import WorkflowEditorPage from './pages/WorkflowEditorPage'
import AlertsPage from './pages/UnifiedAlertsPage'

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
        path="/*"
        element={
          <ProtectedRoute>
            <Layout>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                {/* Security Operations */}
                <Route path="/alerts" element={<AlertsPage />} />
                <Route path="/incidents" element={<IncidentsPage />} />
                <Route path="/incidents/:id" element={<IncidentDetailPage />} />
                <Route path="/cases" element={<CasesPage />} />
                <Route path="/cases/:id" element={<CaseDetailPage />} />
                {/* Automation */}
                <Route path="/connectors" element={<ConnectorsPage />} />
                <Route path="/connectors/new" element={<ConnectorEditorPage />} />
                <Route path="/connectors/:connectorId" element={<ConnectorEditorPage />} />
                <Route path="/connectors/:connectorId/edit" element={<ConnectorEditorPage />} />
                <Route path="/workflows" element={<WorkflowsPage />} />
                <Route path="/workflows/new" element={<WorkflowEditorPage />} />
                <Route path="/workflows/:workflowId" element={<WorkflowEditorPage />} />
                <Route path="/workflows/:workflowId/edit" element={<WorkflowEditorPage />} />
                {/* Investigation */}
                <Route path="/queries" element={<QueryExplorerPage />} />
                <Route path="/ioc-search" element={<IOCSearchPage />} />
                <Route path="/threat-intel" element={<ThreatIntelPage />} />
                <Route path="/converter" element={<ConverterPage />} />
                {/* Analytics */}
                <Route path="/analytics" element={<AnalyticsDashboardPage />} />
                <Route path="/mitre" element={<MitreCoveragePage />} />
                <Route path="/sla" element={<SLADashboardPage />} />
                <Route path="/sla/policies" element={<SLAPoliciesPage />} />
                <Route path="/dashboards" element={<DashboardManagerPage />} />
                <Route path="/dashboards/:id" element={<CustomDashboardPage />} />
                <Route path="/reports" element={<ScheduledReportsPage />} />
                {/* Administration */}
                <Route path="/webhooks" element={<WebhooksPage />} />
                <Route path="/enrichment" element={<EnrichmentPipelinesPage />} />
                <Route path="/roles" element={<RoleManagementPage />} />
                <Route path="/audit" element={<AuditLogPage />} />
                <Route path="/settings" element={<SettingsPage />} />
                <Route path="/settings/ai" element={<AISettingsPage />} />
              </Routes>
            </Layout>
          </ProtectedRoute>
        }
      />
    </Routes>
  )
}

export default App
