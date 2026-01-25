import { Routes, Route, Navigate } from 'react-router-dom'
import { useSelector } from 'react-redux'
import { RootState } from './store'
import Layout from './components/common/Layout'
import LoginPage from './pages/LoginPage'
import Dashboard from './pages/Dashboard'
import AlertsPage from './pages/AlertsPage'
import AlertDetailPage from './pages/AlertDetailPage'
import RulesPage from './pages/RulesPage'
import RuleEditorPage from './pages/RuleEditorPage'
import ConverterPage from './pages/ConverterPage'
import QueryExplorerPage from './pages/QueryExplorerPage'
import AnalyticsDashboardPage from './pages/AnalyticsDashboardPage'
import IOCSearchPage from './pages/IOCSearchPage'
import SettingsPage from './pages/SettingsPage'
import SuppressionRulesPage from './pages/SuppressionRulesPage'
import WebhooksPage from './pages/WebhooksPage'
import RoleManagementPage from './pages/RoleManagementPage'
import AuditLogPage from './pages/AuditLogPage'
import PlaybooksPage from './pages/PlaybooksPage'
import PlaybookEditorPage from './pages/PlaybookEditorPage'
import ScheduledReportsPage from './pages/ScheduledReportsPage'
import IncidentsPage from './pages/IncidentsPage'
import IncidentDetailPage from './pages/IncidentDetailPage'
import CorrelationRulesPage from './pages/CorrelationRulesPage'
import CasesPage from './pages/CasesPage'
import CaseDetailPage from './pages/CaseDetailPage'
import EnrichmentPipelinesPage from './pages/EnrichmentPipelinesPage'
import DashboardManagerPage from './pages/DashboardManagerPage'
import CustomDashboardPage from './pages/CustomDashboardPage'
import MitreCoveragePage from './pages/MitreCoveragePage'
import SLADashboardPage from './pages/SLADashboardPage'
import SLAPoliciesPage from './pages/SLAPoliciesPage'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useSelector((state: RootState) => state.auth.isAuthenticated)

  if (!isAuthenticated) {
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
                <Route path="/alerts" element={<AlertsPage />} />
                <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
                <Route path="/rules" element={<RulesPage />} />
                <Route path="/rules/new" element={<RuleEditorPage />} />
                <Route path="/rules/:ruleId" element={<RuleEditorPage />} />
                <Route path="/converter" element={<ConverterPage />} />
                <Route path="/queries" element={<QueryExplorerPage />} />
                <Route path="/analytics" element={<AnalyticsDashboardPage />} />
                <Route path="/ioc-search" element={<IOCSearchPage />} />
                <Route path="/settings" element={<SettingsPage />} />
                <Route path="/suppression" element={<SuppressionRulesPage />} />
                <Route path="/webhooks" element={<WebhooksPage />} />
                <Route path="/roles" element={<RoleManagementPage />} />
                <Route path="/audit" element={<AuditLogPage />} />
                <Route path="/playbooks" element={<PlaybooksPage />} />
                <Route path="/playbooks/new" element={<PlaybookEditorPage />} />
                <Route path="/playbooks/:playbookId" element={<PlaybookEditorPage />} />
                <Route path="/playbooks/:playbookId/edit" element={<PlaybookEditorPage />} />
                <Route path="/reports" element={<ScheduledReportsPage />} />
                <Route path="/incidents" element={<IncidentsPage />} />
                <Route path="/incidents/:id" element={<IncidentDetailPage />} />
                <Route path="/correlation-rules" element={<CorrelationRulesPage />} />
                <Route path="/cases" element={<CasesPage />} />
                <Route path="/cases/:id" element={<CaseDetailPage />} />
                <Route path="/enrichment" element={<EnrichmentPipelinesPage />} />
                <Route path="/dashboards" element={<DashboardManagerPage />} />
                <Route path="/dashboards/:id" element={<CustomDashboardPage />} />
                <Route path="/mitre" element={<MitreCoveragePage />} />
                <Route path="/sla" element={<SLADashboardPage />} />
                <Route path="/sla/policies" element={<SLAPoliciesPage />} />
              </Routes>
            </Layout>
          </ProtectedRoute>
        }
      />
    </Routes>
  )
}

export default App
