import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react'
import type { RootState } from '../store'
import type {
  Alert,
  AlertSummary,
  AlertEvent,
  AlertComment,
  AlertFilters,
  Rule,
  RuleSummary,
  RuleFilters,
  RuleCreate,
  RuleUpdate,
  ConversionResult,
  SPLConvertRequest,
  PaginatedResponse,
} from '../types'

export const pantherApi = createApi({
  reducerPath: 'pantherApi',
  baseQuery: fetchBaseQuery({
    baseUrl: import.meta.env.VITE_API_BASE_URL || '/api/v1',
    prepareHeaders: (headers, { getState }) => {
      const state = getState() as RootState
      const { pantherHost, pantherToken, userEmail } = state.auth
      if (pantherHost) {
        headers.set('X-Panther-Host', pantherHost)
      }
      if (pantherToken) {
        headers.set('X-Panther-Token', pantherToken)
      }
      if (userEmail) {
        headers.set('X-User-Email', userEmail)
      }
      return headers
    },
  }),
  tagTypes: ['Alert', 'Rule', 'SavedQuery', 'SuppressionRule', 'Settings', 'Webhook', 'UserRole', 'AuditLog', 'Playbook', 'ScheduledReport', 'Incident', 'CorrelationRule', 'Case', 'EnrichmentPipeline', 'Dashboard', 'MitreMapping', 'SLAPolicy', 'Note', 'Notification'],
  endpoints: (builder) => ({
    // Alerts
    listAlerts: builder.query<PaginatedResponse<AlertSummary>, AlertFilters>({
      query: (filters) => ({
        url: '/alerts',
        params: filters,
      }),
      providesTags: ['Alert'],
    }),

    getAlert: builder.query<Alert, string>({
      query: (id) => `/alerts/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'Alert', id }],
    }),

    updateAlert: builder.mutation<Alert, { id: string; status?: string; assigneeId?: string }>({
      query: ({ id, ...update }) => ({
        url: `/alerts/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: (_result, _error, { id }) => [{ type: 'Alert', id }, 'Alert'],
    }),

    getAlertEvents: builder.query<PaginatedResponse<AlertEvent>, { alertId: string; pageSize?: number }>({
      query: ({ alertId, pageSize = 50 }) => ({
        url: `/alerts/${alertId}/events`,
        params: { pageSize },
      }),
    }),

    addAlertComment: builder.mutation<AlertComment, { alertId: string; body: string }>({
      query: ({ alertId, body }) => ({
        url: `/alerts/${alertId}/comments`,
        method: 'POST',
        body: { body },
      }),
      invalidatesTags: (_result, _error, { alertId }) => [{ type: 'Alert', id: alertId }],
    }),

    // Rules
    listRules: builder.query<PaginatedResponse<RuleSummary>, RuleFilters>({
      query: (filters) => ({
        url: '/rules',
        params: filters,
      }),
      providesTags: ['Rule'],
    }),

    getRule: builder.query<Rule, string>({
      query: (id) => `/rules/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'Rule', id }],
    }),

    createRule: builder.mutation<Rule, RuleCreate>({
      query: (rule) => ({
        url: '/rules',
        method: 'POST',
        body: rule,
      }),
      invalidatesTags: ['Rule'],
    }),

    updateRule: builder.mutation<Rule, { id: string; update: RuleUpdate }>({
      query: ({ id, update }) => ({
        url: `/rules/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: (_result, _error, { id }) => [{ type: 'Rule', id }, 'Rule'],
    }),

    deleteRule: builder.mutation<void, string>({
      query: (id) => ({
        url: `/rules/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['Rule'],
    }),

    testRule: builder.mutation<{ total: number; passed: number; failed: number; results: unknown[] }, string>({
      query: (ruleId) => ({
        url: `/rules/${ruleId}/test`,
        method: 'POST',
      }),
    }),

    // Converter
    convertSPL: builder.mutation<ConversionResult, SPLConvertRequest>({
      query: (request) => ({
        url: '/converter/convert',
        method: 'POST',
        body: request,
      }),
    }),

    // Queries (Data Lake)
    executeQuery: builder.mutation<QueryResult, QueryRequest>({
      query: (request) => ({
        url: '/queries/execute',
        method: 'POST',
        body: request,
      }),
    }),

    // Analytics
    getAlertAnalytics: builder.query<AnalyticsResponse, { days?: number }>({
      query: ({ days = 7 }) => ({
        url: '/analytics/alerts',
        params: { days },
      }),
    }),

    // Bulk Alert Actions
    bulkUpdateAlerts: builder.mutation<BulkUpdateResult, BulkUpdateRequest>({
      query: (request) => ({
        url: '/alerts/bulk-update',
        method: 'POST',
        body: request,
      }),
      invalidatesTags: ['Alert'],
    }),

    // Saved Queries
    listSavedQueries: builder.query<SavedQuery[], void>({
      query: () => '/saved-queries',
      providesTags: ['SavedQuery'],
    }),

    createSavedQuery: builder.mutation<SavedQuery, SavedQueryCreate>({
      query: (query) => ({
        url: '/saved-queries',
        method: 'POST',
        body: query,
      }),
      invalidatesTags: ['SavedQuery'],
    }),

    updateSavedQuery: builder.mutation<SavedQuery, { id: string; update: Partial<SavedQueryCreate> }>({
      query: ({ id, update }) => ({
        url: `/saved-queries/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: ['SavedQuery'],
    }),

    deleteSavedQuery: builder.mutation<void, string>({
      query: (id) => ({
        url: `/saved-queries/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['SavedQuery'],
    }),

    // Suppression Rules
    listSuppressionRules: builder.query<SuppressionRule[], { activeOnly?: boolean }>({
      query: ({ activeOnly }) => ({
        url: '/suppression-rules',
        params: activeOnly ? { active_only: true } : {},
      }),
      providesTags: ['SuppressionRule'],
    }),

    createSuppressionRule: builder.mutation<SuppressionRule, SuppressionRuleCreate>({
      query: (rule) => ({
        url: '/suppression-rules',
        method: 'POST',
        body: rule,
      }),
      invalidatesTags: ['SuppressionRule'],
    }),

    updateSuppressionRule: builder.mutation<SuppressionRule, { id: string; update: Partial<SuppressionRuleCreate> }>({
      query: ({ id, update }) => ({
        url: `/suppression-rules/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: ['SuppressionRule'],
    }),

    deleteSuppressionRule: builder.mutation<void, string>({
      query: (id) => ({
        url: `/suppression-rules/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['SuppressionRule'],
    }),

    // User Settings
    getSettings: builder.query<UserSettings, void>({
      query: () => '/settings',
      providesTags: ['Settings'],
    }),

    updateSettings: builder.mutation<UserSettings, Partial<UserSettings>>({
      query: (update) => ({
        url: '/settings',
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: ['Settings'],
    }),

    // Webhooks
    listWebhooks: builder.query<WebhookConfig[], void>({
      query: () => '/webhooks',
      providesTags: ['Webhook'],
    }),

    createWebhook: builder.mutation<WebhookConfig, WebhookCreate>({
      query: (webhook) => ({
        url: '/webhooks',
        method: 'POST',
        body: webhook,
      }),
      invalidatesTags: ['Webhook'],
    }),

    updateWebhook: builder.mutation<WebhookConfig, { id: string; update: Partial<WebhookCreate> }>({
      query: ({ id, update }) => ({
        url: `/webhooks/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: ['Webhook'],
    }),

    deleteWebhook: builder.mutation<void, string>({
      query: (id) => ({
        url: `/webhooks/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['Webhook'],
    }),

    testWebhook: builder.mutation<WebhookTestResult, string>({
      query: (id) => ({
        url: `/webhooks/${id}/test`,
        method: 'POST',
      }),
    }),

    // IOC Search
    searchIOC: builder.mutation<IOCSearchResult, IOCSearchRequest>({
      query: (request) => ({
        url: '/ioc/search',
        method: 'POST',
        body: request,
      }),
    }),

    getIndicatorTypes: builder.query<IndicatorType[], void>({
      query: () => '/ioc/types',
    }),

    // Threat Intel
    lookupThreatIntel: builder.mutation<ThreatIntelResult, ThreatIntelRequest>({
      query: (request) => ({
        url: '/threat-intel/lookup',
        method: 'POST',
        body: request,
      }),
    }),

    getThreatIntelStatus: builder.query<ThreatIntelStatus, void>({
      query: () => '/threat-intel/status',
    }),

    // User Roles
    listUserRoles: builder.query<UserRoleResponse[], void>({
      query: () => '/roles',
      providesTags: ['UserRole'],
    }),

    getMyRole: builder.query<CurrentUserRoleResponse, void>({
      query: () => '/roles/me',
    }),

    createUserRole: builder.mutation<UserRoleResponse, UserRoleCreate>({
      query: (role) => ({
        url: '/roles',
        method: 'POST',
        body: role,
      }),
      invalidatesTags: ['UserRole'],
    }),

    updateUserRole: builder.mutation<UserRoleResponse, { id: string; role: string }>({
      query: ({ id, role }) => ({
        url: `/roles/${id}`,
        method: 'PATCH',
        body: { role },
      }),
      invalidatesTags: ['UserRole'],
    }),

    deleteUserRole: builder.mutation<void, string>({
      query: (id) => ({
        url: `/roles/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['UserRole'],
    }),

    // Audit Logs
    listAuditLogs: builder.query<AuditLogListResponse, AuditLogFilters>({
      query: (filters) => ({
        url: '/audit',
        params: filters,
      }),
      providesTags: ['AuditLog'],
    }),

    getAuditActions: builder.query<string[], void>({
      query: () => '/audit/actions',
    }),

    getAuditResourceTypes: builder.query<string[], void>({
      query: () => '/audit/resource-types',
    }),

    // Playbooks
    listPlaybooks: builder.query<PlaybookResponse[], { status?: string }>({
      query: (params) => ({
        url: '/playbooks',
        params,
      }),
      providesTags: ['Playbook'],
    }),

    getPlaybook: builder.query<PlaybookResponse, string>({
      query: (id) => `/playbooks/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'Playbook', id }],
    }),

    createPlaybook: builder.mutation<PlaybookResponse, PlaybookCreate>({
      query: (playbook) => ({
        url: '/playbooks',
        method: 'POST',
        body: playbook,
      }),
      invalidatesTags: ['Playbook'],
    }),

    updatePlaybook: builder.mutation<PlaybookResponse, { id: string; update: Partial<PlaybookCreate> & { status?: string } }>({
      query: ({ id, update }) => ({
        url: `/playbooks/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: (_result, _error, { id }) => [{ type: 'Playbook', id }, 'Playbook'],
    }),

    deletePlaybook: builder.mutation<void, string>({
      query: (id) => ({
        url: `/playbooks/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['Playbook'],
    }),

    executePlaybook: builder.mutation<PlaybookExecutionResponse, { playbookId: string; alertId: string; alertData?: Record<string, unknown> }>({
      query: ({ playbookId, alertId, alertData }) => ({
        url: `/playbooks/${playbookId}/execute`,
        method: 'POST',
        body: { alert_id: alertId, alert_data: alertData },
      }),
    }),

    listPlaybookExecutions: builder.query<PlaybookExecutionListResponse, { playbookId: string; page?: number; pageSize?: number }>({
      query: ({ playbookId, page = 1, pageSize = 20 }) => ({
        url: `/playbooks/${playbookId}/executions`,
        params: { page, page_size: pageSize },
      }),
    }),

    listRecentExecutions: builder.query<PlaybookExecutionResponse[], { limit?: number }>({
      query: ({ limit = 10 }) => ({
        url: '/playbooks/executions/recent',
        params: { limit },
      }),
    }),

    // Scheduled Reports
    listScheduledReports: builder.query<ScheduledReportResponse[], { activeOnly?: boolean }>({
      query: ({ activeOnly }) => ({
        url: '/scheduled-reports',
        params: activeOnly ? { active_only: true } : {},
      }),
      providesTags: ['ScheduledReport'],
    }),

    getScheduledReport: builder.query<ScheduledReportResponse, string>({
      query: (id) => `/scheduled-reports/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'ScheduledReport', id }],
    }),

    createScheduledReport: builder.mutation<ScheduledReportResponse, ScheduledReportCreate>({
      query: (report) => ({
        url: '/scheduled-reports',
        method: 'POST',
        body: report,
      }),
      invalidatesTags: ['ScheduledReport'],
    }),

    updateScheduledReport: builder.mutation<ScheduledReportResponse, { id: string; update: Partial<ScheduledReportCreate> }>({
      query: ({ id, update }) => ({
        url: `/scheduled-reports/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: (_result, _error, { id }) => [{ type: 'ScheduledReport', id }, 'ScheduledReport'],
    }),

    deleteScheduledReport: builder.mutation<void, string>({
      query: (id) => ({
        url: `/scheduled-reports/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['ScheduledReport'],
    }),

    runScheduledReport: builder.mutation<{ status: string; filename: string; email_sent: boolean }, string>({
      query: (id) => ({
        url: `/scheduled-reports/${id}/run`,
        method: 'POST',
      }),
    }),

    // Incidents
    listIncidents: builder.query<IncidentListResponse, IncidentFilters>({
      query: (filters) => ({
        url: '/incidents',
        params: filters,
      }),
      providesTags: ['Incident'],
    }),

    getIncident: builder.query<IncidentDetailResponse, string>({
      query: (id) => `/incidents/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'Incident', id }],
    }),

    createIncident: builder.mutation<IncidentDetailResponse, IncidentCreate>({
      query: (incident) => ({
        url: '/incidents',
        method: 'POST',
        body: incident,
      }),
      invalidatesTags: ['Incident'],
    }),

    updateIncident: builder.mutation<IncidentResponse, { id: string; update: IncidentUpdate }>({
      query: ({ id, update }) => ({
        url: `/incidents/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: (_result, _error, { id }) => [{ type: 'Incident', id }, 'Incident'],
    }),

    deleteIncident: builder.mutation<void, string>({
      query: (id) => ({
        url: `/incidents/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['Incident'],
    }),

    addAlertsToIncident: builder.mutation<{ added: number; total: number }, { incidentId: string; alertIds: string[] }>({
      query: ({ incidentId, alertIds }) => ({
        url: `/incidents/${incidentId}/alerts`,
        method: 'POST',
        body: { alert_ids: alertIds },
      }),
      invalidatesTags: (_result, _error, { incidentId }) => [{ type: 'Incident', id: incidentId }],
    }),

    removeAlertFromIncident: builder.mutation<void, { incidentId: string; alertId: string }>({
      query: ({ incidentId, alertId }) => ({
        url: `/incidents/${incidentId}/alerts/${alertId}`,
        method: 'DELETE',
      }),
      invalidatesTags: (_result, _error, { incidentId }) => [{ type: 'Incident', id: incidentId }],
    }),

    // Correlation Rules
    listCorrelationRules: builder.query<CorrelationRuleResponse[], { activeOnly?: boolean }>({
      query: ({ activeOnly }) => ({
        url: '/correlation-rules',
        params: activeOnly ? { active_only: true } : {},
      }),
      providesTags: ['CorrelationRule'],
    }),

    getCorrelationRule: builder.query<CorrelationRuleResponse, string>({
      query: (id) => `/correlation-rules/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'CorrelationRule', id }],
    }),

    createCorrelationRule: builder.mutation<CorrelationRuleResponse, CorrelationRuleCreate>({
      query: (rule) => ({
        url: '/correlation-rules',
        method: 'POST',
        body: rule,
      }),
      invalidatesTags: ['CorrelationRule'],
    }),

    updateCorrelationRule: builder.mutation<CorrelationRuleResponse, { id: string; update: CorrelationRuleUpdate }>({
      query: ({ id, update }) => ({
        url: `/correlation-rules/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: (_result, _error, { id }) => [{ type: 'CorrelationRule', id }, 'CorrelationRule'],
    }),

    deleteCorrelationRule: builder.mutation<void, string>({
      query: (id) => ({
        url: `/correlation-rules/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['CorrelationRule'],
    }),

    // Cases
    listCases: builder.query<CaseListResponse, CaseFilters>({
      query: (filters) => ({
        url: '/cases',
        params: filters,
      }),
      providesTags: ['Case'],
    }),

    getCase: builder.query<CaseDetailResponse, string>({
      query: (id) => `/cases/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'Case', id }],
    }),

    getCaseTimeline: builder.query<CaseActivityResponse[], { caseId: string; limit?: number }>({
      query: ({ caseId, limit = 50 }) => ({
        url: `/cases/${caseId}/timeline`,
        params: { limit },
      }),
      providesTags: (_result, _error, { caseId }) => [{ type: 'Case', id: caseId }],
    }),

    createCase: builder.mutation<CaseDetailResponse, CaseCreate>({
      query: (caseData) => ({
        url: '/cases',
        method: 'POST',
        body: caseData,
      }),
      invalidatesTags: ['Case'],
    }),

    updateCase: builder.mutation<CaseResponse, { id: string; update: CaseUpdate }>({
      query: ({ id, update }) => ({
        url: `/cases/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: (_result, _error, { id }) => [{ type: 'Case', id }, 'Case'],
    }),

    deleteCase: builder.mutation<void, string>({
      query: (id) => ({
        url: `/cases/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['Case'],
    }),

    addCaseComment: builder.mutation<CaseActivityResponse, { caseId: string; comment: string }>({
      query: ({ caseId, comment }) => ({
        url: `/cases/${caseId}/comments`,
        method: 'POST',
        body: { comment },
      }),
      invalidatesTags: (_result, _error, { caseId }) => [{ type: 'Case', id: caseId }],
    }),

    linkIncidentToCase: builder.mutation<{ status: string; incident_id: string }, { caseId: string; incidentId: string }>({
      query: ({ caseId, incidentId }) => ({
        url: `/cases/${caseId}/incidents`,
        method: 'POST',
        body: { incident_id: incidentId },
      }),
      invalidatesTags: (_result, _error, { caseId }) => [{ type: 'Case', id: caseId }],
    }),

    unlinkIncidentFromCase: builder.mutation<void, { caseId: string; incidentId: string }>({
      query: ({ caseId, incidentId }) => ({
        url: `/cases/${caseId}/incidents/${incidentId}`,
        method: 'DELETE',
      }),
      invalidatesTags: (_result, _error, { caseId }) => [{ type: 'Case', id: caseId }],
    }),

    // Enrichment Pipelines
    listEnrichmentPipelines: builder.query<EnrichmentPipelineResponse[], { activeOnly?: boolean; enrichmentType?: string }>({
      query: (params) => ({
        url: '/enrichment',
        params: {
          ...(params.activeOnly && { active_only: true }),
          ...(params.enrichmentType && { enrichment_type: params.enrichmentType }),
        },
      }),
      providesTags: ['EnrichmentPipeline'],
    }),

    getEnrichmentTypes: builder.query<{ value: string; label: string }[], void>({
      query: () => '/enrichment/types',
    }),

    getEnrichmentPipeline: builder.query<EnrichmentPipelineResponse, string>({
      query: (id) => `/enrichment/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'EnrichmentPipeline', id }],
    }),

    createEnrichmentPipeline: builder.mutation<EnrichmentPipelineResponse, EnrichmentPipelineCreate>({
      query: (pipeline) => ({
        url: '/enrichment',
        method: 'POST',
        body: pipeline,
      }),
      invalidatesTags: ['EnrichmentPipeline'],
    }),

    updateEnrichmentPipeline: builder.mutation<EnrichmentPipelineResponse, { id: string; update: EnrichmentPipelineUpdate }>({
      query: ({ id, update }) => ({
        url: `/enrichment/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: (_result, _error, { id }) => [{ type: 'EnrichmentPipeline', id }, 'EnrichmentPipeline'],
    }),

    deleteEnrichmentPipeline: builder.mutation<void, string>({
      query: (id) => ({
        url: `/enrichment/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['EnrichmentPipeline'],
    }),

    testEnrichmentPipeline: builder.mutation<EnrichmentTestResult, { pipelineId: string; value: string }>({
      query: ({ pipelineId, value }) => ({
        url: `/enrichment/${pipelineId}/test`,
        method: 'POST',
        body: { value },
      }),
    }),

    enrichAlert: builder.mutation<EnrichAlertResult, { alertId: string; alertData: Record<string, unknown>; pipelineIds?: string[] }>({
      query: ({ alertId, alertData, pipelineIds }) => ({
        url: '/enrichment/enrich-alert',
        method: 'POST',
        body: { alert_id: alertId, alert_data: alertData, pipeline_ids: pipelineIds },
      }),
    }),

    getAlertEnrichments: builder.query<AlertEnrichmentsResult, string>({
      query: (alertId) => `/enrichment/alerts/${alertId}`,
    }),

    // Dashboards
    listDashboards: builder.query<DashboardResponse[], void>({
      query: () => '/dashboards',
      providesTags: ['Dashboard'],
    }),

    getWidgetTypes: builder.query<WidgetTypeInfo[], void>({
      query: () => '/dashboards/widget-types',
    }),

    getDashboard: builder.query<DashboardResponse, string>({
      query: (id) => `/dashboards/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'Dashboard', id }],
    }),

    createDashboard: builder.mutation<DashboardResponse, DashboardCreate>({
      query: (dashboard) => ({
        url: '/dashboards',
        method: 'POST',
        body: dashboard,
      }),
      invalidatesTags: ['Dashboard'],
    }),

    updateDashboard: builder.mutation<DashboardResponse, { id: string; update: DashboardUpdate }>({
      query: ({ id, update }) => ({
        url: `/dashboards/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: (_result, _error, { id }) => [{ type: 'Dashboard', id }, 'Dashboard'],
    }),

    deleteDashboard: builder.mutation<void, string>({
      query: (id) => ({
        url: `/dashboards/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['Dashboard'],
    }),

    // MITRE ATT&CK
    getMitreTactics: builder.query<{ value: string; label: string }[], void>({
      query: () => '/mitre/tactics',
    }),

    getMitreMappings: builder.query<MitreMappingResponse[], { tactic?: string; techniqueId?: string }>({
      query: (params) => ({
        url: '/mitre/mappings',
        params,
      }),
      providesTags: ['MitreMapping'],
    }),

    getMitreCoverage: builder.query<MitreCoverageResponse, void>({
      query: () => '/mitre/coverage',
      providesTags: ['MitreMapping'],
    }),

    getRuleMitreMappings: builder.query<MitreMappingResponse[], string>({
      query: (ruleId) => `/mitre/rules/${ruleId}`,
      providesTags: ['MitreMapping'],
    }),

    createMitreMapping: builder.mutation<MitreMappingResponse, MitreMappingCreate>({
      query: (mapping) => ({
        url: '/mitre/mappings',
        method: 'POST',
        body: mapping,
      }),
      invalidatesTags: ['MitreMapping'],
    }),

    updateMitreMapping: builder.mutation<MitreMappingResponse, { id: string; update: MitreMappingUpdate }>({
      query: ({ id, update }) => ({
        url: `/mitre/mappings/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: ['MitreMapping'],
    }),

    deleteMitreMapping: builder.mutation<void, string>({
      query: (id) => ({
        url: `/mitre/mappings/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['MitreMapping'],
    }),

    // SLA Tracking
    listSLAPolicies: builder.query<SLAPolicyResponse[], { activeOnly?: boolean }>({
      query: ({ activeOnly }) => ({
        url: '/sla/policies',
        params: activeOnly ? { active_only: true } : {},
      }),
      providesTags: ['SLAPolicy'],
    }),

    getSLAPolicy: builder.query<SLAPolicyResponse, string>({
      query: (id) => `/sla/policies/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'SLAPolicy', id }],
    }),

    createSLAPolicy: builder.mutation<SLAPolicyResponse, SLAPolicyCreate>({
      query: (policy) => ({
        url: '/sla/policies',
        method: 'POST',
        body: policy,
      }),
      invalidatesTags: ['SLAPolicy'],
    }),

    updateSLAPolicy: builder.mutation<SLAPolicyResponse, { id: string; update: SLAPolicyUpdate }>({
      query: ({ id, update }) => ({
        url: `/sla/policies/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: (_result, _error, { id }) => [{ type: 'SLAPolicy', id }, 'SLAPolicy'],
    }),

    deleteSLAPolicy: builder.mutation<void, string>({
      query: (id) => ({
        url: `/sla/policies/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['SLAPolicy'],
    }),

    getSLADashboard: builder.query<SLADashboardResponse, { days?: number }>({
      query: ({ days = 7 }) => ({
        url: '/sla/dashboard',
        params: { days },
      }),
    }),

    listSLAMetrics: builder.query<SLAMetricListResponse, SLAMetricFilters>({
      query: (filters) => ({
        url: '/sla/metrics',
        params: filters,
      }),
    }),

    getAlertSLAMetric: builder.query<SLAMetricResponse, string>({
      query: (alertId) => `/sla/metrics/${alertId}`,
    }),

    trackAlertSLA: builder.mutation<SLAMetricResponse, { alert_id: string; severity: string; created_at: string; rule_id?: string }>({
      query: (data) => ({
        url: '/sla/metrics/track',
        method: 'POST',
        body: data,
      }),
    }),

    acknowledgeAlertSLA: builder.mutation<SLAMetricResponse, string>({
      query: (alertId) => ({
        url: `/sla/metrics/${alertId}/acknowledge`,
        method: 'POST',
      }),
    }),

    resolveAlertSLA: builder.mutation<SLAMetricResponse, string>({
      query: (alertId) => ({
        url: `/sla/metrics/${alertId}/resolve`,
        method: 'POST',
      }),
    }),

    // Notes
    listNotes: builder.query<NoteResponse[], { resourceType: NoteResourceType; resourceId: string; includeReplies?: boolean }>({
      query: ({ resourceType, resourceId, includeReplies = true }) => ({
        url: '/notes',
        params: { resource_type: resourceType, resource_id: resourceId, include_replies: includeReplies },
      }),
      providesTags: (_result, _error, { resourceType, resourceId }) => [
        { type: 'Note', id: `${resourceType}-${resourceId}` },
      ],
    }),

    getNoteReplies: builder.query<NoteResponse[], string>({
      query: (noteId) => `/notes/${noteId}/replies`,
      providesTags: (_result, _error, noteId) => [{ type: 'Note', id: noteId }],
    }),

    createNote: builder.mutation<NoteResponse, NoteCreate>({
      query: (note) => ({
        url: '/notes',
        method: 'POST',
        body: note,
      }),
      invalidatesTags: (_result, _error, { resource_type, resource_id }) => [
        { type: 'Note', id: `${resource_type}-${resource_id}` },
        'Notification',
      ],
    }),

    updateNote: builder.mutation<NoteResponse, { id: string; content: string }>({
      query: ({ id, content }) => ({
        url: `/notes/${id}`,
        method: 'PATCH',
        body: { content },
      }),
      invalidatesTags: ['Note'],
    }),

    deleteNote: builder.mutation<void, string>({
      query: (id) => ({
        url: `/notes/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['Note'],
    }),

    // Notifications
    listNotifications: builder.query<NotificationListResponse, { unreadOnly?: boolean; page?: number; pageSize?: number }>({
      query: ({ unreadOnly, page = 1, pageSize = 20 }) => ({
        url: '/notifications',
        params: { unread_only: unreadOnly, page, page_size: pageSize },
      }),
      providesTags: ['Notification'],
    }),

    getUnreadCount: builder.query<{ unread_count: number }, void>({
      query: () => '/notifications/unread-count',
      providesTags: ['Notification'],
    }),

    markNotificationAsRead: builder.mutation<NotificationResponse, string>({
      query: (id) => ({
        url: `/notifications/${id}/read`,
        method: 'POST',
      }),
      invalidatesTags: ['Notification'],
    }),

    markAllNotificationsAsRead: builder.mutation<{ marked_read: number }, void>({
      query: () => ({
        url: '/notifications/read-all',
        method: 'POST',
      }),
      invalidatesTags: ['Notification'],
    }),

    deleteNotification: builder.mutation<void, string>({
      query: (id) => ({
        url: `/notifications/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['Notification'],
    }),

    clearNotifications: builder.mutation<{ deleted: number }, { readOnly?: boolean }>({
      query: ({ readOnly = true }) => ({
        url: '/notifications',
        method: 'DELETE',
        params: { read_only: readOnly },
      }),
      invalidatesTags: ['Notification'],
    }),
  }),
})

// Types for new endpoints
export interface QueryRequest {
  sql: string
  database?: string
  timeout?: number
}

export interface QueryResult {
  queryId: string
  status: string
  sql: string
  results: Record<string, unknown>[]
  columns: { name: string; type: string }[]
  rowsScanned?: number
  bytesScanned?: number
  errorMessage?: string
}

export interface AnalyticsResponse {
  totalAlerts: number
  bySeverity: {
    INFO: number
    LOW: number
    MEDIUM: number
    HIGH: number
    CRITICAL: number
  }
  byStatus: {
    OPEN: number
    TRIAGED: number
    CLOSED: number
    RESOLVED: number
  }
  byDay: Record<string, number>
  topRules: { name: string; count: number }[]
}

// Bulk Update Types
export interface BulkUpdateRequest {
  alert_ids: string[]
  status?: string
  assigneeId?: string
}

export interface BulkUpdateResult {
  success: string[]
  failed: { id: string; error: string }[]
}

// Saved Query Types
export interface SavedQuery {
  id: string
  name: string
  description: string | null
  sql: string
  is_shared: boolean
  created_by: string
  created_at: string
  updated_at: string
}

export interface SavedQueryCreate {
  name: string
  description?: string
  sql: string
  is_shared?: boolean
}

// Suppression Rule Types
export interface SuppressionRule {
  id: string
  name: string
  description: string | null
  rule_id: string | null
  severity: string | null
  title_pattern: string | null
  is_active: boolean
  expires_at: string | null
  created_by: string
  created_at: string
  updated_at: string
}

export interface SuppressionRuleCreate {
  name: string
  description?: string
  rule_id?: string
  severity?: string
  title_pattern?: string
  is_active?: boolean
  expires_at?: string
}

// User Settings Types
export interface UserSettings {
  id: string
  user_id: string
  theme: string
  default_time_range: number
  alerts_per_page: number
  notifications_enabled: boolean
  notification_severities: string[]
  keyboard_shortcuts_enabled: boolean
}

// Webhook Types
export interface WebhookConfig {
  id: string
  name: string
  description: string | null
  webhook_type: string
  url: string
  headers: Record<string, string>
  severity_filter: string[]
  is_active: boolean
  last_triggered_at: string | null
  created_at: string
  updated_at: string
}

export interface WebhookCreate {
  name: string
  description?: string
  webhook_type?: string
  url: string
  secret?: string
  headers?: Record<string, string>
  severity_filter?: string[]
  is_active?: boolean
}

export interface WebhookTestResult {
  success: boolean
  status_code?: number
  message: string
}

// IOC Search Types
export interface IOCSearchRequest {
  indicator: string
  indicator_type?: string
  time_range_days?: number
}

export interface IOCSearchResult {
  indicator: string
  indicator_type: string
  total_matches: number
  sources: { source: string; count: number; first_seen: string; last_seen: string }[]
  first_seen: string | null
  last_seen: string | null
}

export interface IndicatorType {
  value: string
  label: string
}

// Threat Intel Types
export interface ThreatIntelRequest {
  indicator: string
  indicator_type: string
}

export interface ThreatIntelResult {
  indicator: string
  indicator_type: string
  virustotal: Record<string, unknown> | null
  abuseipdb: Record<string, unknown> | null
  error?: string
}

export interface ThreatIntelStatus {
  virustotal: { configured: boolean; supported_types: string[] }
  abuseipdb: { configured: boolean; supported_types: string[] }
}

// User Role Types
export interface UserRoleResponse {
  id: string
  email: string
  role: 'admin' | 'analyst' | 'viewer'
  created_by: string
  created_at: string
  updated_at: string
}

export interface CurrentUserRoleResponse {
  email: string
  role: 'admin' | 'analyst' | 'viewer'
  is_admin_whitelisted: boolean
}

export interface UserRoleCreate {
  email: string
  role: 'admin' | 'analyst' | 'viewer'
}

// Audit Log Types
export interface AuditLogResponse {
  id: string
  user_email: string
  action: string
  resource_type: string
  resource_id: string | null
  details: Record<string, unknown>
  ip_address: string | null
  user_agent: string | null
  created_at: string
}

export interface AuditLogListResponse {
  items: AuditLogResponse[]
  total: number
  page: number
  page_size: number
}

export interface AuditLogFilters {
  user_email?: string
  action?: string
  resource_type?: string
  resource_id?: string
  start_date?: string
  end_date?: string
  page?: number
  page_size?: number
}

// Playbook Types
export type PlaybookStatus = 'active' | 'inactive' | 'draft'
export type ExecutionStatus = 'pending' | 'running' | 'success' | 'failed' | 'partial'
export type ActionType = 'webhook' | 'jira_ticket' | 'servicenow_ticket' | 'update_alert' | 'run_query' | 'crowdstrike_isolate' | 'sentinelone_isolate' | 'firewall_block' | 'soar_trigger'

export interface ActionConfig {
  type: ActionType
  name?: string
  config: Record<string, unknown>
  stop_on_failure?: boolean
}

export interface TriggerConditions {
  severities?: string[]
  rule_ids?: string[]
  title_pattern?: string
}

export interface PlaybookResponse {
  id: string
  name: string
  description: string | null
  trigger_conditions: TriggerConditions
  actions: ActionConfig[]
  status: PlaybookStatus
  auto_execute: boolean
  created_by: string
  created_at: string
  updated_at: string
}

export interface PlaybookCreate {
  name: string
  description?: string
  trigger_conditions?: TriggerConditions
  actions: ActionConfig[]
  auto_execute?: boolean
}

export interface PlaybookExecutionResponse {
  id: string
  playbook_id: string
  alert_id: string
  status: ExecutionStatus
  started_at: string | null
  completed_at: string | null
  action_results: Array<{
    index: number
    type: string
    success: boolean
    message: string
    data?: Record<string, unknown>
    error?: string
  }>
  error_message: string | null
  triggered_by: string
  created_at: string
}

export interface PlaybookExecutionListResponse {
  items: PlaybookExecutionResponse[]
  total: number
  page: number
  page_size: number
}

// Scheduled Report Types
export type ReportFrequency = 'daily' | 'weekly' | 'monthly'

export interface ScheduledReportResponse {
  id: string
  name: string
  description: string | null
  report_type: string
  frequency: ReportFrequency
  recipients: string[]
  filters: Record<string, unknown>
  is_active: boolean
  last_run_at: string | null
  next_run_at: string | null
  created_at: string
  updated_at: string
}

export interface ScheduledReportCreate {
  name: string
  description?: string
  report_type: string
  frequency: ReportFrequency
  recipients?: string[]
  filters?: Record<string, unknown>
  is_active?: boolean
}

// Incident Types
export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'closed'
export type IncidentSeverity = 'low' | 'medium' | 'high' | 'critical'

export interface IncidentResponse {
  id: string
  title: string
  description: string | null
  status: IncidentStatus
  severity: IncidentSeverity
  assignee: string | null
  tags: string[]
  alert_count: number
  created_by: string
  created_at: string
  updated_at: string
}

export interface IncidentDetailResponse extends IncidentResponse {
  alert_ids: string[]
}

export interface IncidentCreate {
  title: string
  description?: string
  severity?: IncidentSeverity
  assignee?: string
  tags?: string[]
  alert_ids?: string[]
}

export interface IncidentUpdate {
  title?: string
  description?: string
  status?: IncidentStatus
  severity?: IncidentSeverity
  assignee?: string
  tags?: string[]
}

export interface IncidentFilters {
  status?: IncidentStatus
  severity?: IncidentSeverity
  page?: number
  page_size?: number
}

export interface IncidentListResponse {
  items: IncidentResponse[]
  total: number
  page: number
  page_size: number
}

// Correlation Rule Types
export interface CorrelationConditions {
  time_window_minutes: number
  min_alerts: number
  field_matches?: string[]
  severity_filter?: string[]
  rule_id_filter?: string[]
}

export interface CorrelationRuleResponse {
  id: string
  name: string
  description: string | null
  conditions: CorrelationConditions
  is_active: boolean
  auto_create_incident: boolean
  created_by: string
  created_at: string
  updated_at: string
}

export interface CorrelationRuleCreate {
  name: string
  description?: string
  conditions: CorrelationConditions
  is_active?: boolean
  auto_create_incident?: boolean
}

export interface CorrelationRuleUpdate {
  name?: string
  description?: string
  conditions?: CorrelationConditions
  is_active?: boolean
  auto_create_incident?: boolean
}

// Case Types
export type CaseStatus = 'open' | 'in_progress' | 'pending' | 'resolved' | 'closed'
export type CasePriority = 'low' | 'medium' | 'high' | 'critical'
export type CaseActivityType = 'created' | 'status_changed' | 'priority_changed' | 'assignee_changed' | 'comment_added' | 'incident_linked' | 'incident_unlinked' | 'attachment_added' | 'updated'

export interface CaseResponse {
  id: string
  case_number: string
  title: string
  description: string | null
  status: CaseStatus
  priority: CasePriority
  assignee: string | null
  tags: string[]
  incident_count: number
  created_by: string
  closed_at: string | null
  created_at: string
  updated_at: string
}

export interface CaseDetailResponse extends CaseResponse {
  incident_ids: string[]
}

export interface CaseCreate {
  title: string
  description?: string
  priority?: CasePriority
  assignee?: string
  tags?: string[]
  incident_ids?: string[]
}

export interface CaseUpdate {
  title?: string
  description?: string
  status?: CaseStatus
  priority?: CasePriority
  assignee?: string
  tags?: string[]
}

export interface CaseFilters {
  status?: CaseStatus
  priority?: CasePriority
  assignee?: string
  page?: number
  page_size?: number
}

export interface CaseListResponse {
  items: CaseResponse[]
  total: number
  page: number
  page_size: number
}

export interface CaseActivityResponse {
  id: string
  activity_type: CaseActivityType
  description: string
  old_value: string | null
  new_value: string | null
  user_email: string
  created_at: string
}

// Enrichment Types
export type EnrichmentType = 'ip_geolocation' | 'ip_reputation' | 'domain_whois' | 'domain_reputation' | 'file_hash' | 'user_lookup' | 'asset_lookup' | 'custom_api'

export interface EnrichmentPipelineResponse {
  id: string
  name: string
  description: string | null
  enrichment_type: EnrichmentType
  source_field: string
  target_field: string
  api_endpoint: string | null
  api_headers: Record<string, string>
  api_key_env: string | null
  cache_ttl_minutes: number
  is_active: boolean
  auto_enrich: boolean
  severity_filter: string[]
  created_by: string
  created_at: string
  updated_at: string
}

export interface EnrichmentPipelineCreate {
  name: string
  description?: string
  enrichment_type: EnrichmentType
  source_field: string
  target_field: string
  api_endpoint?: string
  api_headers?: Record<string, string>
  api_key_env?: string
  cache_ttl_minutes?: number
  is_active?: boolean
  auto_enrich?: boolean
  severity_filter?: string[]
}

export interface EnrichmentPipelineUpdate {
  name?: string
  description?: string
  source_field?: string
  target_field?: string
  api_endpoint?: string
  api_headers?: Record<string, string>
  api_key_env?: string
  cache_ttl_minutes?: number
  is_active?: boolean
  auto_enrich?: boolean
  severity_filter?: string[]
}

export interface EnrichmentTestResult {
  pipeline_id: string
  pipeline_name: string
  input_value: string
  source: 'cache' | 'live'
  data: Record<string, unknown>
}

export interface AlertEnrichmentItem {
  id: string
  pipeline_id: string
  pipeline_name: string
  enrichment_type: EnrichmentType
  source_field: string
  source_value: string
  target_field: string
  data: Record<string, unknown>
  enriched_by: string
  created_at: string
}

export interface EnrichAlertResult {
  alert_id: string
  enrichment_count: number
  enrichments: Array<{
    pipeline_id: string
    pipeline_name: string
    source_field: string
    source_value: string
    target_field: string
    source: 'cache' | 'live'
    data: Record<string, unknown>
  }>
}

export interface AlertEnrichmentsResult {
  alert_id: string
  enrichment_count: number
  enrichments: AlertEnrichmentItem[]
}

// Dashboard Types
export type WidgetType = 'alert_summary' | 'alerts_by_severity' | 'alerts_by_status' | 'alerts_over_time' | 'top_rules' | 'recent_alerts' | 'incident_summary' | 'case_summary' | 'sla_status' | 'custom_query'

export interface LayoutItem {
  i: string
  x: number
  y: number
  w: number
  h: number
  minW?: number
  minH?: number
}

export interface WidgetConfig {
  id: string
  widget_type: WidgetType
  title: string
  config: Record<string, unknown>
}

export interface DashboardResponse {
  id: string
  name: string
  description: string | null
  is_default: boolean
  is_shared: boolean
  layout: LayoutItem[]
  widgets: WidgetConfig[]
  owner_email: string
  created_at: string
  updated_at: string
}

export interface DashboardCreate {
  name: string
  description?: string
  is_shared?: boolean
  layout?: LayoutItem[]
  widgets?: WidgetConfig[]
}

export interface DashboardUpdate {
  name?: string
  description?: string
  is_default?: boolean
  is_shared?: boolean
  layout?: LayoutItem[]
  widgets?: WidgetConfig[]
}

export interface WidgetTypeInfo {
  value: WidgetType
  label: string
  description: string
  default_size: { w: number; h: number }
}

// MITRE ATT&CK Types
export type MitreTactic =
  | 'reconnaissance'
  | 'resource-development'
  | 'initial-access'
  | 'execution'
  | 'persistence'
  | 'privilege-escalation'
  | 'defense-evasion'
  | 'credential-access'
  | 'discovery'
  | 'lateral-movement'
  | 'collection'
  | 'command-and-control'
  | 'exfiltration'
  | 'impact'

export interface MitreMappingResponse {
  id: string
  rule_id: string
  rule_name: string
  technique_id: string
  technique_name: string
  subtechnique_id: string | null
  subtechnique_name: string | null
  tactic: MitreTactic
  notes: string | null
  created_by: string
  created_at: string
  updated_at: string
}

export interface MitreMappingCreate {
  rule_id: string
  rule_name: string
  technique_id: string
  technique_name: string
  subtechnique_id?: string
  subtechnique_name?: string
  tactic: MitreTactic
  notes?: string
}

export interface MitreMappingUpdate {
  technique_id?: string
  technique_name?: string
  subtechnique_id?: string
  subtechnique_name?: string
  tactic?: MitreTactic
  notes?: string
}

export interface TechniqueInfo {
  technique_id: string
  technique_name: string
  rule_count: number
}

export interface TacticCoverage {
  tactic: MitreTactic
  label: string
  technique_count: number
  techniques: TechniqueInfo[]
}

export interface MitreCoverageResponse {
  total_techniques: number
  total_mapped_rules: number
  by_tactic: TacticCoverage[]
}

// SLA Types
export type SLAStatus = 'on_track' | 'at_risk' | 'breached'

export interface SLAPolicyResponse {
  id: string
  name: string
  description: string | null
  ack_time_critical: number
  ack_time_high: number
  ack_time_medium: number
  ack_time_low: number
  resolve_time_critical: number
  resolve_time_high: number
  resolve_time_medium: number
  resolve_time_low: number
  is_default: boolean
  is_active: boolean
  rule_ids: string[]
  created_by: string
  created_at: string
  updated_at: string
}

export interface SLAPolicyCreate {
  name: string
  description?: string
  ack_time_critical?: number
  ack_time_high?: number
  ack_time_medium?: number
  ack_time_low?: number
  resolve_time_critical?: number
  resolve_time_high?: number
  resolve_time_medium?: number
  resolve_time_low?: number
  is_default?: boolean
  is_active?: boolean
  rule_ids?: string[]
}

export interface SLAPolicyUpdate {
  name?: string
  description?: string
  ack_time_critical?: number
  ack_time_high?: number
  ack_time_medium?: number
  ack_time_low?: number
  resolve_time_critical?: number
  resolve_time_high?: number
  resolve_time_medium?: number
  resolve_time_low?: number
  is_default?: boolean
  is_active?: boolean
  rule_ids?: string[]
}

export interface SLAMetricResponse {
  id: string
  alert_id: string
  policy_id: string
  severity: string
  alert_created_at: string
  acknowledged_at: string | null
  resolved_at: string | null
  ack_target_minutes: number
  resolve_target_minutes: number
  ack_status: SLAStatus
  resolve_status: SLAStatus
  ack_time_minutes: number | null
  resolve_time_minutes: number | null
  created_at: string
  updated_at: string
}

export interface SLAMetricFilters {
  severity?: string
  status?: SLAStatus
  days?: number
  page?: number
  page_size?: number
}

export interface SLAMetricListResponse {
  items: SLAMetricResponse[]
  total: number
  page: number
  page_size: number
}

export interface SLASummary {
  total_alerts: number
  on_track: number
  at_risk: number
  breached: number
  avg_ack_time_minutes: number | null
  avg_resolve_time_minutes: number | null
  ack_compliance_rate: number
  resolve_compliance_rate: number
}

export interface SLADashboardResponse {
  summary: SLASummary
  by_severity: Record<string, SLASummary>
  recent_breaches: SLAMetricResponse[]
}

// Notes Types
export type NoteResourceType = 'alert' | 'incident' | 'case' | 'rule'

export interface NoteResponse {
  id: string
  resource_type: NoteResourceType
  resource_id: string
  content: string
  mentions: string[]
  is_edited: boolean
  parent_id: string | null
  created_by: string
  created_at: string
  updated_at: string
  reply_count?: number
}

export interface NoteCreate {
  resource_type: NoteResourceType
  resource_id: string
  content: string
  parent_id?: string
}

// Notification Types
export type NotificationType =
  | 'mention'
  | 'alert_assigned'
  | 'incident_assigned'
  | 'case_assigned'
  | 'comment_reply'
  | 'sla_warning'
  | 'sla_breach'
  | 'playbook_completed'
  | 'playbook_failed'

export interface NotificationResponse {
  id: string
  notification_type: NotificationType
  title: string
  message: string
  resource_type: string | null
  resource_id: string | null
  is_read: boolean
  read_at: string | null
  created_by: string | null
  created_at: string
}

export interface NotificationListResponse {
  items: NotificationResponse[]
  total: number
  unread_count: number
}

export const {
  useListAlertsQuery,
  useGetAlertQuery,
  useUpdateAlertMutation,
  useGetAlertEventsQuery,
  useAddAlertCommentMutation,
  useListRulesQuery,
  useGetRuleQuery,
  useCreateRuleMutation,
  useUpdateRuleMutation,
  useDeleteRuleMutation,
  useTestRuleMutation,
  useConvertSPLMutation,
  useExecuteQueryMutation,
  useGetAlertAnalyticsQuery,
  useBulkUpdateAlertsMutation,
  useListSavedQueriesQuery,
  useCreateSavedQueryMutation,
  useUpdateSavedQueryMutation,
  useDeleteSavedQueryMutation,
  useListSuppressionRulesQuery,
  useCreateSuppressionRuleMutation,
  useUpdateSuppressionRuleMutation,
  useDeleteSuppressionRuleMutation,
  useGetSettingsQuery,
  useUpdateSettingsMutation,
  useListWebhooksQuery,
  useCreateWebhookMutation,
  useUpdateWebhookMutation,
  useDeleteWebhookMutation,
  useTestWebhookMutation,
  useSearchIOCMutation,
  useGetIndicatorTypesQuery,
  useLookupThreatIntelMutation,
  useGetThreatIntelStatusQuery,
  useListUserRolesQuery,
  useGetMyRoleQuery,
  useCreateUserRoleMutation,
  useUpdateUserRoleMutation,
  useDeleteUserRoleMutation,
  useListAuditLogsQuery,
  useGetAuditActionsQuery,
  useGetAuditResourceTypesQuery,
  useListPlaybooksQuery,
  useGetPlaybookQuery,
  useCreatePlaybookMutation,
  useUpdatePlaybookMutation,
  useDeletePlaybookMutation,
  useExecutePlaybookMutation,
  useListPlaybookExecutionsQuery,
  useListRecentExecutionsQuery,
  useListScheduledReportsQuery,
  useGetScheduledReportQuery,
  useCreateScheduledReportMutation,
  useUpdateScheduledReportMutation,
  useDeleteScheduledReportMutation,
  useRunScheduledReportMutation,
  useListIncidentsQuery,
  useGetIncidentQuery,
  useCreateIncidentMutation,
  useUpdateIncidentMutation,
  useDeleteIncidentMutation,
  useAddAlertsToIncidentMutation,
  useRemoveAlertFromIncidentMutation,
  useListCorrelationRulesQuery,
  useGetCorrelationRuleQuery,
  useCreateCorrelationRuleMutation,
  useUpdateCorrelationRuleMutation,
  useDeleteCorrelationRuleMutation,
  useListCasesQuery,
  useGetCaseQuery,
  useGetCaseTimelineQuery,
  useCreateCaseMutation,
  useUpdateCaseMutation,
  useDeleteCaseMutation,
  useAddCaseCommentMutation,
  useLinkIncidentToCaseMutation,
  useUnlinkIncidentFromCaseMutation,
  useListEnrichmentPipelinesQuery,
  useGetEnrichmentTypesQuery,
  useGetEnrichmentPipelineQuery,
  useCreateEnrichmentPipelineMutation,
  useUpdateEnrichmentPipelineMutation,
  useDeleteEnrichmentPipelineMutation,
  useTestEnrichmentPipelineMutation,
  useEnrichAlertMutation,
  useGetAlertEnrichmentsQuery,
  useListDashboardsQuery,
  useGetWidgetTypesQuery,
  useGetDashboardQuery,
  useCreateDashboardMutation,
  useUpdateDashboardMutation,
  useDeleteDashboardMutation,
  useGetMitreTacticsQuery,
  useGetMitreMappingsQuery,
  useGetMitreCoverageQuery,
  useGetRuleMitreMappingsQuery,
  useCreateMitreMappingMutation,
  useUpdateMitreMappingMutation,
  useDeleteMitreMappingMutation,
  useListSLAPoliciesQuery,
  useGetSLAPolicyQuery,
  useCreateSLAPolicyMutation,
  useUpdateSLAPolicyMutation,
  useDeleteSLAPolicyMutation,
  useGetSLADashboardQuery,
  useListSLAMetricsQuery,
  useGetAlertSLAMetricQuery,
  useTrackAlertSLAMutation,
  useAcknowledgeAlertSLAMutation,
  useResolveAlertSLAMutation,
  useListNotesQuery,
  useGetNoteRepliesQuery,
  useCreateNoteMutation,
  useUpdateNoteMutation,
  useDeleteNoteMutation,
  useListNotificationsQuery,
  useGetUnreadCountQuery,
  useMarkNotificationAsReadMutation,
  useMarkAllNotificationsAsReadMutation,
  useDeleteNotificationMutation,
  useClearNotificationsMutation,
} = pantherApi
