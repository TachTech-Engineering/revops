import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react'
import type { BaseQueryApi, BaseQueryFn, FetchArgs, FetchBaseQueryError } from '@reduxjs/toolkit/query'
import type { RootState } from '../store'
import { setTokens, logout } from '../store/authSlice'
import type {
  Alert,
  AlertSummary,
  AlertEvent,
  AlertComment,
  AlertFilters,
  RuleSummary,
  RuleFilters,
  PaginatedResponse,
} from '../types'

const API_BASE = import.meta.env.VITE_API_BASE_URL || ''

const baseQuery = fetchBaseQuery({
  baseUrl: `${API_BASE}/api/v1`,
  prepareHeaders: (headers, { getState }) => {
    const state = getState() as RootState
    const { accessToken, userEmail } = state.auth
    if (accessToken) {
      headers.set('Authorization', `Bearer ${accessToken}`)
    }
    if (userEmail) {
      headers.set('X-User-Email', userEmail)
    }
    return headers
  },
})

// --- Refresh mutex -----------------------------------------------------------
// The backend ROTATES refresh tokens: every POST /auth/refresh revokes the old
// token and mints a new one. If N requests 401 at the same time and each fires
// its own refresh call, all but the first use an already-revoked token and
// fail, causing a spurious logout. So the first 401 starts the refresh and
// stashes the in-flight promise here; concurrent 401s await the SAME promise
// and then retry with the new token. Resolves true if tokens were refreshed.
let refreshPromise: Promise<boolean> | null = null

const refreshTokens = async (api: BaseQueryApi): Promise<boolean> => {
  const { refreshToken } = (api.getState() as RootState).auth
  if (!refreshToken) {
    return false
  }
  try {
    const response = await fetch(`${API_BASE}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    })
    if (!response.ok) {
      return false
    }
    const data = (await response.json()) as { access_token: string; refresh_token: string }
    api.dispatch(setTokens({
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
    }))
    return true
  } catch {
    // Network failure etc. -- treat like a failed refresh
    return false
  }
}

// Wrapper that handles token refresh on 401
const baseQueryWithReauth: BaseQueryFn<string | FetchArgs, unknown, FetchBaseQueryError> = async (
  args,
  api,
  extraOptions
) => {
  let result = await baseQuery(args, api, extraOptions)

  if (result.error && result.error.status === 401) {
    if (!refreshPromise) {
      // First 401 wins: start the refresh and clear the slot when it settles.
      // refreshTokens never rejects, so .finally is purely cleanup.
      refreshPromise = refreshTokens(api).finally(() => {
        refreshPromise = null
      })
    }
    const refreshed = await refreshPromise

    if (refreshed) {
      // Retry the original request; prepareHeaders picks up the new token
      result = await baseQuery(args, api, extraOptions)
    } else if ((api.getState() as RootState).auth.isAuthenticated) {
      // Refresh failed (or no refresh token) -- log out once; concurrent
      // awaiters see isAuthenticated === false and skip the dispatch.
      api.dispatch(logout())
    }
  }

  return result
}

export const revopsApi = createApi({
  reducerPath: 'revopsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Alert', 'Rule', 'SavedQuery', 'Settings', 'Webhook', 'UserRole', 'User', 'AuditLog', 'ScheduledReport', 'Incident', 'Case', 'EnrichmentPipeline', 'Dashboard', 'MitreMapping', 'SLAPolicy', 'Note', 'Notification', 'IOC', 'Feed', 'Connector', 'Pipeline', 'Workflow', 'WorkflowExecution', 'NormalizedAlert', 'RuleHealth', 'TriageSuggestion', 'AssetCriticality', 'NLQuery', 'AlertCluster', 'PlaybookTemplate', 'EscalationPolicy', 'OnCallSchedule', 'TrendAnalytics', 'Anomaly', 'AISettings', 'ComplianceFramework', 'ComplianceControl', 'ComplianceAssessment', 'ExecutiveMetrics', 'ThreatHunt', 'HuntResult'],
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

    // User Management (actual user accounts)
    listUsers: builder.query<UserListResponse, UserListFilters>({
      query: (filters) => ({
        url: '/users',
        params: filters,
      }),
      providesTags: ['User'],
    }),

    getUser: builder.query<UserAccountResponse, string>({
      query: (id) => `/users/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'User', id }],
    }),

    updateUser: builder.mutation<UserAccountResponse, { id: string; role?: string; is_active?: boolean }>({
      query: ({ id, ...update }) => ({
        url: `/users/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: ['User'],
    }),

    deleteUser: builder.mutation<void, string>({
      query: (id) => ({
        url: `/users/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['User'],
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

    // Cases
    listCases: builder.query<CaseListResponse, CaseFilters>({
      query: (filters) => ({
        url: '/cases',
        params: filters,
      }),
      providesTags: ['Case'],
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

    getMitreAlertCoverage: builder.query<MitreAlertCoverageResponse, { days?: number }>({
      query: (params) => ({
        url: '/mitre/coverage/alerts',
        params,
      }),
      providesTags: ['NormalizedAlert'],
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

    // Phase 5: IOC Management
    listIOCs: builder.query<IOCListResponse, { query?: string; ioc_type?: string; severity?: string; source?: string; is_active?: boolean; page?: number; page_size?: number }>({
      query: (params) => ({
        url: '/iocs',
        params,
      }),
      providesTags: ['IOC'],
    }),

    getIOCStats: builder.query<IOCStatsResponse, void>({
      query: () => '/iocs/stats',
      providesTags: ['IOC'],
    }),

    getIOCTypes: builder.query<{ value: string; label: string }[], void>({
      query: () => '/iocs/types',
    }),

    createIOC: builder.mutation<IOCResponse, IOCCreate>({
      query: (ioc) => ({
        url: '/iocs',
        method: 'POST',
        body: ioc,
      }),
      invalidatesTags: ['IOC'],
    }),

    bulkImportIOCs: builder.mutation<{ added: number; updated: number }, { iocs: IOCCreate[] }>({
      query: (data) => ({
        url: '/iocs/bulk',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['IOC'],
    }),

    importSTIX: builder.mutation<{ added: number; updated: number }, { bundle: Record<string, unknown> }>({
      query: (data) => ({
        url: '/iocs/import/stix',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['IOC'],
    }),

    updateIOC: builder.mutation<IOCResponse, { id: string; update: Partial<IOCCreate & { is_active: boolean }> }>({
      query: ({ id, update }) => ({
        url: `/iocs/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: ['IOC'],
    }),

    deleteIOC: builder.mutation<void, string>({
      query: (id) => ({
        url: `/iocs/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['IOC'],
    }),

    // Phase 5: Threat Feeds
    listFeeds: builder.query<FeedResponse[], { status?: string }>({
      query: (params) => ({
        url: '/feeds',
        params,
      }),
      providesTags: ['Feed'],
    }),

    getFeedTypes: builder.query<{ value: string; label: string; description: string; default_url: string }[], void>({
      query: () => '/feeds/types',
    }),

    createFeed: builder.mutation<FeedResponse, FeedCreate>({
      query: (feed) => ({
        url: '/feeds',
        method: 'POST',
        body: feed,
      }),
      invalidatesTags: ['Feed'],
    }),

    updateFeed: builder.mutation<FeedResponse, { id: string; update: Partial<FeedCreate & { status: string }> }>({
      query: ({ id, update }) => ({
        url: `/feeds/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: ['Feed'],
    }),

    deleteFeed: builder.mutation<void, string>({
      query: (id) => ({
        url: `/feeds/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['Feed'],
    }),

    syncFeed: builder.mutation<{ feed_id: string; status: string; iocs_added: number; iocs_updated: number }, string>({
      query: (id) => ({
        url: `/feeds/${id}/sync`,
        method: 'POST',
      }),
      invalidatesTags: ['Feed', 'IOC'],
    }),

    getFeedLogs: builder.query<SyncLogResponse[], { feedId: string; limit?: number }>({
      query: ({ feedId, limit = 20 }) => ({
        url: `/feeds/${feedId}/logs`,
        params: { limit },
      }),
    }),

    // Phase 5: AI Summarization
    summarizeAlert: builder.mutation<SummaryResponse, { alertId: string; provider?: string; force_refresh?: boolean }>({
      query: ({ alertId, provider, force_refresh }) => ({
        url: `/ai/summarize/alert/${alertId}`,
        method: 'POST',
        body: { provider, force_refresh },
      }),
    }),

    summarizeIncident: builder.mutation<SummaryResponse, { incidentId: string; provider?: string; force_refresh?: boolean }>({
      query: ({ incidentId, provider, force_refresh }) => ({
        url: `/ai/summarize/incident/${incidentId}`,
        method: 'POST',
        body: { provider, force_refresh },
      }),
    }),

    getAISettings: builder.query<AISettingsResponse, void>({
      query: () => '/ai/settings',
      providesTags: ['AISettings'],
    }),

    testAIConnection: builder.mutation<{ status: string; provider: string; model?: string; message: string }, string>({
      query: (provider) => ({
        url: `/ai/test/${provider}`,
        method: 'POST',
      }),
    }),

    // Organization API Key Management
    saveAPIKey: builder.mutation<SaveAPIKeyResponse, SaveAPIKeyRequest>({
      query: (body) => ({
        url: '/ai/keys',
        method: 'POST',
        body,
      }),
      invalidatesTags: ['AISettings'],
    }),

    deleteAPIKey: builder.mutation<{ message: string }, string>({
      query: (provider) => ({
        url: `/ai/keys/${provider}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['AISettings'],
    }),

    testOrganizationAPIKey: builder.mutation<{ status: string; provider: string; model?: string; message: string }, string>({
      query: (provider) => ({
        url: `/ai/keys/${provider}/test`,
        method: 'POST',
      }),
    }),

    testAPIKeyDirect: builder.mutation<{ status: string; provider: string; model?: string; message: string }, { provider: string; api_key: string; model?: string }>({
      query: (body) => ({
        url: '/ai/keys/test',
        method: 'POST',
        body,
      }),
    }),

    // Phase 5: Enhanced Threat Intel (unified lookup)
    unifiedThreatIntelLookup: builder.query<UnifiedThreatIntelResponse, { indicator: string; indicator_type: string }>({
      query: ({ indicator, indicator_type }) => ({
        url: '/threat-intel/lookup',
        params: { indicator, indicator_type },
      }),
    }),

    getThreatIntelSources: builder.query<Record<string, { configured: boolean; supported_types: string[]; description: string }>, void>({
      query: () => '/threat-intel/sources',
    }),

    // SecOps Platform: Connectors
    listConnectors: builder.query<ConnectorListResponse, ConnectorFilters>({
      query: (params) => ({
        url: '/connectors',
        params,
      }),
      providesTags: ['Connector'],
    }),

    getConnector: builder.query<ConnectorResponse, string>({
      query: (id) => `/connectors/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'Connector', id }],
    }),

    getConnectorTypes: builder.query<ConnectorTypeInfo[], void>({
      query: () => '/connectors/types',
    }),

    createConnector: builder.mutation<ConnectorResponse, ConnectorCreate>({
      query: (connector) => ({
        url: '/connectors',
        method: 'POST',
        body: connector,
      }),
      invalidatesTags: ['Connector'],
    }),

    updateConnector: builder.mutation<ConnectorResponse, { id: string; update: ConnectorUpdate }>({
      query: ({ id, update }) => ({
        url: `/connectors/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: (_result, _error, { id }) => [{ type: 'Connector', id }, 'Connector'],
    }),

    deleteConnector: builder.mutation<void, string>({
      query: (id) => ({
        url: `/connectors/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['Connector'],
    }),

    testConnector: builder.mutation<ConnectionTestResult, string>({
      query: (id) => ({
        url: `/connectors/${id}/test`,
        method: 'POST',
      }),
    }),

    syncConnector: builder.mutation<ConnectorSyncResult, { id: string; fullSync?: boolean }>({
      query: ({ id, fullSync = false }) => ({
        url: `/connectors/${id}/sync`,
        method: 'POST',
        params: { full_sync: fullSync },
      }),
      invalidatesTags: ['Connector', 'NormalizedAlert'],
    }),

    listUnifiedAlerts: builder.query<NormalizedAlertListResponse, UnifiedAlertFilters>({
      query: (params) => ({
        url: '/connectors/alerts/unified',
        params,
      }),
      providesTags: ['NormalizedAlert'],
    }),

    // SecOps Platform: Data Pipelines
    listPipelines: builder.query<Pipeline[], { status?: PipelineStatus } | undefined>({
      query: (params) => ({
        url: '/pipelines',
        params,
      }),
      providesTags: ['Pipeline'],
    }),

    getPipeline: builder.query<PipelineDetail, string>({
      query: (id) => `/pipelines/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'Pipeline', id }],
    }),

    listStageTypes: builder.query<StageTypeMetadata[], void>({
      query: () => '/pipelines/stage-types',
    }),

    createPipeline: builder.mutation<Pipeline, PipelineCreate>({
      query: (pipeline) => ({
        url: '/pipelines',
        method: 'POST',
        body: pipeline,
      }),
      invalidatesTags: ['Pipeline'],
    }),

    updatePipeline: builder.mutation<Pipeline, { id: string; update: PipelineUpdate }>({
      query: ({ id, update }) => ({
        url: `/pipelines/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: (_result, _error, { id }) => [{ type: 'Pipeline', id }, 'Pipeline'],
    }),

    deletePipeline: builder.mutation<void, string>({
      query: (id) => ({
        url: `/pipelines/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['Pipeline'],
    }),

    executePipeline: builder.mutation<PipelineExecutionResult, { id: string; events?: unknown[] }>({
      query: ({ id, events }) => ({
        url: `/pipelines/${id}/execute`,
        method: 'POST',
        body: { events },
      }),
    }),

    // SecOps Platform: Workflows
    listWorkflows: builder.query<WorkflowListResponse, WorkflowFilters>({
      query: (params) => ({
        url: '/workflows',
        params,
      }),
      providesTags: ['Workflow'],
    }),

    getWorkflow: builder.query<WorkflowDetailResponse, string>({
      query: (id) => `/workflows/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'Workflow', id }],
    }),

    getWorkflowNodeTypes: builder.query<WorkflowNodeTypeInfo[], void>({
      query: () => '/workflows/node-types',
    }),

    createWorkflow: builder.mutation<WorkflowResponse, WorkflowCreate>({
      query: (workflow) => ({
        url: '/workflows',
        method: 'POST',
        body: workflow,
      }),
      invalidatesTags: ['Workflow'],
    }),

    updateWorkflow: builder.mutation<WorkflowDetailResponse, { id: string; update: WorkflowUpdate }>({
      query: ({ id, update }) => ({
        url: `/workflows/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: (_result, _error, { id }) => [{ type: 'Workflow', id }, 'Workflow'],
    }),

    deleteWorkflow: builder.mutation<void, string>({
      query: (id) => ({
        url: `/workflows/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['Workflow'],
    }),

    executeWorkflow: builder.mutation<WorkflowExecutionResponse, { workflowId: string; trigger_data?: Record<string, unknown> }>({
      query: ({ workflowId, trigger_data }) => ({
        url: `/workflows/${workflowId}/execute`,
        method: 'POST',
        body: { trigger_data },
      }),
      invalidatesTags: ['WorkflowExecution'],
    }),

    listWorkflowExecutions: builder.query<WorkflowExecutionListResponse, { workflowId: string; status?: string; page?: number; page_size?: number }>({
      query: ({ workflowId, ...params }) => ({
        url: `/workflows/${workflowId}/executions`,
        params,
      }),
      providesTags: ['WorkflowExecution'],
    }),

    getWorkflowExecution: builder.query<WorkflowExecutionDetailResponse, string>({
      query: (id) => `/workflows/executions/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'WorkflowExecution', id }],
    }),

    // ==================== Feature 2: Stale Rule Detection ====================
    listRuleHealth: builder.query<RuleHealthListResponse, { isStale?: boolean; severity?: string; minHealthScore?: number; page?: number; pageSize?: number }>({
      query: (params) => ({
        url: '/rules/health',
        params: {
          is_stale: params.isStale,
          severity: params.severity,
          min_health_score: params.minHealthScore,
          page: params.page,
          page_size: params.pageSize,
        },
      }),
      providesTags: ['RuleHealth'],
    }),

    listStaleRules: builder.query<RuleHealthListResponse, { page?: number; pageSize?: number }>({
      query: (params) => ({
        url: '/rules/health/stale',
        params: { page: params.page, page_size: params.pageSize },
      }),
      providesTags: ['RuleHealth'],
    }),

    getRuleHealthStats: builder.query<RuleHealthStats, void>({
      query: () => '/rules/health/stats',
      providesTags: ['RuleHealth'],
    }),

    refreshRuleHealth: builder.mutation<{ status: string; message: string }, void>({
      query: () => ({
        url: '/rules/health/refresh',
        method: 'POST',
      }),
      invalidatesTags: ['RuleHealth'],
    }),

    // ==================== Feature 3: Auto-Triage Suggestions ====================
    getTriageSuggestion: builder.query<TriageSuggestionResponse, { alertId: string; forceRefresh?: boolean }>({
      query: ({ alertId, forceRefresh }) => ({
        url: `/triage/suggest/${alertId}`,
        params: { force_refresh: forceRefresh },
      }),
      providesTags: ['TriageSuggestion'],
    }),

    submitTriageFeedback: builder.mutation<{ status: string }, { suggestionId: string; wasAccepted: boolean; feedbackComment?: string }>({
      query: ({ suggestionId, wasAccepted, feedbackComment }) => ({
        url: '/triage/feedback',
        method: 'POST',
        body: { suggestion_id: suggestionId, was_accepted: wasAccepted, feedback_comment: feedbackComment },
      }),
      invalidatesTags: ['TriageSuggestion'],
    }),

    listAssetCriticality: builder.query<AssetCriticalityResponse[], { matchType?: string; isActive?: boolean }>({
      query: (params) => ({
        url: '/triage/assets/criticality',
        params: { match_type: params.matchType, is_active: params.isActive },
      }),
      providesTags: ['AssetCriticality'],
    }),

    createAssetCriticality: builder.mutation<AssetCriticalityResponse, AssetCriticalityCreate>({
      query: (data) => ({
        url: '/triage/assets/criticality',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['AssetCriticality'],
    }),

    updateAssetCriticality: builder.mutation<AssetCriticalityResponse, { id: string; update: Partial<AssetCriticalityCreate> }>({
      query: ({ id, update }) => ({
        url: `/triage/assets/criticality/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: ['AssetCriticality'],
    }),

    deleteAssetCriticality: builder.mutation<void, string>({
      query: (id) => ({
        url: `/triage/assets/criticality/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['AssetCriticality'],
    }),

    // ==================== Feature 4: Natural Language Queries ====================
    executeNaturalQuery: builder.mutation<NLQueryResponse, { query: string; execute?: boolean }>({
      query: (data) => ({
        url: '/queries/natural',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['NLQuery'],
    }),

    getNLQueryHistory: builder.query<NLQueryHistoryResponse[], { limit?: number }>({
      query: ({ limit = 20 }) => ({
        url: '/queries/natural/history',
        params: { limit },
      }),
      providesTags: ['NLQuery'],
    }),

    submitNLQueryFeedback: builder.mutation<{ status: string }, { queryId: string; wasHelpful: boolean; feedbackComment?: string }>({
      query: ({ queryId, wasHelpful, feedbackComment }) => ({
        url: '/queries/natural/feedback',
        method: 'POST',
        body: { query_id: queryId, was_helpful: wasHelpful, feedback_comment: feedbackComment },
      }),
      invalidatesTags: ['NLQuery'],
    }),

    getNLQueryExamples: builder.query<{ examples: Array<{ nl: string; sql: string }>; tips: string[] }, void>({
      query: () => '/queries/natural/examples',
    }),

    // ==================== Feature 5: AI Alert Clustering ====================
    listAlertClusters: builder.query<AlertClusterListResponse, { status?: string; severity?: string; page?: number; pageSize?: number }>({
      query: (params) => ({
        url: '/alert-clusters',
        params: { status: params.status, severity: params.severity, page: params.page, page_size: params.pageSize },
      }),
      providesTags: ['AlertCluster'],
    }),

    getAlertCluster: builder.query<AlertClusterResponse, string>({
      query: (id) => `/alert-clusters/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'AlertCluster', id }],
    }),

    getClusterAlerts: builder.query<ClusterMemberResponse[], string>({
      query: (clusterId) => `/alert-clusters/${clusterId}/alerts`,
      providesTags: ['AlertCluster'],
    }),

    updateAlertCluster: builder.mutation<AlertClusterResponse, { id: string; status?: string; assignee?: string }>({
      query: ({ id, ...update }) => ({
        url: `/alert-clusters/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: (_result, _error, { id }) => [{ type: 'AlertCluster', id }, 'AlertCluster'],
    }),

    generateClusters: builder.mutation<{ status: string; clusters_created: number }, { timeWindowHours?: number; minClusterSize?: number; clusterBy?: string[] }>({
      query: (data) => ({
        url: '/alert-clusters/generate',
        method: 'POST',
        body: { time_window_hours: data.timeWindowHours, min_cluster_size: data.minClusterSize, cluster_by: data.clusterBy },
      }),
      invalidatesTags: ['AlertCluster'],
    }),

    mergeClusters: builder.mutation<{ status: string; clusters_merged: number }, { targetClusterId: string; sourceClusterIds: string[] }>({
      query: ({ targetClusterId, sourceClusterIds }) => ({
        url: `/alert-clusters/${targetClusterId}/merge`,
        method: 'POST',
        body: { source_cluster_ids: sourceClusterIds },
      }),
      invalidatesTags: ['AlertCluster'],
    }),

    deleteAlertCluster: builder.mutation<void, string>({
      query: (id) => ({
        url: `/alert-clusters/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['AlertCluster'],
    }),

    bulkDeleteAlertClusters: builder.mutation<{ status: string; deleted_count: number }, { clusterIds: string[] }>({
      query: (data) => ({
        url: '/alert-clusters/bulk-delete',
        method: 'POST',
        body: { cluster_ids: data.clusterIds },
      }),
      invalidatesTags: ['AlertCluster'],
    }),

    askYourData: builder.mutation<{ answer: string; sql: string; results: NLQueryResultRow[]; provider: string; model: string }, { query: string; provider?: string }>({
      query: (data) => ({
        url: '/ai/ask',
        method: 'POST',
        body: data,
      }),
    }),

    // ==================== Feature 6: AI Playbook Generation ====================
    listPlaybookTemplates: builder.query<PlaybookTemplateListResponse, { isApproved?: boolean; minConfidence?: number; page?: number; pageSize?: number }>({
      query: (params) => ({
        url: '/playbooks/templates',
        params: { is_approved: params.isApproved, min_confidence: params.minConfidence, page: params.page, page_size: params.pageSize },
      }),
      providesTags: ['PlaybookTemplate'],
    }),

    getPlaybookTemplate: builder.query<PlaybookTemplateResponse, string>({
      query: (id) => `/playbooks/templates/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'PlaybookTemplate', id }],
    }),

    generatePlaybooks: builder.mutation<{ status: string; templates_generated: number }, { minIncidents?: number; severityFilter?: string[]; timeRangeDays?: number }>({
      query: (data) => ({
        url: '/playbooks/generate',
        method: 'POST',
        body: { min_incidents: data.minIncidents, severity_filter: data.severityFilter, time_range_days: data.timeRangeDays },
      }),
      invalidatesTags: ['PlaybookTemplate'],
    }),

    approvePlaybookTemplate: builder.mutation<{ status: string; playbook_id?: string }, { templateId: string; convertToPlaybook?: boolean }>({
      query: ({ templateId, convertToPlaybook }) => ({
        url: `/playbooks/templates/${templateId}/approve`,
        method: 'POST',
        body: { convert_to_playbook: convertToPlaybook },
      }),
      invalidatesTags: ['PlaybookTemplate'],
    }),

    getPlaybookSuggestions: builder.query<SuggestedPlaybookResponse[], { alertId?: string; ruleId?: string; severity?: string }>({
      query: (params) => ({
        url: '/playbooks/suggestions',
        params: { alert_id: params.alertId, rule_id: params.ruleId, severity: params.severity },
      }),
      providesTags: ['PlaybookTemplate'],
    }),

    // ==================== Feature 7: Escalation Policies ====================
    listEscalationPolicies: builder.query<EscalationPolicyResponse[], { isActive?: boolean }>({
      query: (params) => ({
        url: '/escalation-policies',
        params: { is_active: params.isActive },
      }),
      providesTags: ['EscalationPolicy'],
    }),

    getEscalationPolicy: builder.query<EscalationPolicyResponse, string>({
      query: (id) => `/escalation-policies/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'EscalationPolicy', id }],
    }),

    createEscalationPolicy: builder.mutation<EscalationPolicyResponse, EscalationPolicyCreate>({
      query: (data) => ({
        url: '/escalation-policies',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['EscalationPolicy'],
    }),

    updateEscalationPolicy: builder.mutation<EscalationPolicyResponse, { id: string; update: Partial<EscalationPolicyCreate> }>({
      query: ({ id, update }) => ({
        url: `/escalation-policies/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: (_result, _error, { id }) => [{ type: 'EscalationPolicy', id }, 'EscalationPolicy'],
    }),

    deleteEscalationPolicy: builder.mutation<void, string>({
      query: (id) => ({
        url: `/escalation-policies/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['EscalationPolicy'],
    }),

    addEscalationStep: builder.mutation<EscalationStepResponse, { policyId: string; step: EscalationStepCreate }>({
      query: ({ policyId, step }) => ({
        url: `/escalation-policies/${policyId}/steps`,
        method: 'POST',
        body: step,
      }),
      invalidatesTags: ['EscalationPolicy'],
    }),

    listActiveEscalations: builder.query<AlertEscalationResponse[], void>({
      query: () => '/escalation-policies/active',
      providesTags: ['EscalationPolicy'],
    }),

    acknowledgeAlertEscalation: builder.mutation<{ status: string; alert_id: string }, string>({
      query: (alertId) => ({
        url: `/escalation-policies/alerts/${alertId}/acknowledge`,
        method: 'POST',
      }),
      invalidatesTags: ['EscalationPolicy', 'Alert'],
    }),

    getAlertEscalation: builder.query<AlertEscalationResponse | null, string>({
      query: (alertId) => `/escalation-policies/alerts/${alertId}/escalation`,
      providesTags: ['EscalationPolicy'],
    }),

    // ==================== Feature 8: On-Call Scheduling ====================
    listOnCallSchedules: builder.query<OnCallScheduleResponse[], { isActive?: boolean }>({
      query: (params) => ({
        url: '/oncall/schedules',
        params: { is_active: params.isActive },
      }),
      providesTags: ['OnCallSchedule'],
    }),

    getOnCallSchedule: builder.query<OnCallScheduleResponse, string>({
      query: (id) => `/oncall/schedules/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'OnCallSchedule', id }],
    }),

    createOnCallSchedule: builder.mutation<OnCallScheduleResponse, OnCallScheduleCreate>({
      query: (data) => ({
        url: '/oncall/schedules',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['OnCallSchedule'],
    }),

    updateOnCallSchedule: builder.mutation<OnCallScheduleResponse, { id: string; update: Partial<OnCallScheduleCreate> }>({
      query: ({ id, update }) => ({
        url: `/oncall/schedules/${id}`,
        method: 'PATCH',
        body: update,
      }),
      invalidatesTags: (_result, _error, { id }) => [{ type: 'OnCallSchedule', id }, 'OnCallSchedule'],
    }),

    deleteOnCallSchedule: builder.mutation<void, string>({
      query: (id) => ({
        url: `/oncall/schedules/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['OnCallSchedule'],
    }),

    getCurrentOnCall: builder.query<CurrentOnCallResponse[], void>({
      query: () => '/oncall/current',
      providesTags: ['OnCallSchedule'],
    }),

    createOnCallOverride: builder.mutation<OnCallOverrideResponse, OnCallOverrideCreate>({
      query: (data) => ({
        url: '/oncall/override',
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['OnCallSchedule'],
    }),

    getOnCallCalendar: builder.query<OnCallCalendarEvent[], { scheduleId?: string; startDate: string; endDate: string }>({
      query: (params) => ({
        url: '/oncall/calendar',
        params: { schedule_id: params.scheduleId, start_date: params.startDate, end_date: params.endDate },
      }),
      providesTags: ['OnCallSchedule'],
    }),

    // ==================== Feature 9: Trend Analysis ====================
    getTrends: builder.query<TrendResponse, { bucketType?: string; days?: number }>({
      query: (params) => ({
        url: '/analytics/trends',
        params: { bucket_type: params.bucketType, days: params.days },
      }),
      providesTags: ['TrendAnalytics'],
    }),

    getForecast: builder.query<ForecastResponse, { forecastDays?: number }>({
      query: (params) => ({
        url: '/analytics/forecast',
        params: { forecast_days: params.forecastDays },
      }),
      providesTags: ['TrendAnalytics'],
    }),

    listAnomalies: builder.query<AnomalyResponse[], { acknowledged?: boolean; severity?: string; days?: number }>({
      query: (params) => ({
        url: '/analytics/anomalies',
        params,
      }),
      providesTags: ['Anomaly'],
    }),

    acknowledgeAnomaly: builder.mutation<{ status: string }, string>({
      query: (anomalyId) => ({
        url: `/analytics/anomalies/${anomalyId}/acknowledge`,
        method: 'POST',
      }),
      invalidatesTags: ['Anomaly'],
    }),

    triggerAnomalyDetection: builder.mutation<{ status: string; anomalies_detected: number }, void>({
      query: () => ({
        url: '/analytics/anomalies/detect',
        method: 'POST',
      }),
      invalidatesTags: ['Anomaly'],
    }),

    getCoverageAnalysis: builder.query<CoverageGapResponse[], void>({
      query: () => '/analytics/coverage',
      providesTags: ['TrendAnalytics'],
    }),

    getCoverageHeatmap: builder.query<CoverageHeatmapResponse, { days?: number }>({
      query: (params) => ({
        url: '/analytics/coverage/heatmap',
        params,
      }),
      providesTags: ['TrendAnalytics'],
    }),

    // ==================== Compliance Dashboard ====================

    listComplianceFrameworks: builder.query<ComplianceFrameworkListResponse, ComplianceFrameworkFilters>({
      query: (params) => ({
        url: '/compliance/frameworks',
        params,
      }),
      providesTags: ['ComplianceFramework'],
    }),

    getComplianceFramework: builder.query<ComplianceFramework, string>({
      query: (id) => `/compliance/frameworks/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'ComplianceFramework', id }],
    }),

    createComplianceFramework: builder.mutation<ComplianceFramework, CreateComplianceFrameworkRequest>({
      query: (body) => ({
        url: '/compliance/frameworks',
        method: 'POST',
        body,
      }),
      invalidatesTags: ['ComplianceFramework'],
    }),

    updateComplianceFramework: builder.mutation<ComplianceFramework, { id: string; data: UpdateComplianceFrameworkRequest }>({
      query: ({ id, data }) => ({
        url: `/compliance/frameworks/${id}`,
        method: 'PATCH',
        body: data,
      }),
      invalidatesTags: (_result, _error, { id }) => [{ type: 'ComplianceFramework', id }, 'ComplianceFramework'],
    }),

    deleteComplianceFramework: builder.mutation<void, string>({
      query: (id) => ({
        url: `/compliance/frameworks/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['ComplianceFramework'],
    }),

    listComplianceControls: builder.query<ComplianceControlListResponse, { frameworkId: string; status?: string; search?: string; page?: number; pageSize?: number }>({
      query: ({ frameworkId, ...params }) => ({
        url: `/compliance/frameworks/${frameworkId}/controls`,
        params,
      }),
      providesTags: ['ComplianceControl'],
    }),

    updateComplianceControl: builder.mutation<ComplianceControl, { id: string; data: UpdateComplianceControlRequest }>({
      query: ({ id, data }) => ({
        url: `/compliance/controls/${id}`,
        method: 'PATCH',
        body: data,
      }),
      invalidatesTags: ['ComplianceControl', 'ComplianceFramework'],
    }),

    getComplianceDashboardSummary: builder.query<ComplianceDashboardSummary, void>({
      query: () => '/compliance/dashboard/summary',
      providesTags: ['ComplianceFramework', 'ComplianceControl'],
    }),

    createComplianceAssessment: builder.mutation<ComplianceAssessment, { frameworkId: string; data: CreateAssessmentRequest }>({
      query: ({ frameworkId, data }) => ({
        url: `/compliance/frameworks/${frameworkId}/assessments`,
        method: 'POST',
        body: data,
      }),
      invalidatesTags: ['ComplianceFramework', 'ComplianceAssessment'],
    }),

    listComplianceAssessments: builder.query<ComplianceAssessment[], string>({
      query: (frameworkId) => `/compliance/frameworks/${frameworkId}/assessments`,
      providesTags: ['ComplianceAssessment'],
    }),

    exportComplianceReport: builder.mutation<Blob, ExportComplianceReportRequest>({
      query: (body) => ({
        url: '/compliance/reports/export',
        method: 'POST',
        body,
        responseHandler: (response) => response.blob(),
      }),
    }),

    // ==================== Executive Summary ====================

    getExecutiveMetrics: builder.query<ExecutiveMetrics, { days?: number; endDate?: string }>({
      query: (params) => ({
        url: '/executive/metrics',
        params,
      }),
      providesTags: ['ExecutiveMetrics'],
    }),

    getTopRiskAreas: builder.query<RiskAreasResponse, { days?: number; limit?: number }>({
      query: (params) => ({
        url: '/executive/risk-areas',
        params,
      }),
      providesTags: ['ExecutiveMetrics'],
    }),

    getTeamPerformance: builder.query<TeamPerformanceResponse, { days?: number }>({
      query: (params) => ({
        url: '/executive/team-performance',
        params,
      }),
      providesTags: ['ExecutiveMetrics'],
    }),

    getSLACompliance: builder.query<SLAComplianceResponse, { days?: number }>({
      query: (params) => ({
        url: '/executive/sla-compliance',
        params,
      }),
      providesTags: ['ExecutiveMetrics'],
    }),

    exportExecutiveReport: builder.mutation<ExportReportResponse, ExportExecutiveReportRequest>({
      query: (body) => ({
        url: '/executive/export',
        method: 'POST',
        body,
      }),
    }),

    // ==================== Threat Hunting ====================

    generateThreatHypothesis: builder.mutation<GeneratedHypothesis, GenerateHypothesisRequest>({
      query: (body) => ({
        url: '/threat-hunting/generate-hypothesis',
        method: 'POST',
        body,
      }),
    }),

    listThreatHunts: builder.query<ThreatHuntListResponse, ThreatHuntFilters>({
      query: (params) => ({
        url: '/threat-hunting/hunts',
        params,
      }),
      providesTags: ['ThreatHunt'],
    }),

    getThreatHunt: builder.query<ThreatHunt, string>({
      query: (id) => `/threat-hunting/hunts/${id}`,
      providesTags: (_result, _error, id) => [{ type: 'ThreatHunt', id }],
    }),

    createThreatHunt: builder.mutation<ThreatHunt, CreateThreatHuntRequest>({
      query: (body) => ({
        url: '/threat-hunting/hunts',
        method: 'POST',
        body,
      }),
      invalidatesTags: ['ThreatHunt'],
    }),

    updateThreatHunt: builder.mutation<ThreatHunt, { id: string; data: UpdateThreatHuntRequest }>({
      query: ({ id, data }) => ({
        url: `/threat-hunting/hunts/${id}`,
        method: 'PATCH',
        body: data,
      }),
      invalidatesTags: (_result, _error, { id }) => [{ type: 'ThreatHunt', id }, 'ThreatHunt'],
    }),

    deleteThreatHunt: builder.mutation<void, string>({
      query: (id) => ({
        url: `/threat-hunting/hunts/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['ThreatHunt'],
    }),

    addHuntQuery: builder.mutation<HuntQuery, { huntId: string; data: CreateHuntQueryRequest }>({
      query: ({ huntId, data }) => ({
        url: `/threat-hunting/hunts/${huntId}/queries`,
        method: 'POST',
        body: data,
      }),
      invalidatesTags: (_result, _error, { huntId }) => [{ type: 'ThreatHunt', id: huntId }],
    }),

    executeHuntQuery: builder.mutation<HuntResult, { huntId: string; queryId: string; data?: ExecuteQueryRequest }>({
      query: ({ huntId, queryId, data }) => ({
        url: `/threat-hunting/hunts/${huntId}/queries/${queryId}/execute`,
        method: 'POST',
        body: data || {},
      }),
      invalidatesTags: (_result, _error, { huntId }) => [{ type: 'ThreatHunt', id: huntId }, 'HuntResult'],
    }),

    getHuntResults: builder.query<HuntResult[], { huntId: string; status?: string }>({
      query: ({ huntId, ...params }) => ({
        url: `/threat-hunting/hunts/${huntId}/results`,
        params,
      }),
      providesTags: ['HuntResult'],
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

export interface SeverityBreakdown {
  INFO: number
  LOW: number
  MEDIUM: number
  HIGH: number
  CRITICAL: number
}

export interface AnalyticsResponse {
  totalAlerts: number
  bySeverity: SeverityBreakdown
  byStatus: {
    OPEN: number
    TRIAGED: number
    CLOSED: number
    RESOLVED: number
  }
  byDay: Record<string, number>
  byDaySeverity: Record<string, SeverityBreakdown>
  topRules: { name: string; count: number }[]
}

// Bulk Update Types
export interface BulkUpdateRequest {
  alert_ids: string[]
  action: string  // acknowledge, resolve, close, set_severity, assign
  value?: string  // used for set_severity (critical, high, etc.) or assign (user_id)
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

// User Account Types (actual user accounts)
export interface UserAccountResponse {
  id: string
  email: string
  name: string | null
  role: 'admin' | 'analyst' | 'viewer'
  is_active: boolean
  sso_provider: string | null
  created_at: string
  last_login_at: string | null
}

export interface UserListResponse {
  items: UserAccountResponse[]
  total: number
  page: number
  page_size: number
}

export interface UserListFilters {
  page?: number
  page_size?: number
  search?: string
  role?: string
  is_active?: boolean
}

// User Role Types (role pre-assignments)
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

// Case Types
export type CaseStatus = 'open' | 'in_progress' | 'pending' | 'resolved' | 'closed'
export type CasePriority = 'low' | 'medium' | 'high' | 'critical'
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

export interface AlertTechnique {
  technique_id: string
  technique_name: string
  alert_count: number
  rule_count: number
  severities: Record<string, number>
}

export interface AlertTacticCoverage {
  tactic: string
  label: string
  alert_count: number
  technique_count: number
  rule_count: number
  techniques: AlertTechnique[]
}

export interface TopTechnique {
  technique_id: string
  alert_count: number
  rule_count: number
  rules: string[]
  severities: Record<string, number>
}

export interface MitreAlertCoverageResponse {
  period_days: number
  total_alerts_with_mitre: number
  total_techniques_detected: number
  total_tactics_detected: number
  by_tactic: AlertTacticCoverage[]
  top_techniques: TopTechnique[]
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

// Phase 5: IOC Types
export type IOCType = 'ip_address' | 'domain' | 'url' | 'file_hash_md5' | 'file_hash_sha1' | 'file_hash_sha256' | 'email'
export type IOCSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface IOCResponse {
  id: string
  ioc_type: IOCType
  value: string
  severity: IOCSeverity
  source: string
  feed_id: string | null
  description: string | null
  tags: string[]
  first_seen: string
  last_seen: string
  is_active: boolean
  expires_at: string | null
  created_by: string
  created_at: string
  updated_at: string
}

export interface IOCCreate {
  ioc_type: IOCType
  value: string
  severity?: IOCSeverity
  description?: string
  tags?: string[]
  expires_at?: string
}

export interface IOCListResponse {
  items: IOCResponse[]
  total: number
  page: number
  page_size: number
}

export interface IOCStatsResponse {
  total: number
  active: number
  by_type: Record<string, number>
  by_severity: Record<string, number>
}

// Phase 5: Threat Feed Types
export type FeedType = 'otx' | 'abusech_feodo' | 'abusech_urlhaus' | 'custom_csv' | 'custom_stix'
export type FeedStatus = 'active' | 'paused' | 'error'

export interface FeedResponse {
  id: string
  name: string
  url: string
  feed_type: FeedType
  status: FeedStatus
  update_interval_minutes: number
  last_sync_at: string | null
  next_sync_at: string | null
  ioc_count: number
  error_message: string | null
  created_by: string
  created_at: string
  updated_at: string
}

export interface FeedCreate {
  name: string
  url: string
  feed_type: FeedType
  update_interval_minutes?: number
}

export interface SyncLogResponse {
  id: string
  feed_id: string
  status: string
  iocs_added: number
  iocs_updated: number
  duration_ms: number
  error: string | null
  synced_at: string
}

// Phase 5: AI Summarization Types
export interface SummaryResponse {
  summary: string
  model: string
  provider: string
  cached: boolean
  generated_at: string
  input_tokens: number
  output_tokens: number
}

export interface OrganizationAPIKey {
  provider: string
  configured: boolean
  model?: string
  last_used_at?: string
  is_active: boolean
}

export interface AISettingsResponse {
  default_provider: string
  openai: { configured: boolean; model: string }
  anthropic: { configured: boolean; model: string }
  organization_keys?: OrganizationAPIKey[]
}

export interface SaveAPIKeyRequest {
  provider: string
  api_key: string
  model?: string
}

export interface SaveAPIKeyResponse {
  provider: string
  configured: boolean
  model?: string
  is_active: boolean
}

// Phase 5: Unified Threat Intel Types
export interface UnifiedThreatIntelResponse {
  indicator: string
  indicator_type: string
  providers: Record<string, { data?: Record<string, unknown>; error?: string; available: boolean }>
  aggregate_risk_level: string
  aggregate_score: number
  total_providers_checked: number
  providers_with_data: number
}

// SecOps Platform: Connector Types
export type ConnectorCategory = 'data_source' | 'action'
export type ConnectorStatus = 'connected' | 'error' | 'disabled' | 'pending'
export interface ConnectorResponse {
  id: string
  name: string
  description: string | null
  category: ConnectorCategory
  connector_type: string
  status: ConnectorStatus
  config: Record<string, unknown>
  last_health_check: string | null
  last_error: string | null
  sync_enabled: boolean
  sync_interval_minutes: number
  last_sync_at: string | null
  created_by: string
  created_at: string
  updated_at: string
}

export interface ConnectorCreate {
  name: string
  description?: string
  category: ConnectorCategory
  connector_type: string
  credentials?: Record<string, unknown>
  config?: Record<string, unknown>
  sync_enabled?: boolean
  sync_interval_minutes?: number
}

export interface ConnectorUpdate {
  name?: string
  description?: string
  credentials?: Record<string, unknown>
  config?: Record<string, unknown>
  sync_enabled?: boolean
  sync_interval_minutes?: number
}

export interface ConnectorFilters {
  category?: ConnectorCategory
  status?: ConnectorStatus
  connector_type?: string
}

export interface ConnectorListResponse {
  items: ConnectorResponse[]
  total: number
}

export interface ConnectorTypeInfo {
  type: string
  category: ConnectorCategory
  name: string
  description: string
  icon: string
  config_schema: Record<string, unknown>
  credential_schema: Record<string, unknown>
}

export interface ConnectionTestResult {
  success: boolean
  message: string
  details?: Record<string, unknown>
}

export interface ConnectorSyncResult {
  connector_id: string
  alerts_fetched: number
  alerts_new: number
  alerts_updated: number
  sync_duration_ms: number
  last_sync_at: string
}

export interface NormalizedAlertResponse {
  id: string
  connector_id: string
  source_type: string
  external_id: string
  title: string
  description: string | null
  severity: string
  status: string
  created_at_source: string
  updated_at_source: string | null
  rule_id: string | null
  rule_name: string | null
  tags: string[]
  mitre_tactics: string[]
  mitre_techniques: string[]
  raw_data: Record<string, unknown>
  ingested_at: string
}

export interface NormalizedAlertListResponse {
  items: NormalizedAlertResponse[]
  total: number
  page: number
  page_size: number
  severity_counts?: Record<string, number>
}

export interface UnifiedAlertFilters {
  source_type?: string
  severity?: string
  status?: string
  connector_id?: string
  start_date?: string
  end_date?: string
  page?: number
  page_size?: number
  exclude_resolved?: boolean
}

// SecOps Platform: Workflow Types
export type WorkflowStatus = 'draft' | 'active' | 'inactive'
export type WorkflowExecutionStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
export type WorkflowNodeType =
  | 'trigger_alert'
  | 'trigger_schedule'
  | 'trigger_webhook'
  | 'trigger_manual'
  | 'http_request'
  | 'connector_action'
  | 'condition'
  | 'transform'
  | 'delay'
  | 'loop'
  | 'set_variable'

export interface WorkflowResponse {
  id: string
  name: string
  description: string | null
  status: WorkflowStatus
  trigger_type: string | null
  trigger_config: Record<string, unknown>
  version: number
  created_by: string
  created_at: string
  updated_at: string
}

export interface WorkflowNodeResponse {
  id: string
  workflow_id: string
  node_key: string
  node_type: WorkflowNodeType
  label: string
  position_x: number
  position_y: number
  config: Record<string, unknown>
  on_error: string
  error_handler_node: string | null
  timeout_seconds: number
}

export interface WorkflowEdgeResponse {
  id: string
  workflow_id: string
  source_node_key: string
  source_handle: string
  target_node_key: string
  condition: string | null
}

export interface WorkflowDetailResponse extends WorkflowResponse {
  nodes: WorkflowNodeResponse[]
  edges: WorkflowEdgeResponse[]
  viewport: { x: number; y: number; zoom: number }
}

export interface WorkflowCreate {
  name: string
  description?: string
  status?: WorkflowStatus
  trigger_type?: string
  trigger_config?: Record<string, unknown>
  nodes?: WorkflowNodeCreate[]
  edges?: WorkflowEdgeCreate[]
  viewport?: { x: number; y: number; zoom: number }
}

export interface WorkflowNodeCreate {
  node_key: string
  node_type: WorkflowNodeType
  label: string
  position_x: number
  position_y: number
  config?: Record<string, unknown>
  on_error?: string
  error_handler_node?: string
  timeout_seconds?: number
}

export interface WorkflowEdgeCreate {
  source_node_key: string
  source_handle?: string
  target_node_key: string
  condition?: string
}

export interface WorkflowUpdate {
  name?: string
  description?: string
  status?: WorkflowStatus
  trigger_type?: string
  trigger_config?: Record<string, unknown>
  nodes?: WorkflowNodeCreate[]
  edges?: WorkflowEdgeCreate[]
  viewport?: { x: number; y: number; zoom: number }
}

export interface WorkflowFilters {
  status?: WorkflowStatus
  trigger_type?: string
  page?: number
  page_size?: number
}

export interface WorkflowListResponse {
  items: WorkflowResponse[]
  total: number
  page: number
  page_size: number
}

export interface WorkflowNodeTypeInfo {
  type: WorkflowNodeType
  category: string
  label: string
  description: string
  config_schema: Record<string, unknown>
  handles: {
    inputs: string[]
    outputs: string[]
  }
}

export interface WorkflowExecutionResponse {
  id: string
  workflow_id: string
  workflow_version: number
  status: WorkflowExecutionStatus
  trigger_data: Record<string, unknown>
  context: Record<string, unknown>
  variables: Record<string, unknown>
  started_at: string | null
  completed_at: string | null
  error_message: string | null
  triggered_by: string
  created_at: string
}

export interface WorkflowStepExecutionResponse {
  id: string
  execution_id: string
  node_key: string
  node_type: string
  status: string
  input_data: Record<string, unknown>
  output_data: Record<string, unknown>
  error_message: string | null
  started_at: string
  completed_at: string | null
  duration_ms: number | null
  loop_index: number | null
}

export interface WorkflowExecutionDetailResponse extends WorkflowExecutionResponse {
  steps: WorkflowStepExecutionResponse[]
}

export interface WorkflowExecutionListResponse {
  items: WorkflowExecutionResponse[]
  total: number
  page: number
  page_size: number
}

// Pipeline Types
export type PipelineStatus = 'active' | 'inactive' | 'draft' | 'error'
export type StageCategory = 'transform' | 'filter' | 'route'

export interface PipelineStage {
  id: string
  node_key: string
  stage_type: string
  label: string
  position_x: number
  position_y: number
  config: Record<string, unknown>
  enabled: boolean
}

export interface PipelineEdge {
  id: string
  source_node_key: string
  source_handle: string
  target_node_key: string
  target_handle?: string
  condition?: string
  label?: string
}

export interface PipelineMetrics {
  events_last_24h: number
  reduction_percentage: number
  avg_processing_ms: number
  error_rate: number
  last_execution?: string
}

export interface Pipeline {
  id: string
  name: string
  description?: string
  status: PipelineStatus
  source_connector_ids: string[]
  batch_size: number
  metrics?: PipelineMetrics
  created_at: string
  updated_at: string
}

export interface PipelineDetail extends Pipeline {
  stages: PipelineStage[]
  edges: PipelineEdge[]
  viewport?: { x: number; y: number; zoom: number }
}

export interface PipelineCreate {
  name: string
  description?: string
  stages?: Omit<PipelineStage, 'id'>[]
  edges?: Omit<PipelineEdge, 'id'>[]
  viewport?: { x: number; y: number; zoom: number }
}

export interface PipelineUpdate {
  name?: string
  description?: string
  status?: PipelineStatus
  stages?: Omit<PipelineStage, 'id'>[]
  edges?: Omit<PipelineEdge, 'id'>[]
  viewport?: { x: number; y: number; zoom: number }
}

export interface PipelineExecutionResult {
  execution_id: string
  status: string
  events_received: number
  events_output: number
  events_filtered: number
  duration_ms: number
}

export interface StageTypeMetadata {
  stage_type: string
  display_name: string
  category: StageCategory
  description: string
  config_schema: {
    properties?: Record<string, Record<string, unknown>>
    required?: string[]
  }
}

// ==================== Feature 2: Stale Rule Detection Types ====================
export interface RuleHealthResponse {
  id: string
  rule_id: string
  rule_name: string
  last_triggered_at: string | null
  trigger_count_7d: number
  trigger_count_30d: number
  trigger_count_90d: number
  is_stale: boolean
  health_score: number
  stale_reason: string | null
  is_enabled: boolean
  severity: string | null
  owner_email: string | null
  last_checked_at: string
}

export interface RuleHealthListResponse {
  rules: RuleHealthResponse[]
  total: number
  stale_count: number
}

export interface RuleHealthStats {
  total_rules: number
  healthy_rules: number
  stale_rules: number
  average_health_score: number
  rules_by_severity: Record<string, number>
}

// ==================== Feature 3: Auto-Triage Suggestions Types ====================
export interface TriageSuggestionResponse {
  id: string
  alert_id: string
  suggested_severity: string
  suggested_priority: string
  confidence_score: number
  reasoning: string
  contributing_factors: Array<{ factor: string; value: string; weight: number }>
  was_accepted: boolean | null
  created_at: string
}

export interface AssetCriticalityResponse {
  id: string
  name: string
  description: string | null
  match_type: string
  match_pattern: string
  criticality_level: number
  business_unit: string | null
  data_classification: string | null
  is_active: boolean
  created_by: string
  created_at: string
}

export interface AssetCriticalityCreate {
  name: string
  description?: string
  match_type: string
  match_pattern: string
  criticality_level: number
  business_unit?: string
  data_classification?: string
  is_active?: boolean
}

// ==================== Feature 4: Natural Language Queries Types ====================
export interface NLQueryResponse {
  id: string
  natural_query: string
  generated_sql: string
  explanation: string | null
  results: Record<string, unknown>[] | null
  row_count: number | null
  execution_time_ms: number | null
  error_message: string | null
}

export interface NLQueryResultRow {
  id: string
  title?: string
  severity?: string
  source_system?: string
}

export interface NLQueryHistoryResponse {
  id: string
  natural_query: string
  generated_sql: string
  explanation: string | null
  was_executed: boolean
  row_count: number | null
  was_helpful: boolean | null
  created_at: string
}

// ==================== Feature 5: AI Alert Clustering Types ====================
export interface AlertClusterResponse {
  id: string
  name: string
  summary: string
  severity: string
  status: string
  primary_rule_id: string | null
  cluster_type: string
  alert_count: number
  first_alert_at: string
  last_alert_at: string
  common_entities: Record<string, unknown>
  assignee: string | null
  created_at: string
}

export interface AlertClusterListResponse {
  clusters: AlertClusterResponse[]
  total: number
}

export interface ClusterMemberResponse {
  id: string
  cluster_id: string
  alert_id: string
  similarity_score: number
  added_at: string
}

// ==================== Feature 6: AI Playbook Generation Types ====================
export interface PlaybookTemplateResponse {
  id: string
  name: string
  description: string | null
  trigger_conditions: { severities?: string[]; rule_ids?: string[] } & Record<string, unknown>
  actions: Array<{ order: number; type: string; name: string; config: Record<string, unknown> }>
  confidence_score: number
  source_incident_count: number
  is_approved: boolean
  approved_by: string | null
  approved_at: string | null
  converted_playbook_id: string | null
  created_at: string
}

export interface PlaybookTemplateListResponse {
  templates: PlaybookTemplateResponse[]
  total: number
}

export interface SuggestedPlaybookResponse {
  template_id: string
  name: string
  description: string | null
  match_score: number
  trigger_conditions: Record<string, unknown>
  suggested_actions: Array<{ order: number; type: string; name: string; config: Record<string, unknown> }>
}

// ==================== Feature 7: Escalation Policies Types ====================
export interface EscalationStepResponse {
  id: string
  step_order: number
  delay_minutes: number
  notification_type: string
  targets: string[]
  use_oncall_schedule: boolean
  oncall_schedule_id: string | null
}

export interface EscalationPolicyResponse {
  id: string
  name: string
  description: string | null
  severity_filter: string[]
  rule_filter: string[]
  is_active: boolean
  steps: EscalationStepResponse[]
  call_message_template: string | null
  sms_message_template: string | null
  created_by: string
  created_at: string
}

export interface EscalationStepCreate {
  step_order: number
  delay_minutes: number
  notification_type: string
  targets: string[]
  use_oncall_schedule?: boolean
  oncall_schedule_id?: string
}

export interface EscalationPolicyCreate {
  name: string
  description?: string
  severity_filter?: string[]
  rule_filter?: string[]
  is_active?: boolean
  steps?: EscalationStepCreate[]
  call_message_template?: string
  sms_message_template?: string
}

export interface AlertEscalationResponse {
  id: string
  alert_id: string
  policy_id: string
  status: string
  current_step: number
  started_at: string
  next_escalation_at: string | null
  acknowledged_at: string | null
  acknowledged_by: string | null
  notification_history: Array<{ step: number; type: string; sent_at: string; targets: string[] }>
}

// ==================== Feature 8: On-Call Scheduling Types ====================
export interface OnCallMemberResponse {
  id: string
  user_email: string
  user_name: string | null
  rotation_order: number
  role: string
  phone_number: string | null
  slack_user_id: string | null
}

export interface OnCallScheduleResponse {
  id: string
  name: string
  description: string | null
  timezone: string
  rotation_type: string
  handoff_time: string
  handoff_day: number | null
  rotation_length_days: number | null
  is_active: boolean
  members: OnCallMemberResponse[]
  created_by: string
  created_at: string
}

export interface OnCallMemberCreate {
  user_email: string
  user_name?: string
  rotation_order: number
  role?: string
  phone_number?: string
  slack_user_id?: string
}

export interface OnCallScheduleCreate {
  name: string
  description?: string
  timezone?: string
  rotation_type?: string
  handoff_time?: string
  handoff_day?: number
  rotation_length_days?: number
  is_active?: boolean
  members?: OnCallMemberCreate[]
}

export interface OnCallOverrideResponse {
  id: string
  schedule_id: string
  override_user_email: string
  original_user_email: string | null
  start_time: string
  end_time: string
  reason: string | null
  created_by: string
  created_at: string
}

export interface OnCallOverrideCreate {
  schedule_id: string
  override_user_email: string
  original_user_email?: string
  start_time: string
  end_time: string
  reason?: string
}

export interface CurrentOnCallResponse {
  schedule_id: string
  schedule_name: string
  primary: OnCallMemberResponse | null
  backup: OnCallMemberResponse | null
  is_override: boolean
  override_end: string | null
}

export interface OnCallCalendarEvent {
  date: string
  schedule_id: string
  schedule_name: string
  primary_email: string
  primary_name: string | null
  backup_email: string | null
  backup_name: string | null
}

// ==================== Feature 9: Trend Analysis Types ====================
export interface TrendDataPoint {
  timestamp: string
  total: number
  by_severity: Record<string, number>
  change_from_previous: number | null
}

export interface TrendResponse {
  bucket_type: string
  data_points: TrendDataPoint[]
  total_period: number
  average: number
  trend_direction: string
}

export interface ForecastResponse {
  forecast_period: string
  predicted_total: number
  confidence_interval: { lower: number; upper: number; confidence_level: string }
  prediction_method: string
  historical_average: number
}

export interface AnomalyResponse {
  id: string
  anomaly_type: string
  severity: string
  description: string
  detected_value: number
  expected_value: number
  deviation_percentage: number
  related_rule_ids: string[]
  time_range_start: string
  time_range_end: string
  is_acknowledged: boolean
  detected_at: string
}

export interface CoverageGapResponse {
  tactic: string
  tactic_name: string
  total_techniques: number
  covered_techniques: number
  coverage_percentage: number
  missing_techniques: Array<{ id: string; name: string }>
}

export interface CoverageHeatmapResponse {
  period_days: number
  heatmap: Record<string, { name: string; alert_count: number; techniques: Record<string, number> }>
  total_alerts_with_mitre: number
}

// ==================== Compliance Dashboard Types ====================

export interface ComplianceFramework {
  id: string
  name: string
  description: string | null
  version: string | null
  is_active: boolean
  total_controls: number
  implemented_controls: number
  coverage_percentage: number
  last_assessment_date: string | null
  next_assessment_date: string | null
  created_by: string
  created_at: string
  updated_at: string
}

export interface ComplianceControl {
  id: string
  framework_id: string
  control_id: string
  title: string
  description: string | null
  status: 'not_implemented' | 'partial' | 'implemented' | 'not_applicable'
  evidence: string | null
  evidence_links: string[]
  owner: string | null
  due_date: string | null
  last_reviewed_at: string | null
  reviewed_by: string | null
  notes: string | null
  created_at: string
  updated_at: string
}

export interface ComplianceAssessment {
  id: string
  framework_id: string
  assessment_date: string
  coverage_score: number
  total_controls: number
  implemented_count: number
  partial_count: number
  not_implemented_count: number
  notes: string | null
  assessor: string | null
  created_at: string
}

export interface ComplianceFrameworkFilters {
  is_active?: boolean
  search?: string
  page?: number
  page_size?: number
}

export interface ComplianceFrameworkListResponse {
  frameworks: ComplianceFramework[]
  total: number
  page: number
  page_size: number
}

export interface ComplianceControlListResponse {
  controls: ComplianceControl[]
  total: number
  page: number
  page_size: number
}

export interface CreateComplianceFrameworkRequest {
  name: string
  description?: string
  version?: string
}

export interface UpdateComplianceFrameworkRequest {
  name?: string
  description?: string
  version?: string
  is_active?: boolean
  next_assessment_date?: string
}

export interface UpdateComplianceControlRequest {
  status?: 'not_implemented' | 'partial' | 'implemented' | 'not_applicable'
  evidence?: string
  evidence_links?: string[]
  owner?: string
  due_date?: string
  notes?: string
}

export interface CreateAssessmentRequest {
  notes?: string
}

export interface ExportComplianceReportRequest {
  framework_id: string
  format: 'csv' | 'pdf'
  include_evidence?: boolean
}

export interface ComplianceDashboardSummary {
  total_frameworks: number
  active_frameworks: number
  total_controls: number
  implemented_controls: number
  partial_controls: number
  not_implemented_controls: number
  overall_coverage: number
  frameworks_by_coverage: { name: string; coverage: number }[]
  upcoming_assessments: { framework_id: string; framework_name: string; date: string }[]
}

// ==================== Executive Summary Types ====================

export interface MetricValue {
  // null when the backend cannot compute the metric (data_available=false).
  // Treat null as "not measured", never as zero.
  value: number | null
  previous_value: number | null
  change_percent: number | null
  trend: 'up' | 'down' | 'stable'
  data_available: boolean
}

export interface ExecutiveMetrics {
  total_alerts: MetricValue
  critical_incidents: MetricValue
  mttr_hours: MetricValue
  mtta_hours: MetricValue
  compliance_score: MetricValue
  open_incidents: MetricValue
  resolved_incidents: MetricValue
  false_positive_rate: MetricValue
  period_start: string
  period_end: string
}

export interface RiskArea {
  category: string
  description: string
  alert_count: number
  incident_count: number
  severity_score: number
  trend: 'up' | 'down' | 'stable'
  change_percent: number
  top_sources: string[]
  mitre_techniques: string[]
}

export interface RiskAreasResponse {
  risk_areas: RiskArea[]
  total_risk_score: number
  risk_trend: 'up' | 'down' | 'stable'
  period_start: string
  period_end: string
}

export interface TeamMemberPerformance {
  user_id: string
  username: string
  display_name: string
  alerts_handled: number
  incidents_resolved: number
  avg_resolution_hours: number
  escalation_rate: number
  false_positive_identifications: number
  accuracy_rate: number
}

export interface TeamPerformanceResponse {
  team_members: TeamMemberPerformance[]
  // null when per-user attribution data does not exist (data_available=false).
  team_avg_resolution_hours: number | null
  team_total_alerts_handled: number | null
  team_total_incidents_resolved: number | null
  data_available: boolean
  period_start: string
  period_end: string
}

export interface SLAMetric {
  sla_name: string
  target_hours: number
  actual_avg_hours: number
  compliance_rate: number
  breaches: number
  total_applicable: number
  trend: 'up' | 'down' | 'stable'
}

export interface SLAComplianceResponse {
  // may be empty when no SLA timing data exists
  sla_metrics: SLAMetric[]
  // null when SLA timing data cannot be computed (data_available=false).
  overall_compliance_rate: number | null
  total_breaches: number | null
  data_available: boolean
  period_start: string
  period_end: string
}

export interface ExportExecutiveReportRequest {
  start_date: string
  end_date: string
  include_metrics?: boolean
  include_risk_areas?: boolean
  include_team_performance?: boolean
  include_sla_compliance?: boolean
  format?: 'pdf' | 'csv'
}

export interface ExportReportResponse {
  format: string
  data?: Record<string, unknown>
  note?: string
}

// ==================== Threat Hunting Types ====================

export interface MitreTechnique {
  id: string
  name: string
  tactic: string
}

export interface GeneratedHypothesis {
  title: string
  hypothesis: string
  rationale: string
  mitre_techniques: MitreTechnique[]
  data_sources: string[]
  suggested_queries: { name: string; description: string; sql: string }[]
  indicators_to_look_for: string[]
  priority: 'low' | 'medium' | 'high' | 'critical'
  // "llm" when produced by the AI model; "fallback" when a keyword-matching
  // heuristic produced the result because the LLM call failed/was unavailable.
  generated_by: 'llm' | 'fallback'
}

export interface GenerateHypothesisRequest {
  description: string
  include_mitre?: boolean
  include_queries?: boolean
}

export interface HuntQuery {
  id: string
  hunt_id: string
  name: string
  description: string | null
  sql_query: string
  query_type: 'detection' | 'baseline' | 'enrichment'
  expected_results: string | null
  order_index: number
  created_at: string
  updated_at: string
}

export interface ThreatHunt {
  id: string
  title: string
  hypothesis: string
  description: string | null
  mitre_techniques: string[]
  data_sources: string[]
  status: 'draft' | 'in_progress' | 'completed' | 'cancelled'
  priority: 'low' | 'medium' | 'high' | 'critical'
  findings_count: number
  started_at: string | null
  completed_at: string | null
  created_by: string
  assigned_to: string | null
  tags: string[]
  queries: HuntQuery[]
  created_at: string
  updated_at: string
}

export interface ThreatHuntFilters {
  status?: string
  priority?: string
  assigned_to?: string
  search?: string
  page?: number
  page_size?: number
}

export interface ThreatHuntListResponse {
  hunts: ThreatHunt[]
  total: number
  page: number
  page_size: number
}

export interface CreateHuntQueryRequest {
  name: string
  description?: string
  sql_query: string
  query_type?: 'detection' | 'baseline' | 'enrichment'
  expected_results?: string
  order_index?: number
}

export interface CreateThreatHuntRequest {
  title: string
  hypothesis: string
  description?: string
  mitre_techniques?: string[]
  data_sources?: string[]
  priority?: 'low' | 'medium' | 'high' | 'critical'
  assigned_to?: string
  tags?: string[]
  queries?: CreateHuntQueryRequest[]
}

export interface UpdateThreatHuntRequest {
  title?: string
  hypothesis?: string
  description?: string
  mitre_techniques?: string[]
  data_sources?: string[]
  status?: 'draft' | 'in_progress' | 'completed' | 'cancelled'
  priority?: 'low' | 'medium' | 'high' | 'critical'
  assigned_to?: string
  tags?: string[]
}

export interface ExecuteQueryRequest {
  timeout_seconds?: number
  limit_results?: number
}

export interface HuntResult {
  id: string
  hunt_id: string
  query_id: string | null
  query_name: string | null
  status: 'pending' | 'running' | 'completed' | 'failed'
  results_count: number
  findings: Record<string, unknown>[]
  raw_results: Record<string, unknown> | null
  execution_time_ms: number | null
  error_message: string | null
  executed_at: string | null
  executed_by: string | null
  created_at: string
  // True when produced by the built-in simulation instead of a real
  // data-lake query execution. Simulated findings are not evidence.
  simulated: boolean
}

export const {
  useListAlertsQuery,
  useGetAlertQuery,
  useUpdateAlertMutation,
  useGetAlertEventsQuery,
  useAddAlertCommentMutation,
  useListRulesQuery,
  useExecuteQueryMutation,
  useGetAlertAnalyticsQuery,
  useBulkUpdateAlertsMutation,
  useListSavedQueriesQuery,
  useCreateSavedQueryMutation,
  useUpdateSavedQueryMutation,
  useDeleteSavedQueryMutation,
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
  useListUsersQuery,
  useGetUserQuery,
  useUpdateUserMutation,
  useDeleteUserMutation,
  useListAuditLogsQuery,
  useGetAuditActionsQuery,
  useGetAuditResourceTypesQuery,
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
  useListCasesQuery,
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
  useGetMitreAlertCoverageQuery,
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
  // Phase 5: IOC Management
  useListIOCsQuery,
  useGetIOCStatsQuery,
  useGetIOCTypesQuery,
  useCreateIOCMutation,
  useBulkImportIOCsMutation,
  useImportSTIXMutation,
  useUpdateIOCMutation,
  useDeleteIOCMutation,
  // Phase 5: Threat Feeds
  useListFeedsQuery,
  useGetFeedTypesQuery,
  useCreateFeedMutation,
  useUpdateFeedMutation,
  useDeleteFeedMutation,
  useSyncFeedMutation,
  useGetFeedLogsQuery,
  // Phase 5: AI Summarization
  useSummarizeAlertMutation,
  useSummarizeIncidentMutation,
  useGetAISettingsQuery,
  useTestAIConnectionMutation,
  // Organization API Key Management
  useSaveAPIKeyMutation,
  useDeleteAPIKeyMutation,
  useTestOrganizationAPIKeyMutation,
  useTestAPIKeyDirectMutation,
  // Phase 5: Enhanced Threat Intel
  useUnifiedThreatIntelLookupQuery,
  useGetThreatIntelSourcesQuery,
  // SecOps Platform: Connectors
  useListConnectorsQuery,
  useGetConnectorQuery,
  useGetConnectorTypesQuery,
  useCreateConnectorMutation,
  useUpdateConnectorMutation,
  useDeleteConnectorMutation,
  useTestConnectorMutation,
  useSyncConnectorMutation,
  useListUnifiedAlertsQuery,
  // SecOps Platform: Data Pipelines
  useListPipelinesQuery,
  useGetPipelineQuery,
  useListStageTypesQuery,
  useCreatePipelineMutation,
  useUpdatePipelineMutation,
  useDeletePipelineMutation,
  useExecutePipelineMutation,
  // SecOps Platform: Workflows
  useListWorkflowsQuery,
  useGetWorkflowQuery,
  useGetWorkflowNodeTypesQuery,
  useCreateWorkflowMutation,
  useUpdateWorkflowMutation,
  useDeleteWorkflowMutation,
  useExecuteWorkflowMutation,
  useListWorkflowExecutionsQuery,
  useGetWorkflowExecutionQuery,
  // Feature 2: Stale Rule Detection
  useListRuleHealthQuery,
  useListStaleRulesQuery,
  useGetRuleHealthStatsQuery,
  useRefreshRuleHealthMutation,
  // Feature 3: Auto-Triage Suggestions
  useGetTriageSuggestionQuery,
  useSubmitTriageFeedbackMutation,
  useListAssetCriticalityQuery,
  useCreateAssetCriticalityMutation,
  useUpdateAssetCriticalityMutation,
  useDeleteAssetCriticalityMutation,
  // Feature 4: Natural Language Queries
  useExecuteNaturalQueryMutation,
  useGetNLQueryHistoryQuery,
  useSubmitNLQueryFeedbackMutation,
  useGetNLQueryExamplesQuery,
  // Feature 5: AI Alert Clustering
  useListAlertClustersQuery,
  useGetAlertClusterQuery,
  useGetClusterAlertsQuery,
  useUpdateAlertClusterMutation,
  useGenerateClustersMutation,
  useMergeClustersMutation,
     useDeleteAlertClusterMutation,
     useBulkDeleteAlertClustersMutation,
   useAskYourDataMutation,
  
  // Feature 6: AI Playbook Generation
  useListPlaybookTemplatesQuery,
  useGetPlaybookTemplateQuery,
  useGeneratePlaybooksMutation,
  useApprovePlaybookTemplateMutation,
  useGetPlaybookSuggestionsQuery,
  // Feature 7: Escalation Policies
  useListEscalationPoliciesQuery,
  useGetEscalationPolicyQuery,
  useCreateEscalationPolicyMutation,
  useUpdateEscalationPolicyMutation,
  useDeleteEscalationPolicyMutation,
  useAddEscalationStepMutation,
  useListActiveEscalationsQuery,
  useAcknowledgeAlertEscalationMutation,
  useGetAlertEscalationQuery,
  // Feature 8: On-Call Scheduling
  useListOnCallSchedulesQuery,
  useGetOnCallScheduleQuery,
  useCreateOnCallScheduleMutation,
  useUpdateOnCallScheduleMutation,
  useDeleteOnCallScheduleMutation,
  useGetCurrentOnCallQuery,
  useCreateOnCallOverrideMutation,
  useGetOnCallCalendarQuery,
  // Feature 9: Trend Analysis
  useGetTrendsQuery,
  useGetForecastQuery,
  useListAnomaliesQuery,
  useAcknowledgeAnomalyMutation,
  useTriggerAnomalyDetectionMutation,
  useGetCoverageAnalysisQuery,
  useGetCoverageHeatmapQuery,
  // Compliance Dashboard
  useListComplianceFrameworksQuery,
  useGetComplianceFrameworkQuery,
  useCreateComplianceFrameworkMutation,
  useUpdateComplianceFrameworkMutation,
  useDeleteComplianceFrameworkMutation,
  useListComplianceControlsQuery,
  useUpdateComplianceControlMutation,
  useGetComplianceDashboardSummaryQuery,
  useCreateComplianceAssessmentMutation,
  useListComplianceAssessmentsQuery,
  useExportComplianceReportMutation,
  // Executive Summary
  useGetExecutiveMetricsQuery,
  useGetTopRiskAreasQuery,
  useGetTeamPerformanceQuery,
  useGetSLAComplianceQuery,
  useExportExecutiveReportMutation,
  // Threat Hunting
  useGenerateThreatHypothesisMutation,
  useListThreatHuntsQuery,
  useGetThreatHuntQuery,
  useCreateThreatHuntMutation,
  useUpdateThreatHuntMutation,
  useDeleteThreatHuntMutation,
  useAddHuntQueryMutation,
  useExecuteHuntQueryMutation,
  useGetHuntResultsQuery,
} = revopsApi

// Legacy alias for backwards compatibility
export const pantherApi = revopsApi
