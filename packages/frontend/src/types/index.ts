export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type AlertStatus = 'OPEN' | 'TRIAGED' | 'CLOSED' | 'RESOLVED'

export interface AlertSummary {
  id: string
  title: string
  severity: Severity
  status: AlertStatus
  detectionId: string
  createdAt: string
  eventCount?: number
}

export interface Alert extends AlertSummary {
  description: string | null
  logTypes?: string[]
  updatedAt: string | null
  firstEventAt?: string | null
  lastEventAt?: string | null
  assigneeId?: string | null
  assigneeName?: string | null
  runbook?: string | null
  reference?: string | null
  tags?: string[]
  // Connector alert fields
  detectionName?: string | null
  sourceType?: string | null
  connectorId?: string | null
  mitreTactics?: string[]
  mitreTechniques?: string[]
  rawData?: Record<string, unknown> | null
}

export interface AlertEvent {
  eventId: string
  logType: string
  eventTime: string | null
  data: Record<string, unknown>
}

export interface AlertComment {
  id: string
  body: string
  author: string
  createdAt: string
}

export interface RuleSummary {
  id: string
  displayName: string | null
  enabled: boolean
  severity: Severity
  logTypes: string[]
  tags: string[]
  updatedAt: string | null
}

export interface Rule extends RuleSummary {
  description: string | null
  body: string | null
  dedupPeriodMinutes: number
  threshold: number
  runbook: string | null
  reference: string | null
  tests: RuleTest[]
  createdAt: string | null
  createdBy: string | null
  updatedBy: string | null
}

export interface RuleTest {
  name: string
  expectedResult: boolean
  log: Record<string, unknown>
  mocks?: Record<string, unknown>
}

export interface RuleCreate {
  id: string
  body: string
  severity: Severity
  logTypes: string[]
  displayName?: string
  description?: string
  enabled?: boolean
  dedupPeriodMinutes?: number
  threshold?: number
  tags?: string[]
  runbook?: string
  reference?: string
  tests?: RuleTest[]
}

export interface RuleUpdate {
  body?: string
  severity?: Severity
  logTypes?: string[]
  displayName?: string
  description?: string
  enabled?: boolean
  dedupPeriodMinutes?: number
  threshold?: number
  tags?: string[]
  runbook?: string
  reference?: string
  tests?: RuleTest[]
}

export interface ConversionResult {
  sourceCode: string
  ruleId: string
  className: string
  logTypes: string[]
  severity: string
  isThresholdRule: boolean
  threshold: number | null
  todos: string[]
  testCode: string | null
  recommendedType: 'STREAMING' | 'SCHEDULED'
  recommendationReasons: string[]
}

export interface SPLConvertRequest {
  spl: string
  ruleId: string
  className?: string
  severity?: string
  sourceFormat?: 'spl' | 'yaral'
}

export interface PaginatedResponse<T> {
  results: T[]
  cursor: string | null
  hasMore: boolean
}

export interface AlertFilters {
  status?: AlertStatus
  severity?: Severity
  detectionId?: string
  pageSize?: number
  cursor?: string
}

export interface RuleFilters {
  enabled?: boolean
  severity?: Severity
  logTypes?: string[]
  tags?: string[]
  pageSize?: number
  cursor?: string
}
