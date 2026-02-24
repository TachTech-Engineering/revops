import { useState, useMemo } from 'react'
import {
  Shield,
  CheckCircle,
  AlertTriangle,
  XCircle,
  TrendingUp,
  TrendingDown,
  Download,
  RefreshCw,
  ChevronRight,
  Calendar,
  FileText,
  Target,
  Loader2,
} from 'lucide-react'
import { cn } from '../lib/utils'
import {
  useListComplianceFrameworksQuery,
  useListComplianceControlsQuery,
  useGetComplianceDashboardSummaryQuery,
  useExportComplianceReportMutation,
  ComplianceFramework,
  ComplianceControl,
} from '../api/pantherApi'

interface DisplayFramework {
  id: string
  name: string
  description: string | null
  totalControls: number
  implementedControls: number
  partialControls: number
  notImplementedControls: number
  coverage: number
  trend: 'up' | 'down' | 'stable'
  trendValue: number
  lastAssessment: string | null
  nextAssessment: string | null
}

const statusConfig = {
  implemented: { icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-500/20', label: 'Implemented' },
  partial: { icon: AlertTriangle, color: 'text-yellow-400', bg: 'bg-yellow-500/20', label: 'Partial' },
  not_implemented: { icon: XCircle, color: 'text-red-400', bg: 'bg-red-500/20', label: 'Not Implemented' },
  not_applicable: { icon: Shield, color: 'text-gray-400', bg: 'bg-gray-500/20', label: 'N/A' },
}

function mapFrameworkToDisplay(framework: ComplianceFramework): DisplayFramework {
  const implementedControls = framework.implemented_controls || 0
  const totalControls = framework.total_controls || 1
  const partialControls = Math.max(0, totalControls - implementedControls - Math.floor((totalControls - implementedControls) / 2))
  const notImplementedControls = Math.max(0, totalControls - implementedControls - partialControls)

  return {
    id: framework.id,
    name: framework.name,
    description: framework.description,
    totalControls: framework.total_controls,
    implementedControls: framework.implemented_controls,
    partialControls,
    notImplementedControls,
    coverage: framework.coverage_percentage || 0,
    trend: framework.coverage_percentage > 80 ? 'up' : framework.coverage_percentage > 50 ? 'stable' : 'down',
    trendValue: Math.abs(Math.round((framework.coverage_percentage - 75) / 10)),
    lastAssessment: framework.last_assessment_date,
    nextAssessment: framework.next_assessment_date,
  }
}

export default function ComplianceDashboardPage() {
  const [selectedFramework, setSelectedFramework] = useState<DisplayFramework | null>(null)
  const [statusFilter, setStatusFilter] = useState<string>('all')

  // Fetch frameworks
  const {
    data: frameworksData,
    isLoading: frameworksLoading,
    error: frameworksError,
  } = useListComplianceFrameworksQuery({ is_active: true })

  // Fetch dashboard summary
  const { data: summaryData, isLoading: summaryLoading } = useGetComplianceDashboardSummaryQuery()

  // Fetch controls for selected framework
  const {
    data: controlsData,
    isLoading: controlsLoading,
  } = useListComplianceControlsQuery(
    {
      frameworkId: selectedFramework?.id || '',
      status: statusFilter !== 'all' ? statusFilter : undefined,
      page_size: 100,
    },
    { skip: !selectedFramework }
  )

  // Export mutation
  const [exportReport, { isLoading: isExporting }] = useExportComplianceReportMutation()

  // Map frameworks to display format
  const displayFrameworks = useMemo(() => {
    if (!frameworksData?.frameworks) return []
    return frameworksData.frameworks.map(mapFrameworkToDisplay)
  }, [frameworksData])

  const handleExportReport = async () => {
    if (!selectedFramework) return
    try {
      const blob = await exportReport({
        framework_id: selectedFramework.id,
        format: 'csv',
        include_evidence: true,
      }).unwrap()

      // Download the file
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `compliance_report_${selectedFramework.name.replace(/\s+/g, '_')}.csv`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (error) {
      console.error('Export failed:', error)
    }
  }

  // Calculate overall score from summary or frameworks
  const overallScore = summaryData?.overall_coverage
    ? Math.round(summaryData.overall_coverage)
    : displayFrameworks.length > 0
    ? Math.round(displayFrameworks.reduce((sum, f) => sum + f.coverage, 0) / displayFrameworks.length)
    : 0

  // Get total counts from summary or frameworks
  const implementedTotal = summaryData?.implemented_controls
    ?? displayFrameworks.reduce((sum, f) => sum + f.implementedControls, 0)
  const partialTotal = summaryData?.partial_controls
    ?? displayFrameworks.reduce((sum, f) => sum + f.partialControls, 0)
  const notImplementedTotal = summaryData?.not_implemented_controls
    ?? displayFrameworks.reduce((sum, f) => sum + f.notImplementedControls, 0)

  if (frameworksLoading || summaryLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <span className="ml-2 text-muted-foreground">Loading compliance data...</span>
      </div>
    )
  }

  if (frameworksError) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <AlertTriangle className="h-12 w-12 text-yellow-500 mx-auto mb-4" />
          <h3 className="text-lg font-semibold">Failed to load compliance data</h3>
          <p className="text-muted-foreground">Please try refreshing the page.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Shield className="text-primary" />
            Compliance Dashboard
          </h1>
          <p className="text-muted-foreground mt-1">
            Monitor compliance posture across frameworks
          </p>
        </div>
        <button
          onClick={handleExportReport}
          disabled={isExporting || !selectedFramework}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
        >
          {isExporting ? (
            <>
              <RefreshCw size={16} className="animate-spin" />
              Generating...
            </>
          ) : (
            <>
              <Download size={16} />
              Export Report
            </>
          )}
        </button>
      </div>

      {/* Overall Score */}
      <div className="grid gap-4 md:grid-cols-4">
        <div className="md:col-span-1 bg-card rounded-lg border p-6 flex flex-col items-center justify-center">
          <div className="relative w-32 h-32 mb-4">
            <svg className="w-full h-full -rotate-90">
              <circle
                cx="64"
                cy="64"
                r="56"
                fill="none"
                stroke="currentColor"
                strokeWidth="8"
                className="text-muted"
              />
              <circle
                cx="64"
                cy="64"
                r="56"
                fill="none"
                stroke="currentColor"
                strokeWidth="8"
                strokeDasharray={`${(overallScore / 100) * 352} 352`}
                className={cn(
                  overallScore >= 80
                    ? 'text-green-500'
                    : overallScore >= 60
                    ? 'text-yellow-500'
                    : 'text-red-500'
                )}
              />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="text-center">
                <span className="text-3xl font-bold">{overallScore}%</span>
                <p className="text-xs text-muted-foreground">Overall</p>
              </div>
            </div>
          </div>
          <p className="text-sm text-muted-foreground text-center">
            Average compliance score across {displayFrameworks.length} frameworks
          </p>
        </div>

        <div className="md:col-span-3 grid gap-4 md:grid-cols-3">
          <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <CheckCircle className="text-green-400" size={20} />
              <span className="text-sm text-muted-foreground">Implemented</span>
            </div>
            <p className="text-2xl font-bold text-green-400">{implementedTotal}</p>
            <p className="text-xs text-muted-foreground">controls</p>
          </div>
          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle className="text-yellow-400" size={20} />
              <span className="text-sm text-muted-foreground">Partial</span>
            </div>
            <p className="text-2xl font-bold text-yellow-400">{partialTotal}</p>
            <p className="text-xs text-muted-foreground">controls</p>
          </div>
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <XCircle className="text-red-400" size={20} />
              <span className="text-sm text-muted-foreground">Gaps</span>
            </div>
            <p className="text-2xl font-bold text-red-400">{notImplementedTotal}</p>
            <p className="text-xs text-muted-foreground">controls</p>
          </div>
        </div>
      </div>

      {/* Framework Cards */}
      {displayFrameworks.length === 0 ? (
        <div className="text-center py-12 bg-card rounded-lg border">
          <Shield className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
          <h3 className="text-lg font-semibold">No Compliance Frameworks</h3>
          <p className="text-muted-foreground">
            Add a compliance framework to start tracking your compliance posture.
          </p>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {displayFrameworks.map((framework) => (
            <button
              key={framework.id}
              onClick={() => setSelectedFramework(framework)}
              className={cn(
                'text-left p-4 rounded-lg border transition-colors',
                selectedFramework?.id === framework.id
                  ? 'border-primary bg-primary/5'
                  : 'bg-card hover:border-primary/50'
              )}
            >
              <div className="flex items-start justify-between mb-3">
                <div>
                  <h3 className="font-semibold">{framework.name}</h3>
                  <p className="text-xs text-muted-foreground">{framework.description || 'No description'}</p>
                </div>
                <div className="flex items-center gap-1">
                  {framework.trend === 'up' ? (
                    <TrendingUp className="text-green-400" size={14} />
                  ) : framework.trend === 'down' ? (
                    <TrendingDown className="text-red-400" size={14} />
                  ) : null}
                  {framework.trendValue > 0 && (
                    <span
                      className={cn(
                        'text-xs',
                        framework.trend === 'up' ? 'text-green-400' : 'text-red-400'
                      )}
                    >
                      {framework.trend === 'up' ? '+' : '-'}{framework.trendValue}%
                    </span>
                  )}
                </div>
              </div>

              <div className="mb-3">
                <div className="flex justify-between text-sm mb-1">
                  <span>Coverage</span>
                  <span className="font-medium">{Math.round(framework.coverage)}%</span>
                </div>
                <div className="h-2 bg-muted rounded-full overflow-hidden">
                  <div
                    className={cn(
                      'h-full rounded-full',
                      framework.coverage >= 80
                        ? 'bg-green-500'
                        : framework.coverage >= 60
                        ? 'bg-yellow-500'
                        : 'bg-red-500'
                    )}
                    style={{ width: `${framework.coverage}%` }}
                  />
                </div>
              </div>

              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-3">
                  <span className="text-green-400">{framework.implementedControls} ✓</span>
                  <span className="text-yellow-400">{framework.partialControls} !</span>
                  <span className="text-red-400">{framework.notImplementedControls} ✗</span>
                </div>
                <ChevronRight size={14} className="text-muted-foreground" />
              </div>
            </button>
          ))}
        </div>
      )}

      {/* Control Details */}
      {selectedFramework && (
        <div className="bg-card rounded-lg border">
          <div className="flex items-center justify-between p-4 border-b">
            <div className="flex items-center gap-3">
              <Target size={20} />
              <div>
                <h3 className="font-semibold">{selectedFramework.name} Controls</h3>
                <p className="text-xs text-muted-foreground">
                  {selectedFramework.totalControls} total controls
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Calendar size={12} />
                {selectedFramework.lastAssessment && (
                  <span>Last: {new Date(selectedFramework.lastAssessment).toLocaleDateString()}</span>
                )}
                {selectedFramework.nextAssessment && (
                  <>
                    <span>•</span>
                    <span>Next: {new Date(selectedFramework.nextAssessment).toLocaleDateString()}</span>
                  </>
                )}
              </div>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="px-3 py-1.5 bg-background border rounded-md text-sm"
              >
                <option value="all">All Status</option>
                <option value="implemented">Implemented</option>
                <option value="partial">Partial</option>
                <option value="not_implemented">Not Implemented</option>
              </select>
            </div>
          </div>

          <div className="divide-y">
            {controlsLoading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="h-6 w-6 animate-spin text-primary" />
                <span className="ml-2 text-muted-foreground">Loading controls...</span>
              </div>
            ) : controlsData?.controls && controlsData.controls.length > 0 ? (
              controlsData.controls.map((control: ComplianceControl) => {
                const status = statusConfig[control.status]
                const StatusIcon = status.icon
                return (
                  <div key={control.id} className="p-4 flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className={cn('w-10 h-10 rounded-lg flex items-center justify-center', status.bg)}>
                        <StatusIcon size={18} className={status.color} />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-sm text-muted-foreground">
                            {control.control_id}
                          </span>
                          <span className="font-medium">{control.title}</span>
                        </div>
                        <div className="flex items-center gap-4 mt-1 text-xs text-muted-foreground">
                          {control.owner && <span>Owner: {control.owner}</span>}
                          {control.last_reviewed_at && (
                            <>
                              <span>•</span>
                              <span>Last reviewed: {new Date(control.last_reviewed_at).toLocaleDateString()}</span>
                            </>
                          )}
                          {control.evidence_links && control.evidence_links.length > 0 && (
                            <>
                              <span>•</span>
                              <span>{control.evidence_links.length} evidence items</span>
                            </>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={cn('px-3 py-1 rounded-full text-xs', status.bg, status.color)}>
                        {status.label}
                      </span>
                      <button className="p-2 hover:bg-accent rounded-md">
                        <FileText size={14} />
                      </button>
                    </div>
                  </div>
                )
              })
            ) : (
              <div className="text-center py-8 text-muted-foreground">
                No controls found for this framework.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
