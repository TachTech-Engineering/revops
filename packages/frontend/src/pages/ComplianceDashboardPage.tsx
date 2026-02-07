import { useState } from 'react'
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
  Filter,
  Calendar,
  FileText,
  Target,
} from 'lucide-react'
import { cn } from '../lib/utils'

interface Framework {
  id: string
  name: string
  description: string
  totalControls: number
  implementedControls: number
  partialControls: number
  notImplementedControls: number
  coverage: number
  trend: 'up' | 'down' | 'stable'
  trendValue: number
  lastAssessment: string
  nextAssessment: string
}

interface Control {
  id: string
  frameworkId: string
  controlId: string
  title: string
  status: 'implemented' | 'partial' | 'not_implemented' | 'not_applicable'
  evidence: string[]
  lastReviewed: string
  owner: string
}

const mockFrameworks: Framework[] = [
  {
    id: 'soc2',
    name: 'SOC 2 Type II',
    description: 'Service Organization Control 2',
    totalControls: 85,
    implementedControls: 78,
    partialControls: 5,
    notImplementedControls: 2,
    coverage: 92,
    trend: 'up',
    trendValue: 3,
    lastAssessment: '2024-01-15',
    nextAssessment: '2024-07-15',
  },
  {
    id: 'hipaa',
    name: 'HIPAA',
    description: 'Health Insurance Portability and Accountability Act',
    totalControls: 50,
    implementedControls: 44,
    partialControls: 4,
    notImplementedControls: 2,
    coverage: 88,
    trend: 'up',
    trendValue: 5,
    lastAssessment: '2024-02-01',
    nextAssessment: '2024-08-01',
  },
  {
    id: 'pci',
    name: 'PCI-DSS 4.0',
    description: 'Payment Card Industry Data Security Standard',
    totalControls: 120,
    implementedControls: 90,
    partialControls: 15,
    notImplementedControls: 15,
    coverage: 75,
    trend: 'down',
    trendValue: 2,
    lastAssessment: '2024-01-20',
    nextAssessment: '2024-04-20',
  },
  {
    id: 'nist',
    name: 'NIST CSF',
    description: 'NIST Cybersecurity Framework',
    totalControls: 108,
    implementedControls: 73,
    partialControls: 20,
    notImplementedControls: 15,
    coverage: 68,
    trend: 'up',
    trendValue: 8,
    lastAssessment: '2024-01-10',
    nextAssessment: '2024-04-10',
  },
  {
    id: 'iso27001',
    name: 'ISO 27001',
    description: 'Information Security Management System',
    totalControls: 114,
    implementedControls: 95,
    partialControls: 12,
    notImplementedControls: 7,
    coverage: 83,
    trend: 'stable',
    trendValue: 0,
    lastAssessment: '2024-02-10',
    nextAssessment: '2024-08-10',
  },
]

const mockControls: Control[] = [
  {
    id: '1',
    frameworkId: 'soc2',
    controlId: 'CC6.1',
    title: 'Logical and Physical Access Controls',
    status: 'implemented',
    evidence: ['Access control policy', 'Access review logs', 'MFA configuration'],
    lastReviewed: '2024-01-15',
    owner: 'Security Team',
  },
  {
    id: '2',
    frameworkId: 'soc2',
    controlId: 'CC6.2',
    title: 'System Authentication',
    status: 'implemented',
    evidence: ['SSO configuration', 'Password policy'],
    lastReviewed: '2024-01-15',
    owner: 'IT Team',
  },
  {
    id: '3',
    frameworkId: 'soc2',
    controlId: 'CC7.1',
    title: 'Security Monitoring',
    status: 'partial',
    evidence: ['SIEM alerts', 'Monitoring dashboard'],
    lastReviewed: '2024-01-15',
    owner: 'SOC Team',
  },
  {
    id: '4',
    frameworkId: 'soc2',
    controlId: 'CC7.2',
    title: 'Incident Response',
    status: 'implemented',
    evidence: ['IR playbook', 'Incident logs'],
    lastReviewed: '2024-01-15',
    owner: 'Security Team',
  },
  {
    id: '5',
    frameworkId: 'soc2',
    controlId: 'CC8.1',
    title: 'Change Management',
    status: 'not_implemented',
    evidence: [],
    lastReviewed: '2024-01-15',
    owner: 'Engineering',
  },
]

const statusConfig = {
  implemented: { icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-500/20', label: 'Implemented' },
  partial: { icon: AlertTriangle, color: 'text-yellow-400', bg: 'bg-yellow-500/20', label: 'Partial' },
  not_implemented: { icon: XCircle, color: 'text-red-400', bg: 'bg-red-500/20', label: 'Not Implemented' },
  not_applicable: { icon: Shield, color: 'text-gray-400', bg: 'bg-gray-500/20', label: 'N/A' },
}

export default function ComplianceDashboardPage() {
  const [selectedFramework, setSelectedFramework] = useState<Framework | null>(null)
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [isExporting, setIsExporting] = useState(false)

  const filteredControls = mockControls.filter((control) => {
    if (!selectedFramework) return false
    if (control.frameworkId !== selectedFramework.id) return false
    if (statusFilter !== 'all' && control.status !== statusFilter) return false
    return true
  })

  const handleExportReport = async () => {
    setIsExporting(true)
    await new Promise((resolve) => setTimeout(resolve, 2000))
    setIsExporting(false)
  }

  const overallScore = Math.round(
    mockFrameworks.reduce((sum, f) => sum + f.coverage, 0) / mockFrameworks.length
  )

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
          disabled={isExporting}
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
            Average compliance score across {mockFrameworks.length} frameworks
          </p>
        </div>

        <div className="md:col-span-3 grid gap-4 md:grid-cols-3">
          <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <CheckCircle className="text-green-400" size={20} />
              <span className="text-sm text-muted-foreground">Implemented</span>
            </div>
            <p className="text-2xl font-bold text-green-400">
              {mockFrameworks.reduce((sum, f) => sum + f.implementedControls, 0)}
            </p>
            <p className="text-xs text-muted-foreground">controls</p>
          </div>
          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle className="text-yellow-400" size={20} />
              <span className="text-sm text-muted-foreground">Partial</span>
            </div>
            <p className="text-2xl font-bold text-yellow-400">
              {mockFrameworks.reduce((sum, f) => sum + f.partialControls, 0)}
            </p>
            <p className="text-xs text-muted-foreground">controls</p>
          </div>
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <XCircle className="text-red-400" size={20} />
              <span className="text-sm text-muted-foreground">Gaps</span>
            </div>
            <p className="text-2xl font-bold text-red-400">
              {mockFrameworks.reduce((sum, f) => sum + f.notImplementedControls, 0)}
            </p>
            <p className="text-xs text-muted-foreground">controls</p>
          </div>
        </div>
      </div>

      {/* Framework Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {mockFrameworks.map((framework) => (
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
                <p className="text-xs text-muted-foreground">{framework.description}</p>
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
                <span className="font-medium">{framework.coverage}%</span>
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
                <span>Last: {new Date(selectedFramework.lastAssessment).toLocaleDateString()}</span>
                <span>•</span>
                <span>Next: {new Date(selectedFramework.nextAssessment).toLocaleDateString()}</span>
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
            {filteredControls.map((control) => {
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
                          {control.controlId}
                        </span>
                        <span className="font-medium">{control.title}</span>
                      </div>
                      <div className="flex items-center gap-4 mt-1 text-xs text-muted-foreground">
                        <span>Owner: {control.owner}</span>
                        <span>•</span>
                        <span>Last reviewed: {new Date(control.lastReviewed).toLocaleDateString()}</span>
                        {control.evidence.length > 0 && (
                          <>
                            <span>•</span>
                            <span>{control.evidence.length} evidence items</span>
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
            })}
          </div>
        </div>
      )}
    </div>
  )
}
