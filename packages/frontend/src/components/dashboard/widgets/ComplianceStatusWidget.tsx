import { Link } from 'react-router-dom'
import {
  Shield,
  RefreshCw,
  ChevronRight,
  CheckCircle,
  AlertTriangle,
  XCircle,
  TrendingUp,
  TrendingDown,
} from 'lucide-react'
import { cn } from '../../../lib/utils'

interface ComplianceStatusWidgetProps {
  config?: {
    frameworks?: string[]
  }
}

// Mock data - in production this would come from an API
const useComplianceStatus = () => {
  return {
    data: {
      frameworks: [
        {
          id: 'soc2',
          name: 'SOC 2',
          coverage: 92,
          controls_met: 78,
          controls_total: 85,
          trend: 'up',
          status: 'compliant',
        },
        {
          id: 'hipaa',
          name: 'HIPAA',
          coverage: 88,
          controls_met: 44,
          controls_total: 50,
          trend: 'up',
          status: 'compliant',
        },
        {
          id: 'pci',
          name: 'PCI-DSS',
          coverage: 75,
          controls_met: 90,
          controls_total: 120,
          trend: 'down',
          status: 'partial',
        },
        {
          id: 'nist',
          name: 'NIST CSF',
          coverage: 68,
          controls_met: 82,
          controls_total: 120,
          trend: 'up',
          status: 'partial',
        },
      ],
      overall_score: 85,
      last_assessment: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    },
    isLoading: false,
  }
}

const statusConfig = {
  compliant: { icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-500' },
  partial: { icon: AlertTriangle, color: 'text-yellow-400', bg: 'bg-yellow-500' },
  'non-compliant': { icon: XCircle, color: 'text-red-400', bg: 'bg-red-500' },
}

export default function ComplianceStatusWidget({ config }: ComplianceStatusWidgetProps) {
  const { data, isLoading } = useComplianceStatus()

  if (isLoading) {
    return (
      <div className="h-full flex items-center justify-center">
        <RefreshCw className="animate-spin text-muted-foreground" size={24} />
      </div>
    )
  }

  if (!data) return null

  const filteredFrameworks = config?.frameworks
    ? data.frameworks.filter((f) => config.frameworks!.includes(f.id))
    : data.frameworks

  return (
    <div className="h-full flex flex-col p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-medium flex items-center gap-2">
          <Shield size={16} className="text-primary" />
          Compliance Status
        </h3>
        <Link
          to="/compliance"
          className="text-xs text-primary hover:underline flex items-center gap-1"
        >
          Details <ChevronRight size={12} />
        </Link>
      </div>

      {/* Overall Score */}
      <div className="flex items-center justify-center mb-4">
        <div className="relative w-20 h-20">
          <svg className="w-full h-full -rotate-90">
            <circle
              cx="40"
              cy="40"
              r="35"
              fill="none"
              stroke="currentColor"
              strokeWidth="6"
              className="text-muted"
            />
            <circle
              cx="40"
              cy="40"
              r="35"
              fill="none"
              stroke="currentColor"
              strokeWidth="6"
              strokeDasharray={`${(data.overall_score / 100) * 220} 220`}
              className={cn(
                data.overall_score >= 80
                  ? 'text-green-500'
                  : data.overall_score >= 60
                  ? 'text-yellow-500'
                  : 'text-red-500'
              )}
            />
          </svg>
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-xl font-bold">{data.overall_score}%</span>
          </div>
        </div>
      </div>

      {/* Framework List */}
      <div className="flex-1 space-y-2 overflow-y-auto">
        {filteredFrameworks.map((framework) => {
          const status = statusConfig[framework.status as keyof typeof statusConfig]
          const StatusIcon = status.icon
          return (
            <div
              key={framework.id}
              className="p-2 bg-muted/50 rounded-lg"
            >
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2">
                  <StatusIcon size={14} className={status.color} />
                  <span className="text-sm font-medium">{framework.name}</span>
                </div>
                <div className="flex items-center gap-1">
                  {framework.trend === 'up' ? (
                    <TrendingUp size={12} className="text-green-400" />
                  ) : (
                    <TrendingDown size={12} className="text-red-400" />
                  )}
                  <span className="text-sm font-medium">{framework.coverage}%</span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
                  <div
                    className={cn('h-full rounded-full', status.bg)}
                    style={{ width: `${framework.coverage}%` }}
                  />
                </div>
                <span className="text-xs text-muted-foreground">
                  {framework.controls_met}/{framework.controls_total}
                </span>
              </div>
            </div>
          )
        })}
      </div>

      <p className="text-xs text-muted-foreground text-center mt-2">
        Last assessed: {new Date(data.last_assessment).toLocaleDateString()}
      </p>
    </div>
  )
}
