import { RefreshCw, Shield, AlertTriangle, ChevronRight } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useGetCoverageHeatmapQuery } from '../../../api/pantherApi'
import { cn } from '../../../lib/utils'

interface CoverageGapWidgetProps {
  config?: {
    days?: number
  }
}

const coverageColors = (percentage: number): string => {
  if (percentage >= 80) return 'bg-green-500'
  if (percentage >= 60) return 'bg-yellow-500'
  if (percentage >= 40) return 'bg-orange-500'
  return 'bg-red-500'
}

const tacticLabels: Record<string, string> = {
  'reconnaissance': 'Recon',
  'resource-development': 'Resource Dev',
  'initial-access': 'Initial Access',
  'execution': 'Execution',
  'persistence': 'Persistence',
  'privilege-escalation': 'Priv Esc',
  'defense-evasion': 'Def Evasion',
  'credential-access': 'Cred Access',
  'discovery': 'Discovery',
  'lateral-movement': 'Lateral Move',
  'collection': 'Collection',
  'command-and-control': 'C2',
  'exfiltration': 'Exfil',
  'impact': 'Impact',
}

export default function CoverageGapWidget({ config }: CoverageGapWidgetProps) {
  const { data, isLoading } = useGetCoverageHeatmapQuery({
    days: config?.days || 30,
  })

  if (isLoading) {
    return (
      <div className="h-full flex items-center justify-center">
        <RefreshCw className="animate-spin text-muted-foreground" size={24} />
      </div>
    )
  }

  if (!data) {
    return (
      <div className="h-full flex items-center justify-center text-muted-foreground">
        No coverage data available
      </div>
    )
  }

  const tactics = data.tactics || []
  const criticalGaps = tactics.filter((t) => (t.coverage_percentage || 0) < 40)

  return (
    <div className="h-full flex flex-col p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-medium flex items-center gap-2">
          <Shield size={16} className="text-primary" />
          MITRE Coverage
        </h3>
        <Link to="/mitre" className="text-xs text-primary hover:underline flex items-center gap-1">
          Full View <ChevronRight size={12} />
        </Link>
      </div>

      {/* Summary */}
      <div className="flex items-center gap-4 mb-4">
        <div className="flex-1 bg-muted/50 rounded-lg p-3">
          <p className="text-xs text-muted-foreground">Overall</p>
          <p className="text-xl font-bold">
            {((data.overall_coverage || 0) * 100).toFixed(0)}%
          </p>
        </div>
        {criticalGaps.length > 0 && (
          <div className="flex-1 bg-red-500/10 border border-red-500/30 rounded-lg p-3">
            <p className="text-xs text-red-400">Critical Gaps</p>
            <p className="text-xl font-bold text-red-400">{criticalGaps.length}</p>
          </div>
        )}
      </div>

      {/* Heatmap Grid */}
      <div className="flex-1">
        <p className="text-xs text-muted-foreground mb-2">Coverage by Tactic</p>
        <div className="grid grid-cols-7 gap-1">
          {tactics.slice(0, 14).map((tactic) => {
            const percentage = (tactic.coverage_percentage || 0) * 100
            return (
              <div
                key={tactic.tactic}
                className="aspect-square relative group"
                title={`${tacticLabels[tactic.tactic] || tactic.tactic}: ${percentage.toFixed(0)}%`}
              >
                <div
                  className={cn(
                    'w-full h-full rounded',
                    coverageColors(percentage),
                    'opacity-60 hover:opacity-100 transition-opacity'
                  )}
                />
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-[10px] font-bold text-white drop-shadow">
                    {percentage.toFixed(0)}
                  </span>
                </div>
                {/* Tooltip */}
                <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1 px-2 py-1 bg-popover rounded text-xs whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-10">
                  {tacticLabels[tactic.tactic] || tactic.tactic}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center justify-center gap-4 mt-4 text-xs">
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-red-500" />
          <span className="text-muted-foreground">&lt;40%</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-yellow-500" />
          <span className="text-muted-foreground">40-60%</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded bg-green-500" />
          <span className="text-muted-foreground">&gt;80%</span>
        </div>
      </div>

      {/* Critical Gaps Alert */}
      {criticalGaps.length > 0 && (
        <div className="mt-4 p-2 bg-red-500/10 border border-red-500/30 rounded">
          <div className="flex items-center gap-2 text-sm text-red-400">
            <AlertTriangle size={14} />
            <span>
              Low coverage in: {criticalGaps.map((t) => tacticLabels[t.tactic] || t.tactic).join(', ')}
            </span>
          </div>
        </div>
      )}
    </div>
  )
}
