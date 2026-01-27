import { useState } from 'react'
import {
  Lightbulb,
  RefreshCw,
  Check,
  X,
  ChevronDown,
  ChevronUp,
  Target,
  BarChart3,
  Code,
  AlertTriangle,
} from 'lucide-react'
import {
  useListRecommendationsQuery,
  useGetRecommendationStatsQuery,
  useGetCoverageGapsQuery,
  useGenerateRecommendationsMutation,
  useAcceptRecommendationMutation,
  useDismissRecommendationMutation,
  type RecommendationResponse,
} from '../api/pantherApi'
import { cn } from '../lib/utils'

const STATUS_COLORS: Record<string, string> = {
  pending: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
  accepted: 'bg-green-500/10 text-green-500 border-green-500/20',
  dismissed: 'bg-gray-500/10 text-gray-500 border-gray-500/20',
}

export default function RuleRecommendationsPage() {
  const [page, setPage] = useState(1)
  const [statusFilter, setStatusFilter] = useState<string>('pending')
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const { data: recommendations, isLoading, refetch } = useListRecommendationsQuery({
    status: statusFilter || undefined,
    page,
    page_size: 20,
  })
  const { data: stats } = useGetRecommendationStatsQuery()
  const { data: coverage } = useGetCoverageGapsQuery()

  const [generateRecommendations, { isLoading: isGenerating }] = useGenerateRecommendationsMutation()
  const [acceptRecommendation] = useAcceptRecommendationMutation()
  const [dismissRecommendation] = useDismissRecommendationMutation()

  const handleGenerate = async () => {
    await generateRecommendations({})
    refetch()
  }

  const handleAccept = async (id: string) => {
    if (window.confirm('Accept this recommendation and create the rule in Panther?')) {
      await acceptRecommendation(id)
      refetch()
    }
  }

  const handleDismiss = async (id: string) => {
    const reason = window.prompt('Reason for dismissal (optional):')
    await dismissRecommendation({ id, reason: reason || undefined })
    refetch()
  }

  // Calculate overall coverage
  const overallCoverage = coverage && coverage.length > 0
    ? coverage.reduce((acc, g) => acc + g.coverage_percentage, 0) / coverage.length
    : 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold flex items-center gap-2">
            <Lightbulb size={24} />
            Rule Recommendations
          </h1>
          <p className="text-muted-foreground mt-1">
            AI-suggested detection rules based on your log sources
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="flex items-center gap-2 px-3 py-2 bg-accent hover:bg-accent/80 rounded-md text-sm"
          >
            <RefreshCw size={16} />
            Refresh
          </button>
          <button
            onClick={handleGenerate}
            disabled={isGenerating}
            className="flex items-center gap-2 px-3 py-2 bg-primary text-primary-foreground hover:bg-primary/90 rounded-md text-sm disabled:opacity-50"
          >
            {isGenerating ? <RefreshCw size={16} className="animate-spin" /> : <Lightbulb size={16} />}
            Generate Recommendations
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 bg-card rounded-lg border">
          <div className="flex items-center gap-2 text-muted-foreground mb-2">
            <BarChart3 size={16} />
            <span className="text-sm">Coverage</span>
          </div>
          <p className="text-2xl font-bold">{overallCoverage.toFixed(0)}%</p>
        </div>
        <div className="p-4 bg-card rounded-lg border">
          <div className="flex items-center gap-2 text-muted-foreground mb-2">
            <AlertTriangle size={16} />
            <span className="text-sm">Pending</span>
          </div>
          <p className="text-2xl font-bold text-yellow-500">{stats?.by_status.pending || 0}</p>
        </div>
        <div className="p-4 bg-card rounded-lg border">
          <div className="flex items-center gap-2 text-muted-foreground mb-2">
            <Check size={16} />
            <span className="text-sm">Accepted</span>
          </div>
          <p className="text-2xl font-bold text-green-500">{stats?.by_status.accepted || 0}</p>
        </div>
        <div className="p-4 bg-card rounded-lg border">
          <div className="flex items-center gap-2 text-muted-foreground mb-2">
            <Target size={16} />
            <span className="text-sm">Catalog Rules</span>
          </div>
          <p className="text-2xl font-bold">{stats?.catalog_rules || 0}</p>
        </div>
      </div>

      {/* Coverage Gaps */}
      {coverage && coverage.length > 0 && (
        <div className="bg-card rounded-lg border p-6">
          <h2 className="text-lg font-semibold mb-4">Coverage by Log Source</h2>
          <div className="space-y-3">
            {coverage.map((gap) => (
              <div key={gap.log_source} className="flex items-center gap-4">
                <span className="w-40 text-sm truncate">{gap.log_source}</span>
                <div className="flex-1 bg-muted rounded-full h-2 overflow-hidden">
                  <div
                    className={cn(
                      'h-full rounded-full transition-all',
                      gap.coverage_percentage >= 80 ? 'bg-green-500' :
                      gap.coverage_percentage >= 50 ? 'bg-yellow-500' : 'bg-red-500'
                    )}
                    style={{ width: `${gap.coverage_percentage}%` }}
                  />
                </div>
                <span className="w-16 text-right text-sm font-medium">
                  {gap.coverage_percentage.toFixed(0)}%
                </span>
                <span className="w-24 text-right text-xs text-muted-foreground">
                  {gap.implemented_rules}/{gap.total_available_rules} rules
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filter */}
      <div className="flex items-center gap-4">
        <select
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value)
            setPage(1)
          }}
          className="px-3 py-2 bg-card border rounded-md text-sm"
        >
          <option value="">All Status</option>
          <option value="pending">Pending</option>
          <option value="accepted">Accepted</option>
          <option value="dismissed">Dismissed</option>
        </select>
        <span className="text-sm text-muted-foreground">
          {recommendations?.total || 0} recommendations
        </span>
      </div>

      {/* Recommendations List */}
      <div className="space-y-4">
        {isLoading ? (
          <div className="p-8 text-center text-muted-foreground bg-card rounded-lg border">
            Loading recommendations...
          </div>
        ) : recommendations?.items.length === 0 ? (
          <div className="p-8 text-center text-muted-foreground bg-card rounded-lg border">
            <Lightbulb size={48} className="mx-auto mb-4 opacity-50" />
            <p>No recommendations found</p>
            <p className="text-sm mt-2">Click "Generate Recommendations" to analyze your log sources</p>
          </div>
        ) : (
          recommendations?.items.map((rec) => (
            <RecommendationCard
              key={rec.id}
              recommendation={rec}
              isExpanded={expandedId === rec.id}
              onToggle={() => setExpandedId(expandedId === rec.id ? null : rec.id)}
              onAccept={() => handleAccept(rec.id)}
              onDismiss={() => handleDismiss(rec.id)}
            />
          ))
        )}
      </div>

      {/* Pagination */}
      {recommendations && recommendations.total > 20 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Showing {((page - 1) * 20) + 1} - {Math.min(page * 20, recommendations.total)} of {recommendations.total}
          </p>
          <div className="flex gap-2">
            <button
              disabled={page === 1}
              onClick={() => setPage(p => p - 1)}
              className="px-3 py-1 bg-accent rounded-md text-sm disabled:opacity-50"
            >
              Previous
            </button>
            <button
              disabled={page * 20 >= recommendations.total}
              onClick={() => setPage(p => p + 1)}
              className="px-3 py-1 bg-accent rounded-md text-sm disabled:opacity-50"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function RecommendationCard({
  recommendation,
  isExpanded,
  onToggle,
  onAccept,
  onDismiss,
}: {
  recommendation: RecommendationResponse
  isExpanded: boolean
  onToggle: () => void
  onAccept: () => void
  onDismiss: () => void
}) {
  return (
    <div className="bg-card rounded-lg border overflow-hidden">
      <div className="p-4">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className="flex items-center gap-3">
              <h3 className="font-semibold">{recommendation.rule_name}</h3>
              <span className={cn('text-xs px-2 py-0.5 rounded border', STATUS_COLORS[recommendation.status])}>
                {recommendation.status}
              </span>
              <span className="text-xs bg-accent px-2 py-0.5 rounded">
                {(recommendation.confidence_score * 100).toFixed(0)}% confidence
              </span>
            </div>
            <p className="text-sm text-muted-foreground mt-1">{recommendation.description}</p>
            <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
              <span>Log Source: {recommendation.log_source}</span>
              {recommendation.mitre_techniques.length > 0 && (
                <span>MITRE: {recommendation.mitre_techniques.join(', ')}</span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2">
            {recommendation.status === 'pending' && (
              <>
                <button
                  onClick={onAccept}
                  className="p-2 bg-green-500/10 text-green-500 hover:bg-green-500/20 rounded-md"
                  title="Accept and create rule"
                >
                  <Check size={16} />
                </button>
                <button
                  onClick={onDismiss}
                  className="p-2 bg-red-500/10 text-red-500 hover:bg-red-500/20 rounded-md"
                  title="Dismiss"
                >
                  <X size={16} />
                </button>
              </>
            )}
            <button
              onClick={onToggle}
              className="p-2 bg-accent hover:bg-accent/80 rounded-md"
            >
              {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
            </button>
          </div>
        </div>
      </div>

      {isExpanded && (
        <div className="border-t bg-muted/30 p-4">
          <div className="flex items-center gap-2 mb-2">
            <Code size={14} />
            <span className="text-sm font-medium">Rule Code</span>
          </div>
          <pre className="bg-background p-4 rounded-md text-sm overflow-x-auto max-h-64">
            {recommendation.rule_code}
          </pre>
        </div>
      )}
    </div>
  )
}
