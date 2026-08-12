import { useState } from 'react'
import {
  Sparkles,
  ChevronDown,
  ChevronUp,
  ThumbsUp,
  ThumbsDown,
  RefreshCw,
  Info,
} from 'lucide-react'
import {
  useGetTriageSuggestionQuery,
  useSubmitTriageFeedbackMutation,
} from '../../api/pantherApi'
import { cn } from '../../lib/utils'

interface TriageSuggestionBadgeProps {
  alertId: string
  compact?: boolean
}

const severityColors: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/50',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/50',
  info: 'bg-gray-500/20 text-gray-400 border-gray-500/50',
}

const confidenceColors = (confidence: number): string => {
  if (confidence >= 0.8) return 'text-green-400'
  if (confidence >= 0.6) return 'text-yellow-400'
  return 'text-orange-400'
}

export default function TriageSuggestionBadge({
  alertId,
  compact = false,
}: TriageSuggestionBadgeProps) {
  const [expanded, setExpanded] = useState(false)
  const [feedbackComment, setFeedbackComment] = useState('')

  const { data: suggestion, isLoading } = useGetTriageSuggestionQuery({
    alertId,
    forceRefresh: false,
  })

  const [submitFeedback, { isLoading: isSubmitting }] = useSubmitTriageFeedbackMutation()

  const handleFeedback = async (accepted: boolean) => {
    if (!suggestion) return
    try {
      await submitFeedback({
        suggestionId: suggestion.id,
        wasAccepted: accepted,
        feedbackComment: feedbackComment || undefined,
      }).unwrap()
      setFeedbackComment('')
    } catch (err) {
      console.error('Failed to submit feedback:', err)
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <RefreshCw size={14} className="animate-spin" />
        <span>Getting AI suggestion...</span>
      </div>
    )
  }

  if (!suggestion) {
    return null
  }

  // Compact view - just the badge
  if (compact) {
    return (
      <button
        onClick={() => setExpanded(!expanded)}
        className={cn(
          'flex items-center gap-2 px-3 py-1.5 rounded-lg border transition-colors',
          'bg-primary/10 border-primary/30 hover:bg-primary/20'
        )}
      >
        <Sparkles size={14} className="text-primary" />
        <span className="text-sm font-medium">
          AI: {suggestion.suggested_severity.toUpperCase()}
        </span>
        <span className={cn('text-xs', confidenceColors(suggestion.confidence_score))}>
          {(suggestion.confidence_score * 100).toFixed(0)}%
        </span>
        {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
      </button>
    )
  }

  return (
    <div className="bg-card rounded-lg border border-primary/30 overflow-hidden">
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between p-3 hover:bg-accent/50 transition-colors"
      >
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center">
            <Sparkles size={16} className="text-primary" />
          </div>
          <div className="text-left">
            <p className="font-medium text-sm">AI Triage Suggestion</p>
            <p className="text-xs text-muted-foreground">
              {suggestion.was_accepted === true && 'Accepted'}
              {suggestion.was_accepted === false && 'Rejected'}
              {suggestion.was_accepted === null && 'Pending review'}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span
              className={cn(
                'px-2 py-1 rounded text-xs font-medium border',
                severityColors[suggestion.suggested_severity] || severityColors.medium
              )}
            >
              {suggestion.suggested_severity.toUpperCase()}
            </span>
            <span className={cn('text-sm font-medium', confidenceColors(suggestion.confidence_score))}>
              {(suggestion.confidence_score * 100).toFixed(0)}% confident
            </span>
          </div>
          {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </div>
      </button>

      {/* Expanded Content */}
      {expanded && (
        <div className="border-t p-4 space-y-4">
          {/* Reasoning */}
          <div>
            <h4 className="text-sm font-medium mb-2 flex items-center gap-1">
              <Info size={14} />
              Reasoning
            </h4>
            <p className="text-sm text-muted-foreground">{suggestion.reasoning}</p>
          </div>

          {/* Contributing Factors */}
          {suggestion.contributing_factors && suggestion.contributing_factors.length > 0 && (
            <div>
              <h4 className="text-sm font-medium mb-2">Contributing Factors</h4>
              <div className="space-y-2">
                {suggestion.contributing_factors.map((factor: { factor: string; value: string; weight: number }, index: number) => (
                  <div
                    key={index}
                    className="flex items-center justify-between p-2 bg-muted/50 rounded"
                  >
                    <span className="text-sm capitalize">
                      {factor.factor.replace('_', ' ')}
                    </span>
                    <div className="flex items-center gap-3">
                      <span className="text-sm text-muted-foreground capitalize">
                        {factor.value}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        Weight: {(factor.weight * 100).toFixed(0)}%
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Feedback Section */}
          {suggestion.was_accepted === null && (
            <div className="border-t pt-4">
              <h4 className="text-sm font-medium mb-2">Was this helpful?</h4>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleFeedback(true)}
                  disabled={isSubmitting}
                  className="flex items-center gap-2 px-3 py-1.5 bg-green-500/20 text-green-400 rounded hover:bg-green-500/30 disabled:opacity-50"
                >
                  <ThumbsUp size={14} />
                  Accept
                </button>
                <button
                  onClick={() => handleFeedback(false)}
                  disabled={isSubmitting}
                  className="flex items-center gap-2 px-3 py-1.5 bg-red-500/20 text-red-400 rounded hover:bg-red-500/30 disabled:opacity-50"
                >
                  <ThumbsDown size={14} />
                  Reject
                </button>
                <input
                  type="text"
                  value={feedbackComment}
                  onChange={(e) => setFeedbackComment(e.target.value)}
                  placeholder="Optional comment..."
                  className="flex-1 px-3 py-1.5 bg-background border rounded text-sm"
                />
              </div>
            </div>
          )}

          {/* Feedback Status */}
          {suggestion.was_accepted !== null && (
            <div className="border-t pt-4">
              <div
                className={cn(
                  'flex items-center gap-2 px-3 py-2 rounded',
                  suggestion.was_accepted
                    ? 'bg-green-500/20 text-green-400'
                    : 'bg-red-500/20 text-red-400'
                )}
              >
                {suggestion.was_accepted ? (
                  <>
                    <ThumbsUp size={14} />
                    <span className="text-sm">Suggestion accepted</span>
                  </>
                ) : (
                  <>
                    <ThumbsDown size={14} />
                    <span className="text-sm">Suggestion rejected</span>
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
