import { useState } from 'react'
import {
  RefreshCw,
  ChevronRight,
  Play,
  CheckCircle,
  AlertTriangle,
  Clock,
  Zap,
  BookOpen,
  ThumbsUp,
  ThumbsDown,
  ExternalLink,
} from 'lucide-react'
import { cn } from '../../lib/utils'

interface ResponseSuggestionsPanelProps {
  alertId: string
  alertType?: string
  severity?: string
  className?: string
}

// Mock API hook - in production this would call a real endpoint
const useResponseSuggestions = (_alertId: string) => {
  return {
    data: {
      alert_context: {
        type: 'Credential Access',
        severity: 'high',
        affected_assets: ['user@company.com', '192.168.1.100', 'prod-server-01'],
      },
      suggested_actions: [
        {
          id: '1',
          priority: 1,
          action: 'Disable compromised user account',
          description: 'Immediately disable the affected user account to prevent further unauthorized access',
          automation_available: true,
          estimated_time: '< 1 min',
          risk_level: 'low',
          playbook_id: 'disable-user-account',
        },
        {
          id: '2',
          priority: 2,
          action: 'Reset user credentials',
          description: 'Force password reset and revoke all active sessions for the affected user',
          automation_available: true,
          estimated_time: '< 1 min',
          risk_level: 'low',
          playbook_id: 'reset-credentials',
        },
        {
          id: '3',
          priority: 3,
          action: 'Review recent user activity',
          description: 'Analyze authentication logs and resource access patterns for the past 7 days',
          automation_available: false,
          estimated_time: '15-30 min',
          risk_level: 'none',
          query_template: 'SELECT * FROM logs WHERE user_id = :user_id AND timestamp > NOW() - INTERVAL 7 DAY',
        },
        {
          id: '4',
          priority: 4,
          action: 'Block source IP address',
          description: 'Add the source IP to the firewall blocklist to prevent further attempts',
          automation_available: true,
          estimated_time: '< 1 min',
          risk_level: 'medium',
          playbook_id: 'block-ip',
        },
        {
          id: '5',
          priority: 5,
          action: 'Notify security team',
          description: 'Send notification to the incident response team with alert details',
          automation_available: true,
          estimated_time: '< 1 min',
          risk_level: 'none',
          playbook_id: 'notify-team',
        },
      ],
      related_playbooks: [
        {
          id: 'credential-compromise',
          name: 'Credential Compromise Response',
          description: 'Complete playbook for handling credential-based attacks',
          steps: 12,
        },
        {
          id: 'account-takeover',
          name: 'Account Takeover Investigation',
          description: 'Step-by-step guide for investigating account takeover incidents',
          steps: 8,
        },
      ],
      similar_incidents: [
        {
          id: 'INC-2024-089',
          title: 'Similar credential stuffing attack',
          resolution: 'IP blocked, credentials reset, MFA enforced',
          resolved_in: '45 minutes',
        },
      ],
      confidence: 0.92,
    },
    isLoading: false,
  }
}

const riskColors = {
  none: 'text-green-400',
  low: 'text-blue-400',
  medium: 'text-yellow-400',
  high: 'text-red-400',
}

export default function ResponseSuggestionsPanel({
  alertId,
  className,
}: ResponseSuggestionsPanelProps) {
  const [executingAction, setExecutingAction] = useState<string | null>(null)
  const [completedActions, setCompletedActions] = useState<Set<string>>(new Set())
  const [feedback, setFeedback] = useState<Record<string, boolean>>({})

  const { data, isLoading } = useResponseSuggestions(alertId)

  const handleExecuteAction = async (actionId: string, _playbookId?: string) => {
    setExecutingAction(actionId)
    // Simulate execution
    await new Promise((resolve) => setTimeout(resolve, 2000))
    setExecutingAction(null)
    setCompletedActions((prev) => new Set(prev).add(actionId))
  }

  const handleFeedback = (actionId: string, helpful: boolean) => {
    setFeedback((prev) => ({ ...prev, [actionId]: helpful }))
  }

  if (isLoading) {
    return (
      <div className={cn('bg-card rounded-lg border p-6', className)}>
        <div className="flex items-center justify-center py-8">
          <RefreshCw className="animate-spin text-muted-foreground" size={24} />
          <span className="ml-2 text-muted-foreground">Analyzing alert and generating suggestions...</span>
        </div>
      </div>
    )
  }

  if (!data) return null

  return (
    <div className={cn('bg-card rounded-lg border overflow-hidden', className)}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b bg-gradient-to-r from-primary/10 to-transparent">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-full bg-primary/20 flex items-center justify-center">
            <Zap className="text-primary" size={20} />
          </div>
          <div>
            <h3 className="font-semibold">AI Response Suggestions</h3>
            <p className="text-xs text-muted-foreground">
              {(data.confidence * 100).toFixed(0)}% confidence based on similar incidents
            </p>
          </div>
        </div>
      </div>

      <div className="p-4 space-y-6">
        {/* Suggested Actions */}
        <div>
          <h4 className="font-medium mb-3 flex items-center gap-2">
            <Play size={16} />
            Recommended Actions
          </h4>
          <div className="space-y-2">
            {data.suggested_actions.map((action) => {
              const isExecuting = executingAction === action.id
              const isCompleted = completedActions.has(action.id)
              const hasFeedback = action.id in feedback

              return (
                <div
                  key={action.id}
                  className={cn(
                    'p-3 rounded-lg border transition-colors',
                    isCompleted
                      ? 'bg-green-500/10 border-green-500/30'
                      : 'bg-muted/30 hover:bg-muted/50'
                  )}
                >
                  <div className="flex items-start gap-3">
                    <div className="w-6 h-6 rounded-full bg-primary/20 flex items-center justify-center flex-shrink-0 text-xs font-bold">
                      {action.priority}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-medium">{action.action}</span>
                        {isCompleted && <CheckCircle size={14} className="text-green-400" />}
                      </div>
                      <p className="text-sm text-muted-foreground mb-2">{action.description}</p>
                      <div className="flex items-center gap-4 text-xs">
                        <span className="flex items-center gap-1 text-muted-foreground">
                          <Clock size={10} />
                          {action.estimated_time}
                        </span>
                        <span className={cn('flex items-center gap-1', riskColors[action.risk_level as keyof typeof riskColors])}>
                          <AlertTriangle size={10} />
                          {action.risk_level} risk
                        </span>
                        {action.automation_available && (
                          <span className="flex items-center gap-1 text-primary">
                            <Zap size={10} />
                            Automated
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {!isCompleted && action.automation_available && (
                        <button
                          onClick={() => handleExecuteAction(action.id, action.playbook_id)}
                          disabled={isExecuting}
                          className="flex items-center gap-1 px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm hover:bg-primary/90 disabled:opacity-50"
                        >
                          {isExecuting ? (
                            <>
                              <RefreshCw size={12} className="animate-spin" />
                              Running...
                            </>
                          ) : (
                            <>
                              <Play size={12} />
                              Execute
                            </>
                          )}
                        </button>
                      )}
                      {!hasFeedback && (
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => handleFeedback(action.id, true)}
                            className="p-1 hover:bg-accent rounded"
                            title="Helpful"
                          >
                            <ThumbsUp size={12} className="text-muted-foreground" />
                          </button>
                          <button
                            onClick={() => handleFeedback(action.id, false)}
                            className="p-1 hover:bg-accent rounded"
                            title="Not helpful"
                          >
                            <ThumbsDown size={12} className="text-muted-foreground" />
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Related Playbooks */}
        <div>
          <h4 className="font-medium mb-3 flex items-center gap-2">
            <BookOpen size={16} />
            Related Playbooks
          </h4>
          <div className="grid gap-2 md:grid-cols-2">
            {data.related_playbooks.map((playbook) => (
              <button
                key={playbook.id}
                className="flex items-center justify-between p-3 bg-muted/30 rounded-lg hover:bg-muted/50 text-left transition-colors"
              >
                <div>
                  <p className="font-medium text-sm">{playbook.name}</p>
                  <p className="text-xs text-muted-foreground">{playbook.steps} steps</p>
                </div>
                <ChevronRight size={16} className="text-muted-foreground" />
              </button>
            ))}
          </div>
        </div>

        {/* Similar Incidents */}
        {data.similar_incidents.length > 0 && (
          <div>
            <h4 className="font-medium mb-3 flex items-center gap-2">
              <ExternalLink size={16} />
              Similar Past Incidents
            </h4>
            <div className="space-y-2">
              {data.similar_incidents.map((incident) => (
                <div
                  key={incident.id}
                  className="p-3 bg-muted/30 rounded-lg"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-medium text-sm">{incident.id}</span>
                    <span className="text-xs text-green-400">Resolved in {incident.resolved_in}</span>
                  </div>
                  <p className="text-sm text-muted-foreground">{incident.title}</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    <strong>Resolution:</strong> {incident.resolution}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
