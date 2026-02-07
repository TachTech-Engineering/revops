import { useState } from 'react'
import {
  Sparkles,
  RefreshCw,
  CheckCircle,
  XCircle,
  ChevronRight,
  Play,
  BookOpen,
  Filter,
  Wand2,
} from 'lucide-react'
import { Link } from 'react-router-dom'
import {
  useListPlaybookTemplatesQuery,
  useGeneratePlaybooksMutation,
  useApprovePlaybookTemplateMutation,
} from '../api/pantherApi'
import { cn } from '../lib/utils'

const confidenceColors = (confidence: number): string => {
  if (confidence >= 0.8) return 'text-green-400'
  if (confidence >= 0.6) return 'text-yellow-400'
  return 'text-orange-400'
}

export default function PlaybookGeneratorPage() {
  const [isApprovedFilter, setIsApprovedFilter] = useState<boolean | undefined>(undefined)
  const [showGenerateModal, setShowGenerateModal] = useState(false)

  const { data: templates, isLoading, refetch } = useListPlaybookTemplatesQuery({
    isApproved: isApprovedFilter,
    page: 1,
    pageSize: 50,
  })

  const [generatePlaybooks, { isLoading: isGenerating }] = useGeneratePlaybooksMutation()
  const [approveTemplate, { isLoading: isApproving }] = useApprovePlaybookTemplateMutation()

  const [generateParams, setGenerateParams] = useState({
    minIncidents: 5,
    severityFilter: ['high', 'critical'] as string[],
    timeRangeDays: 30,
  })

  const handleGenerate = async () => {
    try {
      await generatePlaybooks({
        minIncidents: generateParams.minIncidents,
        severityFilter: generateParams.severityFilter,
        timeRangeDays: generateParams.timeRangeDays,
      }).unwrap()
      setShowGenerateModal(false)
      refetch()
    } catch (err) {
      console.error('Failed to generate playbooks:', err)
    }
  }

  const handleApprove = async (templateId: string, convertToPlaybook: boolean) => {
    try {
      await approveTemplate({ templateId, convertToPlaybook }).unwrap()
      refetch()
    } catch (err) {
      console.error('Failed to approve template:', err)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Sparkles className="text-primary" />
            AI Playbook Generator
          </h1>
          <p className="text-muted-foreground mt-1">
            Automatically generate playbooks from incident resolution patterns
          </p>
        </div>
        <button
          onClick={() => setShowGenerateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
        >
          <Wand2 size={16} />
          Generate Playbooks
        </button>
      </div>

      {/* Info Banner */}
      <div className="bg-primary/10 border border-primary/30 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <Sparkles className="text-primary mt-0.5" size={20} />
          <div>
            <h3 className="font-medium">How it works</h3>
            <p className="text-sm text-muted-foreground mt-1">
              The AI analyzes resolved incidents to identify common response patterns.
              It extracts the steps analysts took and synthesizes them into reusable
              playbook templates. Review and approve templates before converting them
              to active playbooks.
            </p>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 bg-card rounded-lg border p-1">
          <button
            onClick={() => setIsApprovedFilter(undefined)}
            className={cn(
              'px-4 py-1.5 rounded text-sm transition-colors',
              isApprovedFilter === undefined
                ? 'bg-primary text-primary-foreground'
                : 'hover:bg-accent'
            )}
          >
            All
          </button>
          <button
            onClick={() => setIsApprovedFilter(false)}
            className={cn(
              'px-4 py-1.5 rounded text-sm transition-colors',
              isApprovedFilter === false
                ? 'bg-primary text-primary-foreground'
                : 'hover:bg-accent'
            )}
          >
            Pending Review
          </button>
          <button
            onClick={() => setIsApprovedFilter(true)}
            className={cn(
              'px-4 py-1.5 rounded text-sm transition-colors',
              isApprovedFilter === true
                ? 'bg-primary text-primary-foreground'
                : 'hover:bg-accent'
            )}
          >
            Approved
          </button>
        </div>
        <span className="text-sm text-muted-foreground ml-auto">
          {templates?.total || 0} templates
        </span>
      </div>

      {/* Templates List */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="animate-spin text-muted-foreground" size={24} />
        </div>
      ) : !templates?.templates?.length ? (
        <div className="text-center py-12 bg-card rounded-lg border">
          <BookOpen className="mx-auto text-muted-foreground mb-4" size={48} />
          <h3 className="text-lg font-medium">No playbook templates</h3>
          <p className="text-muted-foreground mt-1">
            Click "Generate Playbooks" to analyze resolved incidents and create templates
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {templates.templates.map((template) => (
            <div key={template.id} className="bg-card rounded-lg border p-4">
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-3">
                  {template.is_approved ? (
                    <span className="flex items-center gap-1 px-2 py-1 bg-green-500/20 text-green-400 text-xs rounded">
                      <CheckCircle size={12} />
                      Approved
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 px-2 py-1 bg-yellow-500/20 text-yellow-400 text-xs rounded">
                      <RefreshCw size={12} />
                      Pending Review
                    </span>
                  )}
                  <span
                    className={cn(
                      'text-sm font-medium',
                      confidenceColors(template.confidence_score)
                    )}
                  >
                    {(template.confidence_score * 100).toFixed(0)}% confidence
                  </span>
                </div>
                <span className="text-xs text-muted-foreground">
                  Based on {template.source_incident_count} incidents
                </span>
              </div>

              <h3 className="font-medium text-lg mb-2">{template.name}</h3>
              <p className="text-muted-foreground text-sm mb-4">{template.description}</p>

              {/* Trigger Conditions */}
              <div className="mb-4">
                <h4 className="text-sm font-medium mb-2">Trigger Conditions</h4>
                <div className="flex flex-wrap gap-2">
                  {template.trigger_conditions?.severities?.map((sev) => (
                    <span
                      key={sev}
                      className="px-2 py-1 bg-accent rounded text-xs capitalize"
                    >
                      {sev}
                    </span>
                  ))}
                  {template.trigger_conditions?.rule_ids?.map((rule) => (
                    <span key={rule} className="px-2 py-1 bg-accent rounded text-xs">
                      Rule: {rule}
                    </span>
                  ))}
                </div>
              </div>

              {/* Actions Preview */}
              <div className="mb-4">
                <h4 className="text-sm font-medium mb-2">
                  Actions ({template.actions?.length || 0} steps)
                </h4>
                <div className="space-y-2">
                  {template.actions?.slice(0, 3).map((action, index) => (
                    <div
                      key={index}
                      className="flex items-center gap-2 p-2 bg-muted/50 rounded text-sm"
                    >
                      <span className="w-6 h-6 flex items-center justify-center bg-primary/20 text-primary rounded-full text-xs font-bold">
                        {index + 1}
                      </span>
                      <span className="capitalize">{action.type.replace('_', ' ')}</span>
                      {action.name && (
                        <span className="text-muted-foreground">- {action.name}</span>
                      )}
                    </div>
                  ))}
                  {(template.actions?.length || 0) > 3 && (
                    <p className="text-xs text-muted-foreground pl-8">
                      +{template.actions!.length - 3} more actions
                    </p>
                  )}
                </div>
              </div>

              {/* Actions */}
              <div className="flex items-center gap-2 pt-3 border-t">
                {!template.is_approved ? (
                  <>
                    <button
                      onClick={() => handleApprove(template.id, false)}
                      disabled={isApproving}
                      className="flex items-center gap-2 px-3 py-1.5 text-sm border rounded hover:bg-accent"
                    >
                      <CheckCircle size={14} />
                      Approve
                    </button>
                    <button
                      onClick={() => handleApprove(template.id, true)}
                      disabled={isApproving}
                      className="flex items-center gap-2 px-3 py-1.5 text-sm bg-primary text-primary-foreground rounded hover:bg-primary/90"
                    >
                      <Play size={14} />
                      Approve & Create Playbook
                    </button>
                  </>
                ) : (
                  <Link
                    to={`/playbooks/${template.playbook_id}`}
                    className="flex items-center gap-2 px-3 py-1.5 text-sm border rounded hover:bg-accent"
                  >
                    View Playbook <ChevronRight size={14} />
                  </Link>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Generate Modal */}
      {showGenerateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-card rounded-lg p-6 max-w-md w-full mx-4">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Wand2 size={20} className="text-primary" />
              Generate Playbook Templates
            </h2>

            <p className="text-sm text-muted-foreground mb-4">
              Analyze resolved incidents to identify common response patterns
              and generate playbook templates automatically.
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">
                  Minimum Incidents Required
                </label>
                <input
                  type="number"
                  value={generateParams.minIncidents}
                  onChange={(e) =>
                    setGenerateParams({
                      ...generateParams,
                      minIncidents: parseInt(e.target.value),
                    })
                  }
                  min={2}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Pattern must appear in at least this many incidents
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">Time Range (days)</label>
                <input
                  type="number"
                  value={generateParams.timeRangeDays}
                  onChange={(e) =>
                    setGenerateParams({
                      ...generateParams,
                      timeRangeDays: parseInt(e.target.value),
                    })
                  }
                  className="w-full px-3 py-2 bg-background border rounded-md"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">Severity Filter</label>
                <div className="flex flex-wrap gap-2">
                  {['critical', 'high', 'medium', 'low'].map((sev) => (
                    <label key={sev} className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={generateParams.severityFilter.includes(sev)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setGenerateParams({
                              ...generateParams,
                              severityFilter: [...generateParams.severityFilter, sev],
                            })
                          } else {
                            setGenerateParams({
                              ...generateParams,
                              severityFilter: generateParams.severityFilter.filter(
                                (s) => s !== sev
                              ),
                            })
                          }
                        }}
                        className="rounded"
                      />
                      <span className="text-sm capitalize">{sev}</span>
                    </label>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => setShowGenerateModal(false)}
                className="px-4 py-2 border rounded-md hover:bg-accent"
              >
                Cancel
              </button>
              <button
                onClick={handleGenerate}
                disabled={isGenerating}
                className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
              >
                {isGenerating ? (
                  <>
                    <RefreshCw size={16} className="animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Sparkles size={16} />
                    Generate
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
