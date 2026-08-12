import { useState } from 'react'
import {
  Crosshair,
  Sparkles,
  Search,
  Play,
  RefreshCw,
  BookOpen,
  Clock,
  Target,
  AlertTriangle,
  CheckCircle,
  History,
  Lightbulb,
  FileText,
  Plus,
  Loader2,
} from 'lucide-react'
import { cn } from '../lib/utils'
import {
  useListThreatHuntsQuery,
  useGenerateThreatHypothesisMutation,
  useCreateThreatHuntMutation,
  useExecuteHuntQueryMutation,
  useGetHuntResultsQuery,
  useExecuteQueryMutation,
  type ThreatHunt,
  type GeneratedHypothesis,
  type QueryResult,
} from '../api/pantherApi'

export default function ThreatHuntingPage() {
  const [selectedHunt, setSelectedHunt] = useState<ThreatHunt | null>(null)
  const [customQuery, setCustomQuery] = useState('')
  const [naturalLanguageQuery, setNaturalLanguageQuery] = useState('')
  const [activeTab, setActiveTab] = useState<'hypotheses' | 'custom' | 'history'>('hypotheses')
  const [generatedHypothesis, setGeneratedHypothesis] = useState<GeneratedHypothesis | null>(null)
  const [runningQueryId, setRunningQueryId] = useState<string | null>(null)

  // API queries and mutations
  const {
    data: huntsData,
    isLoading: huntsLoading,
    error: huntsError,
    refetch: refetchHunts,
  } = useListThreatHuntsQuery({ page_size: 50 })

  const {
    data: huntResults,
    isLoading: resultsLoading,
  } = useGetHuntResultsQuery(
    { huntId: selectedHunt?.id || '' },
    { skip: !selectedHunt }
  )

  const [generateHypothesis, { isLoading: isGenerating }] = useGenerateThreatHypothesisMutation()
  const [createHunt] = useCreateThreatHuntMutation()
  const [executeHuntQuery] = useExecuteHuntQueryMutation()
  const [executeCustomQuery, { isLoading: isRunningCustomQuery }] = useExecuteQueryMutation()

  const [customQueryResult, setCustomQueryResult] = useState<QueryResult | null>(null)

  const hunts = huntsData?.hunts || []

  const handleGenerateHypothesis = async () => {
    if (!naturalLanguageQuery.trim()) return
    try {
      const result = await generateHypothesis({
        description: naturalLanguageQuery,
        include_mitre: true,
        include_queries: true,
      }).unwrap()
      setGeneratedHypothesis(result)
    } catch (error) {
      console.error('Failed to generate hypothesis:', error)
    }
  }

  const handleCreateHuntFromHypothesis = async () => {
    if (!generatedHypothesis) return
    try {
      const newHunt = await createHunt({
        title: generatedHypothesis.title,
        hypothesis: generatedHypothesis.hypothesis,
        description: generatedHypothesis.rationale,
        mitre_techniques: generatedHypothesis.mitre_techniques.map(t => t.id),
        data_sources: generatedHypothesis.data_sources,
        priority: generatedHypothesis.priority,
        queries: generatedHypothesis.suggested_queries.map((q, idx) => ({
          name: q.name,
          description: q.description,
          sql_query: q.sql,
          query_type: 'detection' as const,
          order_index: idx,
        })),
      }).unwrap()
      setSelectedHunt(newHunt)
      setGeneratedHypothesis(null)
      setNaturalLanguageQuery('')
      refetchHunts()
    } catch (error) {
      console.error('Failed to create hunt:', error)
    }
  }

  const handleRunQuery = async (huntId: string, queryId: string) => {
    setRunningQueryId(queryId)
    try {
      await executeHuntQuery({
        huntId,
        queryId,
        data: { timeout_seconds: 60, limit_results: 1000 },
      }).unwrap()
      refetchHunts()
    } catch (error) {
      console.error('Failed to execute query:', error)
    } finally {
      setRunningQueryId(null)
    }
  }

  const handleRunCustomQuery = async () => {
    if (!customQuery.trim()) return
    try {
      const result = await executeCustomQuery({
        sql: customQuery,
        timeout: 60000,
      }).unwrap()
      setCustomQueryResult(result)
    } catch (error) {
      console.error('Failed to execute custom query:', error)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Crosshair className="text-primary" />
            Threat Hunting Assistant
          </h1>
          <p className="text-muted-foreground mt-1">
            AI-powered threat hunting with hypothesis generation and guided investigations
          </p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90">
          <Plus size={16} />
          New Hunt
        </button>
      </div>

      {/* AI Query Input */}
      <div className="bg-card rounded-lg border p-4">
        <div className="flex items-center gap-3 mb-3">
          <Sparkles className="text-primary" size={20} />
          <h3 className="font-medium">Ask AI to Generate a Hunt</h3>
        </div>
        <div className="flex gap-2">
          <input
            type="text"
            value={naturalLanguageQuery}
            onChange={(e) => setNaturalLanguageQuery(e.target.value)}
            placeholder="Describe what you want to hunt for... (e.g., 'Find signs of PowerShell-based attacks in the last week')"
            className="flex-1 px-4 py-2 bg-background border rounded-md"
          />
          <button
            onClick={handleGenerateHypothesis}
            disabled={isGenerating || !naturalLanguageQuery.trim()}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
          >
            {isGenerating ? (
              <>
                <RefreshCw size={16} className="animate-spin" />
                Generating...
              </>
            ) : (
              <>
                <Sparkles size={16} />
                Generate Hunt
              </>
            )}
          </button>
        </div>
        <div className="flex items-center gap-4 mt-3 text-xs text-muted-foreground">
          <span className="flex items-center gap-1">
            <Lightbulb size={12} />
            Try: "Hunt for signs of data exfiltration"
          </span>
          <span className="flex items-center gap-1">
            <Lightbulb size={12} />
            Try: "Look for persistence mechanisms"
          </span>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b">
        <button
          onClick={() => setActiveTab('hypotheses')}
          className={cn(
            'px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors',
            activeTab === 'hypotheses'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          )}
        >
          <Target size={14} className="inline mr-2" />
          Hunting Hypotheses
        </button>
        <button
          onClick={() => setActiveTab('custom')}
          className={cn(
            'px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors',
            activeTab === 'custom'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          )}
        >
          <Search size={14} className="inline mr-2" />
          Custom Query
        </button>
        <button
          onClick={() => setActiveTab('history')}
          className={cn(
            'px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors',
            activeTab === 'history'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          )}
        >
          <History size={14} className="inline mr-2" />
          Hunt History
        </button>
      </div>

      {/* Hypotheses Tab */}
      {activeTab === 'hypotheses' && (
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Hunt List */}
          <div className="space-y-4">
            <h3 className="font-medium">Active Hunts</h3>
            {huntsLoading ? (
              <div className="flex items-center justify-center p-8">
                <Loader2 className="animate-spin text-muted-foreground" size={32} />
              </div>
            ) : huntsError ? (
              <div className="p-4 bg-destructive/10 border border-destructive/30 rounded-lg text-center">
                <p className="text-sm text-destructive">Failed to load hunts</p>
                <button
                  onClick={() => refetchHunts()}
                  className="mt-2 text-xs text-primary hover:underline"
                >
                  Retry
                </button>
              </div>
            ) : hunts.length === 0 ? (
              <div className="p-8 bg-muted/30 rounded-lg border border-dashed text-center">
                <Target className="mx-auto text-muted-foreground mb-3" size={32} />
                <p className="text-sm text-muted-foreground">No hunts created yet</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Generate a hypothesis above to get started
                </p>
              </div>
            ) : (
              hunts.map((hunt) => (
                <button
                  key={hunt.id}
                  onClick={() => setSelectedHunt(hunt)}
                  className={cn(
                    'w-full text-left p-4 rounded-lg border transition-colors',
                    selectedHunt?.id === hunt.id
                      ? 'border-primary bg-primary/5'
                      : 'hover:bg-muted/50'
                  )}
                >
                  <div className="flex items-start justify-between mb-2">
                    <h4 className="font-medium">{hunt.title}</h4>
                    <span className={cn(
                      'text-xs px-2 py-0.5 rounded capitalize',
                      hunt.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                      hunt.status === 'in_progress' ? 'bg-blue-500/20 text-blue-400' :
                      hunt.status === 'draft' ? 'bg-gray-500/20 text-gray-400' :
                      'bg-red-500/20 text-red-400'
                    )}>
                      {hunt.status.replace('_', ' ')}
                    </span>
                  </div>
                  <p className="text-sm text-muted-foreground mb-3 line-clamp-2">{hunt.hypothesis}</p>
                  <div className="flex items-center gap-4 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Target size={10} />
                      {hunt.mitre_techniques.length} techniques
                    </span>
                    <span className="flex items-center gap-1">
                      <FileText size={10} />
                      {hunt.queries?.length || 0} queries
                    </span>
                    {hunt.findings_count > 0 && (
                      <span className="flex items-center gap-1 text-yellow-400">
                        <AlertTriangle size={10} />
                        {hunt.findings_count} findings
                      </span>
                    )}
                  </div>
                </button>
              ))
            )}

            {/* Generated Hypothesis Preview */}
            {generatedHypothesis && (
              <div className="mt-4 p-4 bg-primary/5 border border-primary/30 rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="font-medium text-primary flex items-center gap-2">
                    <Sparkles size={14} />
                    Generated Hypothesis
                    <span
                      className={cn(
                        'px-2 py-0.5 rounded-full text-xs font-normal',
                        generatedHypothesis.generated_by === 'llm'
                          ? 'bg-primary/20 text-primary'
                          : 'bg-yellow-500/20 text-yellow-400'
                      )}
                      title={
                        generatedHypothesis.generated_by === 'llm'
                          ? 'Generated by the AI model'
                          : 'Generated by a keyword-matching heuristic (LLM unavailable)'
                      }
                    >
                      {generatedHypothesis.generated_by === 'llm' ? 'AI' : 'Heuristic'}
                    </span>
                  </h4>
                  <button
                    onClick={() => setGeneratedHypothesis(null)}
                    className="text-xs text-muted-foreground hover:text-foreground"
                  >
                    Dismiss
                  </button>
                </div>
                <h5 className="font-medium mb-1">{generatedHypothesis.title}</h5>
                <p className="text-sm text-muted-foreground mb-3">{generatedHypothesis.hypothesis}</p>
                <div className="flex flex-wrap gap-2 mb-3">
                  {generatedHypothesis.mitre_techniques.map((tech) => (
                    <span
                      key={tech.id}
                      className="px-2 py-0.5 bg-red-500/20 text-red-400 rounded text-xs"
                    >
                      {tech.id}: {tech.name}
                    </span>
                  ))}
                </div>
                <button
                  onClick={handleCreateHuntFromHypothesis}
                  className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
                >
                  <Plus size={14} />
                  Create Hunt from Hypothesis
                </button>
              </div>
            )}
          </div>

          {/* Hunt Detail */}
          {selectedHunt ? (
            <div className="bg-card rounded-lg border p-4 space-y-4">
              <div>
                <div className="flex items-start justify-between">
                  <h3 className="font-semibold text-lg">{selectedHunt.title}</h3>
                  <span className={cn(
                    'text-xs px-2 py-0.5 rounded capitalize',
                    selectedHunt.priority === 'critical' ? 'bg-red-500/20 text-red-400' :
                    selectedHunt.priority === 'high' ? 'bg-orange-500/20 text-orange-400' :
                    selectedHunt.priority === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                    'bg-green-500/20 text-green-400'
                  )}>
                    {selectedHunt.priority} priority
                  </span>
                </div>
                <p className="text-sm text-muted-foreground mt-1">
                  {selectedHunt.hypothesis}
                </p>
                {selectedHunt.description && (
                  <p className="text-xs text-muted-foreground mt-2 italic">
                    {selectedHunt.description}
                  </p>
                )}
              </div>

              {/* MITRE Techniques */}
              <div>
                <h4 className="text-sm font-medium mb-2">MITRE ATT&CK Techniques</h4>
                <div className="flex flex-wrap gap-2">
                  {selectedHunt.mitre_techniques.map((tech) => (
                    <span
                      key={tech}
                      className="px-2 py-1 bg-red-500/20 text-red-400 rounded text-xs"
                    >
                      {tech}
                    </span>
                  ))}
                </div>
              </div>

              {/* Data Sources */}
              <div>
                <h4 className="text-sm font-medium mb-2">Data Sources</h4>
                <div className="flex flex-wrap gap-2">
                  {selectedHunt.data_sources.map((source) => (
                    <span
                      key={source}
                      className="px-2 py-1 bg-muted rounded text-xs"
                    >
                      {source}
                    </span>
                  ))}
                </div>
              </div>

              {/* Hunt Queries */}
              <div>
                <h4 className="text-sm font-medium mb-2">Hunt Queries</h4>
                <div className="space-y-3">
                  {selectedHunt.queries && selectedHunt.queries.length > 0 ? (
                    selectedHunt.queries.map((query) => (
                      <div key={query.id} className="bg-muted/50 rounded-lg p-3">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-medium text-sm">{query.name}</span>
                          <button
                            onClick={() => handleRunQuery(selectedHunt.id, query.id)}
                            disabled={runningQueryId === query.id}
                            className="flex items-center gap-1 px-3 py-1 bg-primary text-primary-foreground rounded text-xs hover:bg-primary/90 disabled:opacity-50"
                          >
                            {runningQueryId === query.id ? (
                              <RefreshCw size={12} className="animate-spin" />
                            ) : (
                              <Play size={12} />
                            )}
                            Run
                          </button>
                        </div>
                        {query.description && (
                          <p className="text-xs text-muted-foreground mb-2">{query.description}</p>
                        )}
                        <pre className="text-xs bg-background p-2 rounded overflow-x-auto">
                          {query.sql_query}
                        </pre>
                      </div>
                    ))
                  ) : (
                    <p className="text-sm text-muted-foreground italic">No queries defined</p>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-muted/30 rounded-lg border border-dashed p-8 flex flex-col items-center justify-center text-center">
              <Crosshair className="text-muted-foreground mb-4" size={48} />
              <p className="text-muted-foreground">Select a hunt to view details and run queries</p>
            </div>
          )}
        </div>
      )}

      {/* Custom Query Tab */}
      {activeTab === 'custom' && (
        <div className="space-y-4">
          <div className="bg-card rounded-lg border p-4 space-y-4">
            <h3 className="font-medium">Custom Hunt Query</h3>
            <textarea
              value={customQuery}
              onChange={(e) => setCustomQuery(e.target.value)}
              placeholder="Enter your SQL query here..."
              className="w-full h-48 px-4 py-3 bg-background border rounded-md font-mono text-sm"
            />
            <div className="flex justify-end gap-2">
              <button className="px-4 py-2 border rounded-md hover:bg-accent">
                <BookOpen size={14} className="inline mr-2" />
                Query Library
              </button>
              <button
                onClick={handleRunCustomQuery}
                disabled={isRunningCustomQuery || !customQuery.trim()}
                className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
              >
                {isRunningCustomQuery ? <RefreshCw size={16} className="animate-spin" /> : <Play size={16} />}
                Execute Query
              </button>
            </div>
          </div>

          {/* Custom Query Results */}
          {customQueryResult && (
            <div className="bg-card rounded-lg border p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-medium">Query Results</h3>
                <div className="flex items-center gap-3 text-xs text-muted-foreground">
                  <span>{customQueryResult.results?.length || 0} rows</span>
                  {customQueryResult.bytesScanned && (
                    <span>{(customQueryResult.bytesScanned / 1024 / 1024).toFixed(2)} MB scanned</span>
                  )}
                </div>
              </div>

              {customQueryResult.errorMessage ? (
                <div className="p-3 bg-red-500/10 border border-red-500/30 rounded text-sm text-red-400">
                  {customQueryResult.errorMessage}
                </div>
              ) : customQueryResult.results && customQueryResult.results.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b">
                        {customQueryResult.columns?.map((col) => (
                          <th key={col.name} className="text-left p-2 font-medium">
                            {col.name}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {customQueryResult.results.slice(0, 100).map((row, idx) => (
                        <tr key={idx} className="border-b border-muted/30">
                          {customQueryResult.columns?.map((col) => (
                            <td key={col.name} className="p-2 text-muted-foreground">
                              {String(row[col.name] ?? '')}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {customQueryResult.results.length > 100 && (
                    <p className="text-xs text-muted-foreground text-center mt-2">
                      Showing first 100 of {customQueryResult.results.length} results
                    </p>
                  )}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">No results found</p>
              )}
            </div>
          )}
        </div>
      )}

      {/* History Tab */}
      {activeTab === 'history' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="font-medium">Hunt Results</h3>
            {selectedHunt && (
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <span>Showing results for:</span>
                <span className="font-medium text-foreground">{selectedHunt.title}</span>
              </div>
            )}
          </div>

          {!selectedHunt ? (
            <div className="p-8 bg-muted/30 rounded-lg border border-dashed text-center">
              <History className="mx-auto text-muted-foreground mb-3" size={32} />
              <p className="text-sm text-muted-foreground">Select a hunt from the Hypotheses tab to view its results</p>
            </div>
          ) : resultsLoading ? (
            <div className="flex items-center justify-center p-8">
              <Loader2 className="animate-spin text-muted-foreground" size={32} />
            </div>
          ) : !huntResults || huntResults.length === 0 ? (
            <div className="p-8 bg-muted/30 rounded-lg border border-dashed text-center">
              <FileText className="mx-auto text-muted-foreground mb-3" size={32} />
              <p className="text-sm text-muted-foreground">No query results yet</p>
              <p className="text-xs text-muted-foreground mt-1">
                Run a query from the Hypotheses tab to see results here
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {huntResults.map((result) => (
                <div key={result.id} className="bg-card rounded-lg border p-4">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-3">
                      {result.status === 'completed' ? (
                        <CheckCircle className="text-green-400" size={18} />
                      ) : result.status === 'running' || result.status === 'pending' ? (
                        <RefreshCw className="text-blue-400 animate-spin" size={18} />
                      ) : (
                        <AlertTriangle className="text-red-400" size={18} />
                      )}
                      <span className="font-medium">{result.query_name || 'Query'}</span>
                      {result.simulated && (
                        <span
                          className="px-2 py-0.5 bg-yellow-500/20 text-yellow-400 rounded-full text-xs"
                          title="Produced by the built-in simulation, not a real data-lake query. Simulated findings are not evidence."
                        >
                          Simulated
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-3">
                      {result.execution_time_ms && (
                        <span className="text-xs text-muted-foreground">
                          {(result.execution_time_ms / 1000).toFixed(2)}s
                        </span>
                      )}
                      {result.executed_at && (
                        <span className="text-xs text-muted-foreground flex items-center gap-1">
                          <Clock size={10} />
                          {new Date(result.executed_at).toLocaleString()}
                        </span>
                      )}
                    </div>
                  </div>

                  {result.error_message ? (
                    <div className="p-2 bg-red-500/10 border border-red-500/30 rounded text-sm text-red-400">
                      {result.error_message}
                    </div>
                  ) : (
                    <>
                      <div className="flex items-center gap-4 text-sm">
                        <span className="text-muted-foreground">
                          {result.results_count} results found
                        </span>
                        {result.findings && result.findings.length > 0 && (
                          <span className="text-yellow-400 flex items-center gap-1">
                            <AlertTriangle size={12} />
                            {result.findings.length} findings
                          </span>
                        )}
                      </div>
                      {result.findings && result.findings.length > 0 && (
                        <div className="mt-3 pt-3 border-t space-y-2">
                          {result.findings.map((finding, index) => {
                            const findingData = finding as Record<string, unknown>
                            const severity = (findingData.severity as string) || 'medium'
                            const description = (findingData.description as string) || JSON.stringify(finding)
                            const evidence = findingData.evidence as string
                            return (
                              <div
                                key={index}
                                className={cn(
                                  'p-2 rounded text-sm',
                                  severity === 'critical' || severity === 'high'
                                    ? 'bg-red-500/10 border border-red-500/30'
                                    : 'bg-yellow-500/10 border border-yellow-500/30'
                                )}
                              >
                                <p className="font-medium">{description}</p>
                                {evidence && (
                                  <p className="text-xs text-muted-foreground mt-1">{evidence}</p>
                                )}
                              </div>
                            )
                          })}
                        </div>
                      )}
                    </>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
