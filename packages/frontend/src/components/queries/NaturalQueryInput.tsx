import { useState } from 'react'
import {
  Sparkles,
  Send,
  RefreshCw,
  History,
  Lightbulb,
  Code,
  ThumbsUp,
  ThumbsDown,
  ChevronDown,
  ChevronUp,
  X,
} from 'lucide-react'
import {
  useExecuteNaturalQueryMutation,
  useGetNLQueryHistoryQuery,
  useGetNLQueryExamplesQuery,
  useSubmitNLQueryFeedbackMutation,
  type NLQueryResponse,
} from '../../api/pantherApi'
import { cn } from '../../lib/utils'

interface NaturalQueryInputProps {
  onQueryResult?: (result: unknown) => void
  className?: string
}

export default function NaturalQueryInput({
  onQueryResult,
  className,
}: NaturalQueryInputProps) {
  const [query, setQuery] = useState('')
  const [showHistory, setShowHistory] = useState(false)
  const [showExamples, setShowExamples] = useState(false)
  const [showGeneratedSql, setShowGeneratedSql] = useState(false)
  const [currentResult, setCurrentResult] = useState<NLQueryResponse | null>(null)

  const [executeQuery, { isLoading }] = useExecuteNaturalQueryMutation()
  const { data: history } = useGetNLQueryHistoryQuery({ limit: 10 })
  const { data: examples } = useGetNLQueryExamplesQuery()
  const [submitFeedback] = useSubmitNLQueryFeedbackMutation()

  const handleSubmit = async (e?: React.FormEvent) => {
    e?.preventDefault()
    if (!query.trim()) return

    try {
      const result = await executeQuery({ query, execute: true }).unwrap()
      setCurrentResult(result)
      setShowGeneratedSql(true)
      if (onQueryResult && result.results) {
        onQueryResult(result.results)
      }
    } catch (err) {
      console.error('Query failed:', err)
    }
  }

  const handleExampleClick = (example: string) => {
    setQuery(example)
    setShowExamples(false)
  }

  const handleHistoryClick = (historicalQuery: string) => {
    setQuery(historicalQuery)
    setShowHistory(false)
  }

  const handleFeedback = async (wasHelpful: boolean) => {
    if (!currentResult) return
    try {
      await submitFeedback({
        queryId: currentResult.id,
        wasHelpful,
      }).unwrap()
    } catch (err) {
      console.error('Failed to submit feedback:', err)
    }
  }

  return (
    <div className={cn('space-y-4', className)}>
      {/* Input Form */}
      <form onSubmit={handleSubmit} className="relative">
        <div className="flex items-center gap-2 p-2 bg-card rounded-lg border focus-within:ring-2 focus-within:ring-primary/50">
          <Sparkles size={20} className="text-primary ml-2" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Ask in natural language... (e.g., 'Show critical alerts from last week')"
            className="flex-1 bg-transparent border-none outline-none text-sm py-2"
            disabled={isLoading}
          />
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => setShowExamples(!showExamples)}
              className="p-2 hover:bg-accent rounded-md"
              title="Show examples"
            >
              <Lightbulb size={16} className="text-muted-foreground" />
            </button>
            <button
              type="button"
              onClick={() => setShowHistory(!showHistory)}
              className="p-2 hover:bg-accent rounded-md"
              title="Query history"
            >
              <History size={16} className="text-muted-foreground" />
            </button>
            <button
              type="submit"
              disabled={isLoading || !query.trim()}
              className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
            >
              {isLoading ? (
                <RefreshCw size={16} className="animate-spin" />
              ) : (
                <Send size={16} />
              )}
              <span className="hidden sm:inline">Query</span>
            </button>
          </div>
        </div>

        {/* Examples Dropdown */}
        {showExamples && examples && (
          <div className="absolute top-full left-0 right-0 mt-2 bg-card rounded-lg border shadow-lg z-10 p-4">
            <div className="flex items-center justify-between mb-3">
              <h4 className="font-medium text-sm flex items-center gap-2">
                <Lightbulb size={14} />
                Example Queries
              </h4>
              <button onClick={() => setShowExamples(false)} className="p-1 hover:bg-accent rounded">
                <X size={14} />
              </button>
            </div>
            <div className="space-y-2">
              {examples.examples?.map((example, index) => (
                <button
                  key={index}
                  onClick={() => handleExampleClick(example.nl)}
                  className="w-full text-left p-2 hover:bg-accent rounded text-sm"
                >
                  <p className="font-medium">{example.nl}</p>
                  <p className="text-xs text-muted-foreground mt-1 font-mono truncate">
                    {example.sql}
                  </p>
                </button>
              ))}
            </div>
            {examples.tips && examples.tips.length > 0 && (
              <div className="mt-4 pt-3 border-t">
                <p className="text-xs font-medium text-muted-foreground mb-2">Tips:</p>
                <ul className="text-xs text-muted-foreground space-y-1">
                  {examples.tips.map((tip, i) => (
                    <li key={i}>• {tip}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {/* History Dropdown */}
        {showHistory && history && history.length > 0 && (
          <div className="absolute top-full left-0 right-0 mt-2 bg-card rounded-lg border shadow-lg z-10 p-4 max-h-64 overflow-y-auto">
            <div className="flex items-center justify-between mb-3">
              <h4 className="font-medium text-sm flex items-center gap-2">
                <History size={14} />
                Recent Queries
              </h4>
              <button onClick={() => setShowHistory(false)} className="p-1 hover:bg-accent rounded">
                <X size={14} />
              </button>
            </div>
            <div className="space-y-2">
              {history.map((item) => (
                <button
                  key={item.id}
                  onClick={() => handleHistoryClick(item.natural_query)}
                  className="w-full text-left p-2 hover:bg-accent rounded text-sm"
                >
                  <p>{item.natural_query}</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {new Date(item.created_at).toLocaleString()}
                  </p>
                </button>
              ))}
            </div>
          </div>
        )}
      </form>

      {/* Generated SQL & Results */}
      {currentResult && (
        <div className="bg-card rounded-lg border">
          <button
            onClick={() => setShowGeneratedSql(!showGeneratedSql)}
            className="w-full flex items-center justify-between p-3 hover:bg-accent/50"
          >
            <div className="flex items-center gap-2">
              <Code size={16} className="text-primary" />
              <span className="font-medium text-sm">Generated SQL</span>
            </div>
            {showGeneratedSql ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>

          {showGeneratedSql && (
            <div className="border-t p-4 space-y-4">
              {/* Explanation */}
              <p className="text-sm text-muted-foreground">{currentResult.explanation}</p>

              {/* SQL */}
              <div className="relative">
                <pre className="bg-muted p-4 rounded-lg text-sm overflow-x-auto font-mono">
                  {currentResult.generated_sql}
                </pre>
                <button
                  onClick={() => navigator.clipboard.writeText(currentResult.generated_sql)}
                  className="absolute top-2 right-2 px-2 py-1 bg-background/80 rounded text-xs hover:bg-background"
                >
                  Copy
                </button>
              </div>

              {/* Results Count */}
              {currentResult.row_count !== null && (
                <p className="text-sm text-muted-foreground">
                  {currentResult.row_count} rows returned
                </p>
              )}

              {/* Feedback */}
              <div className="flex items-center gap-4 pt-3 border-t">
                <span className="text-sm text-muted-foreground">Was this helpful?</span>
                <button
                  onClick={() => handleFeedback(true)}
                  className="flex items-center gap-1 px-3 py-1.5 bg-green-500/20 text-green-400 rounded hover:bg-green-500/30 text-sm"
                >
                  <ThumbsUp size={14} />
                  Yes
                </button>
                <button
                  onClick={() => handleFeedback(false)}
                  className="flex items-center gap-1 px-3 py-1.5 bg-red-500/20 text-red-400 rounded hover:bg-red-500/30 text-sm"
                >
                  <ThumbsDown size={14} />
                  No
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
