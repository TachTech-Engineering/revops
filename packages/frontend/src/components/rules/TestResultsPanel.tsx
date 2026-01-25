import { CheckCircle, XCircle, AlertCircle, Clock } from 'lucide-react'
import { cn } from '../../lib/utils'

interface TestResult {
  testId: string
  testName: string
  passed: boolean
  expected: boolean
  actual: boolean
  executionTime?: number
  error?: string
}

interface TestResultsPanelProps {
  results: TestResult[]
  isRunning: boolean
}

export default function TestResultsPanel({ results, isRunning }: TestResultsPanelProps) {
  const total = results.length
  const passed = results.filter((r) => r.passed).length
  const failed = total - passed

  return (
    <div className="rounded-lg border bg-background">
      <div className="flex items-center justify-between border-b px-4 py-2 bg-muted/50">
        <h3 className="font-semibold text-sm">Test Results</h3>
        {isRunning ? (
          <div className="flex items-center gap-1 text-xs text-muted-foreground">
            <Clock size={14} className="animate-spin" />
            Running tests...
          </div>
        ) : total > 0 ? (
          <div className="flex items-center gap-3 text-xs">
            <span className="flex items-center gap-1">
              <span className="font-medium">{total}</span> Total
            </span>
            <span className="flex items-center gap-1 text-green-400">
              <CheckCircle size={14} />
              <span className="font-medium">{passed}</span> Passed
            </span>
            <span className="flex items-center gap-1 text-red-400">
              <XCircle size={14} />
              <span className="font-medium">{failed}</span> Failed
            </span>
          </div>
        ) : null}
      </div>

      {total === 0 && !isRunning ? (
        <div className="p-6 text-center text-muted-foreground">
          <AlertCircle size={24} className="mx-auto mb-2 opacity-40" />
          <p className="text-sm">No test results yet</p>
          <p className="text-xs mt-1">Run tests to see results here</p>
        </div>
      ) : (
        <div className="divide-y max-h-64 overflow-auto">
          {results.map((result) => (
            <div
              key={result.testId}
              className={cn(
                "px-4 py-3 flex items-start gap-3",
                result.passed ? "bg-green-500/5" : "bg-red-500/5"
              )}
            >
              {result.passed ? (
                <CheckCircle size={18} className="text-green-400 mt-0.5 shrink-0" />
              ) : (
                <XCircle size={18} className="text-red-400 mt-0.5 shrink-0" />
              )}
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <span className="font-medium text-sm">{result.testName}</span>
                  {result.executionTime !== undefined && (
                    <span className="text-xs text-muted-foreground">
                      {result.executionTime}ms
                    </span>
                  )}
                </div>
                {!result.passed && (
                  <div className="mt-1 text-xs text-muted-foreground">
                    <span>
                      Expected: <span className="font-mono">{result.expected ? 'match' : 'no match'}</span>
                    </span>
                    <span className="mx-2">|</span>
                    <span>
                      Actual: <span className="font-mono">{result.actual ? 'match' : 'no match'}</span>
                    </span>
                  </div>
                )}
                {result.error && (
                  <div className="mt-1 text-xs text-red-400 font-mono bg-red-500/10 p-2 rounded">
                    {result.error}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Summary bar */}
      {total > 0 && !isRunning && (
        <div className="border-t px-4 py-2 bg-muted/30">
          <div className="flex items-center gap-2">
            <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
              <div
                className="h-full bg-green-500 transition-all"
                style={{ width: `${(passed / total) * 100}%` }}
              />
            </div>
            <span className="text-xs text-muted-foreground">
              {Math.round((passed / total) * 100)}% passing
            </span>
          </div>
        </div>
      )}
    </div>
  )
}
