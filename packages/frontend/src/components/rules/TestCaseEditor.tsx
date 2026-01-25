import { useState } from 'react'
import { Plus, Trash2, Play, CheckCircle, XCircle } from 'lucide-react'
import Editor from '@monaco-editor/react'
import { cn } from '../../lib/utils'

export interface TestCase {
  id: string
  name: string
  event: string
  expectedResult: boolean
}

interface TestCaseEditorProps {
  testCases: TestCase[]
  onChange: (testCases: TestCase[]) => void
  onRunTests: (testCases: TestCase[]) => void
  isRunning: boolean
  results?: Map<string, { passed: boolean; error?: string }>
}

const DEFAULT_EVENT = `{
  "eventVersion": "1.08",
  "eventSource": "ec2.amazonaws.com",
  "eventName": "DescribeInstances",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "1.2.3.4",
  "userAgent": "console.amazonaws.com",
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROAEXAMPLE:user@example.com",
    "arn": "arn:aws:sts::123456789012:assumed-role/MyRole/user@example.com"
  }
}`

export default function TestCaseEditor({
  testCases,
  onChange,
  onRunTests,
  isRunning,
  results,
}: TestCaseEditorProps) {
  const [activeCase, setActiveCase] = useState<string | null>(
    testCases.length > 0 ? testCases[0].id : null
  )

  const addTestCase = () => {
    const newCase: TestCase = {
      id: `test_${Date.now()}`,
      name: `Test Case ${testCases.length + 1}`,
      event: DEFAULT_EVENT,
      expectedResult: true,
    }
    onChange([...testCases, newCase])
    setActiveCase(newCase.id)
  }

  const updateTestCase = (id: string, updates: Partial<TestCase>) => {
    onChange(
      testCases.map((tc) => (tc.id === id ? { ...tc, ...updates } : tc))
    )
  }

  const removeTestCase = (id: string) => {
    const updated = testCases.filter((tc) => tc.id !== id)
    onChange(updated)
    if (activeCase === id) {
      setActiveCase(updated.length > 0 ? updated[0].id : null)
    }
  }

  const activeTestCase = testCases.find((tc) => tc.id === activeCase)

  return (
    <div className="rounded-lg border bg-background">
      <div className="flex items-center justify-between border-b px-4 py-2 bg-muted/50">
        <h3 className="font-semibold text-sm">Test Cases</h3>
        <div className="flex items-center gap-2">
          <button
            onClick={addTestCase}
            className="flex items-center gap-1 px-2 py-1 text-xs bg-muted hover:bg-accent rounded"
          >
            <Plus size={14} />
            Add Test
          </button>
          <button
            onClick={() => onRunTests(testCases)}
            disabled={isRunning || testCases.length === 0}
            className="flex items-center gap-1 px-2 py-1 text-xs bg-primary text-primary-foreground rounded hover:bg-primary/90 disabled:opacity-50"
          >
            <Play size={14} />
            {isRunning ? 'Running...' : 'Run All'}
          </button>
        </div>
      </div>

      {testCases.length === 0 ? (
        <div className="p-6 text-center text-muted-foreground">
          <p className="text-sm">No test cases defined</p>
          <p className="text-xs mt-1">Add test cases to validate your rule</p>
        </div>
      ) : (
        <div className="flex">
          {/* Test case list */}
          <div className="w-48 border-r flex-shrink-0">
            {testCases.map((tc) => {
              const result = results?.get(tc.id)
              return (
                <button
                  key={tc.id}
                  onClick={() => setActiveCase(tc.id)}
                  className={cn(
                    "w-full flex items-center gap-2 px-3 py-2 text-sm text-left hover:bg-muted border-b last:border-b-0",
                    activeCase === tc.id && "bg-muted"
                  )}
                >
                  {result !== undefined && (
                    result.passed ? (
                      <CheckCircle size={14} className="text-green-400 shrink-0" />
                    ) : (
                      <XCircle size={14} className="text-red-400 shrink-0" />
                    )
                  )}
                  <span className="truncate flex-1">{tc.name}</span>
                </button>
              )
            })}
          </div>

          {/* Active test case editor */}
          {activeTestCase && (
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between px-4 py-2 border-b bg-muted/30">
                <input
                  type="text"
                  value={activeTestCase.name}
                  onChange={(e) => updateTestCase(activeTestCase.id, { name: e.target.value })}
                  className="bg-transparent border-none text-sm font-medium focus:outline-none"
                />
                <div className="flex items-center gap-2">
                  <label className="flex items-center gap-1 text-xs">
                    <span>Expected:</span>
                    <select
                      value={activeTestCase.expectedResult.toString()}
                      onChange={(e) => updateTestCase(activeTestCase.id, {
                        expectedResult: e.target.value === 'true',
                      })}
                      className="bg-background border rounded px-1 py-0.5 text-xs"
                    >
                      <option value="true">Match</option>
                      <option value="false">No Match</option>
                    </select>
                  </label>
                  <button
                    onClick={() => removeTestCase(activeTestCase.id)}
                    className="p-1 hover:bg-accent rounded text-red-400"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>

              {/* Event JSON editor */}
              <div className="h-64">
                <Editor
                  height="100%"
                  defaultLanguage="json"
                  value={activeTestCase.event}
                  onChange={(value) => updateTestCase(activeTestCase.id, { event: value || '{}' })}
                  theme="vs-dark"
                  options={{
                    minimap: { enabled: false },
                    fontSize: 12,
                    lineNumbers: 'on',
                    scrollBeyondLastLine: false,
                    automaticLayout: true,
                    formatOnPaste: true,
                  }}
                />
              </div>

              {/* Result for this test case */}
              {results?.has(activeTestCase.id) && (
                <div className={cn(
                  "px-4 py-2 text-sm border-t",
                  results.get(activeTestCase.id)?.passed
                    ? "bg-green-500/10 text-green-400"
                    : "bg-red-500/10 text-red-400"
                )}>
                  {results.get(activeTestCase.id)?.passed ? (
                    <span>Test passed</span>
                  ) : (
                    <span>
                      Test failed
                      {results.get(activeTestCase.id)?.error && (
                        <span className="ml-2">: {results.get(activeTestCase.id)?.error}</span>
                      )}
                    </span>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
