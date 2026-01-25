import { useState, useEffect } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { ArrowLeft, Play, Save, ChevronDown, ChevronUp } from 'lucide-react'
import Editor from '@monaco-editor/react'
import {
  useGetRuleQuery,
  useCreateRuleMutation,
  useUpdateRuleMutation,
  useTestRuleMutation
} from '../api/pantherApi'
import type { Severity, RuleCreate, RuleUpdate } from '../types'
import TestCaseEditor, { TestCase } from '../components/rules/TestCaseEditor'
import TestResultsPanel from '../components/rules/TestResultsPanel'

const DEFAULT_RULE_CODE = `from panther_sdk.detections import Rule, Severity, LogType, deep_get

class MyDetectionRule(Rule):
    id = "Custom.MyRule"
    log_types = [LogType.AWS_CLOUDTRAIL]
    severity = Severity.MEDIUM
    threshold = 1
    dedup_period_minutes = 60

    def rule(self, event: dict) -> bool:
        # Add your detection logic here
        return False

    def title(self, event: dict) -> str:
        return f"Detection triggered"

    def dedup(self, event: dict) -> str:
        return self.id
`

export default function RuleEditorPage() {
  const { ruleId } = useParams<{ ruleId: string }>()
  const navigate = useNavigate()
  const isNew = !ruleId

  const { data: existingRule, isLoading } = useGetRuleQuery(ruleId!, { skip: isNew })

  const [createRule, { isLoading: isCreating }] = useCreateRuleMutation()
  const [updateRule, { isLoading: isUpdating }] = useUpdateRuleMutation()
  const [testRule, { isLoading: isTesting }] = useTestRuleMutation()

  const [formData, setFormData] = useState({
    id: '',
    displayName: '',
    description: '',
    severity: 'MEDIUM' as Severity,
    logTypes: ['AWS.CloudTrail'],
    enabled: true,
    threshold: 1,
    dedupPeriodMinutes: 60,
    tags: [] as string[],
  })
  const [code, setCode] = useState(DEFAULT_RULE_CODE)
  const [testResults, setTestResults] = useState<{ total: number; passed: number; failed: number; results: unknown[] } | null>(null)
  const [testCases, setTestCases] = useState<TestCase[]>([])
  const [testCaseResults, setTestCaseResults] = useState<Map<string, { passed: boolean; error?: string }>>(new Map())
  const [showTestPanel, setShowTestPanel] = useState(false)

  useEffect(() => {
    if (existingRule) {
      setFormData({
        id: existingRule.id,
        displayName: existingRule.displayName || '',
        description: existingRule.description || '',
        severity: existingRule.severity,
        logTypes: existingRule.logTypes,
        enabled: existingRule.enabled,
        threshold: existingRule.threshold,
        dedupPeriodMinutes: existingRule.dedupPeriodMinutes,
        tags: existingRule.tags,
      })
      setCode(existingRule.body || DEFAULT_RULE_CODE)
    }
  }, [existingRule])

  const handleSave = async () => {
    try {
      if (isNew) {
        const ruleData: RuleCreate = {
          id: formData.id,
          body: code,
          severity: formData.severity,
          logTypes: formData.logTypes,
          displayName: formData.displayName || undefined,
          description: formData.description || undefined,
          enabled: formData.enabled,
          threshold: formData.threshold,
          dedupPeriodMinutes: formData.dedupPeriodMinutes,
          tags: formData.tags,
        }
        await createRule(ruleData).unwrap()
        navigate('/rules')
      } else {
        const updateData: RuleUpdate = {
          body: code,
          severity: formData.severity,
          logTypes: formData.logTypes,
          displayName: formData.displayName || undefined,
          description: formData.description || undefined,
          enabled: formData.enabled,
          threshold: formData.threshold,
          dedupPeriodMinutes: formData.dedupPeriodMinutes,
          tags: formData.tags,
        }
        await updateRule({ id: ruleId!, update: updateData }).unwrap()
        navigate('/rules')
      }
    } catch (err) {
      console.error('Failed to save rule:', err)
    }
  }

  const handleTest = async () => {
    if (!ruleId) return
    try {
      const results = await testRule(ruleId).unwrap()
      setTestResults(results)
    } catch (err) {
      console.error('Failed to test rule:', err)
    }
  }

  const handleRunTestCases = async (cases: TestCase[]) => {
    // Run the standard test first
    if (ruleId) {
      await handleTest()
    }

    // Simulate running individual test cases
    // In production, this would call a backend endpoint
    const results = new Map<string, { passed: boolean; error?: string }>()
    for (const tc of cases) {
      try {
        // Parse the event to validate JSON
        JSON.parse(tc.event)
        // Simulate test execution - in production this would call the backend
        const passed = Math.random() > 0.3 // Mock result
        results.set(tc.id, { passed: passed === tc.expectedResult })
      } catch (err) {
        results.set(tc.id, { passed: false, error: 'Invalid JSON in test event' })
      }
    }
    setTestCaseResults(results)
  }

  if (!isNew && isLoading) {
    return <div className="p-6 text-center">Loading rule...</div>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Link to="/rules" className="p-2 hover:bg-accent rounded-md">
          <ArrowLeft size={20} />
        </Link>
        <div className="flex-1">
          <h1 className="text-2xl font-bold">{isNew ? 'New Rule' : 'Edit Rule'}</h1>
          {!isNew && <p className="text-muted-foreground">{ruleId}</p>}
        </div>
        <div className="flex gap-2">
          {!isNew && (
            <button
              onClick={handleTest}
              disabled={isTesting}
              className="flex items-center gap-2 px-4 py-2 border rounded-md text-sm font-medium hover:bg-accent disabled:opacity-50"
            >
              <Play size={16} />
              {isTesting ? 'Testing...' : 'Run Tests'}
            </button>
          )}
          <button
            onClick={handleSave}
            disabled={isCreating || isUpdating}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
          >
            <Save size={16} />
            {isCreating || isUpdating ? 'Saving...' : 'Save Rule'}
          </button>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Metadata Form */}
        <div className="space-y-4 rounded-lg border bg-background p-6">
          <h2 className="font-semibold">Rule Metadata</h2>

          {isNew && (
            <div>
              <label className="block text-sm font-medium mb-1">Rule ID *</label>
              <input
                type="text"
                value={formData.id}
                onChange={(e) => setFormData({ ...formData, id: e.target.value })}
                placeholder="Custom.MyRule"
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              />
            </div>
          )}

          <div>
            <label className="block text-sm font-medium mb-1">Display Name</label>
            <input
              type="text"
              value={formData.displayName}
              onChange={(e) => setFormData({ ...formData, displayName: e.target.value })}
              placeholder="My Detection Rule"
              className="w-full rounded-md border bg-background px-3 py-2 text-sm"
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">Description</label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              placeholder="What does this rule detect?"
              className="w-full rounded-md border bg-background px-3 py-2 text-sm h-20 resize-none"
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">Severity *</label>
            <select
              value={formData.severity}
              onChange={(e) => setFormData({ ...formData, severity: e.target.value as Severity })}
              className="w-full rounded-md border bg-background px-3 py-2 text-sm"
            >
              <option value="INFO">Info</option>
              <option value="LOW">Low</option>
              <option value="MEDIUM">Medium</option>
              <option value="HIGH">High</option>
              <option value="CRITICAL">Critical</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">Log Types *</label>
            <input
              type="text"
              value={formData.logTypes.join(', ')}
              onChange={(e) => setFormData({ ...formData, logTypes: e.target.value.split(',').map(s => s.trim()).filter(Boolean) })}
              placeholder="AWS.CloudTrail, Okta.SystemLog"
              className="w-full rounded-md border bg-background px-3 py-2 text-sm"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-1">Threshold</label>
              <input
                type="number"
                value={formData.threshold}
                onChange={(e) => setFormData({ ...formData, threshold: parseInt(e.target.value) || 1 })}
                min={1}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Dedup (min)</label>
              <input
                type="number"
                value={formData.dedupPeriodMinutes}
                onChange={(e) => setFormData({ ...formData, dedupPeriodMinutes: parseInt(e.target.value) || 60 })}
                min={1}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              />
            </div>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="enabled"
              checked={formData.enabled}
              onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
              className="rounded"
            />
            <label htmlFor="enabled" className="text-sm font-medium">Enabled</label>
          </div>
        </div>

        {/* Code Editor */}
        <div className="lg:col-span-2 space-y-4">
          <div className="rounded-lg border bg-background overflow-hidden">
            <div className="border-b px-4 py-2 bg-muted/50">
              <h2 className="font-semibold text-sm">Rule Code (Python)</h2>
            </div>
            <Editor
              height="400px"
              defaultLanguage="python"
              value={code}
              onChange={(value) => setCode(value || '')}
              theme="vs-dark"
              options={{
                minimap: { enabled: false },
                fontSize: 13,
                lineNumbers: 'on',
                scrollBeyondLastLine: false,
                automaticLayout: true,
              }}
            />
          </div>

          {/* Test Panel Toggle */}
          <button
            onClick={() => setShowTestPanel(!showTestPanel)}
            className="w-full flex items-center justify-between px-4 py-2 rounded-lg border bg-muted/50 hover:bg-muted transition-colors"
          >
            <span className="font-semibold text-sm">Rule Testing</span>
            {showTestPanel ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>

          {/* Test Panel */}
          {showTestPanel && (
            <div className="space-y-4">
              <TestCaseEditor
                testCases={testCases}
                onChange={setTestCases}
                onRunTests={handleRunTestCases}
                isRunning={isTesting}
                results={testCaseResults}
              />

              {/* Standard Test Results */}
              {testResults && (
                <TestResultsPanel
                  results={testCases.map((tc) => ({
                    testId: tc.id,
                    testName: tc.name,
                    passed: testCaseResults.get(tc.id)?.passed ?? false,
                    expected: tc.expectedResult,
                    actual: testCaseResults.get(tc.id)?.passed === tc.expectedResult,
                    error: testCaseResults.get(tc.id)?.error,
                  }))}
                  isRunning={isTesting}
                />
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
