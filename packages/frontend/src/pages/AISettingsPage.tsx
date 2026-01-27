import { useState } from 'react'
import {
  Bot,
  Settings,
  CheckCircle,
  XCircle,
  Loader2,
  Eye,
  EyeOff,
} from 'lucide-react'
import {
  useGetAISettingsQuery,
  useTestAIConnectionMutation,
} from '../api/pantherApi'
import { cn } from '../lib/utils'

export default function AISettingsPage() {
  const { data: settings, isLoading, refetch } = useGetAISettingsQuery()
  const [testConnection, { isLoading: isTesting }] = useTestAIConnectionMutation()
  const [testResults, setTestResults] = useState<Record<string, { status: string; message: string }>>({})

  const handleTest = async (provider: string) => {
    const result = await testConnection(provider).unwrap()
    setTestResults(prev => ({ ...prev, [provider]: result }))
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="animate-spin" size={32} />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-semibold flex items-center gap-2">
          <Bot size={24} />
          AI Settings
        </h1>
        <p className="text-muted-foreground mt-1">
          Configure LLM providers for AI-powered alert and incident summarization
        </p>
      </div>

      {/* Current Configuration */}
      <div className="bg-card rounded-lg border p-6">
        <h2 className="text-lg font-semibold mb-4">Current Configuration</h2>
        <div className="flex items-center gap-2 text-sm">
          <span className="text-muted-foreground">Default Provider:</span>
          <span className="font-medium capitalize">{settings?.default_provider || 'Not set'}</span>
        </div>
        <p className="text-xs text-muted-foreground mt-2">
          Configure API keys in your environment variables or .env file
        </p>
      </div>

      {/* Provider Cards */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* OpenAI */}
        <div className="bg-card rounded-lg border overflow-hidden">
          <div className="p-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-green-500/10 rounded-lg flex items-center justify-center">
                  <span className="text-green-500 font-bold">AI</span>
                </div>
                <div>
                  <h3 className="font-semibold">OpenAI</h3>
                  <p className="text-sm text-muted-foreground">GPT-4 and GPT-3.5 models</p>
                </div>
              </div>
              {settings?.openai.configured ? (
                <span className="flex items-center gap-1 text-green-500 text-sm">
                  <CheckCircle size={16} />
                  Configured
                </span>
              ) : (
                <span className="flex items-center gap-1 text-muted-foreground text-sm">
                  <XCircle size={16} />
                  Not Configured
                </span>
              )}
            </div>

            <div className="mt-4 space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Model:</span>
                <span>{settings?.openai.model || 'gpt-4'}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">API Key:</span>
                <span className="font-mono text-xs">
                  {settings?.openai.configured ? '••••••••••••••••' : 'Not set'}
                </span>
              </div>
            </div>

            <div className="mt-4 pt-4 border-t">
              <button
                onClick={() => handleTest('openai')}
                disabled={!settings?.openai.configured || isTesting}
                className="w-full px-4 py-2 bg-accent hover:bg-accent/80 rounded-md text-sm disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {isTesting ? <Loader2 size={14} className="animate-spin" /> : null}
                Test Connection
              </button>
              {testResults.openai && (
                <p className={cn(
                  'text-sm mt-2 text-center',
                  testResults.openai.status === 'success' ? 'text-green-500' : 'text-red-500'
                )}>
                  {testResults.openai.message}
                </p>
              )}
            </div>
          </div>
          <div className="bg-muted/30 px-6 py-3 text-xs text-muted-foreground">
            Set OPENAI_API_KEY environment variable
          </div>
        </div>

        {/* Anthropic */}
        <div className="bg-card rounded-lg border overflow-hidden">
          <div className="p-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-orange-500/10 rounded-lg flex items-center justify-center">
                  <span className="text-orange-500 font-bold">A</span>
                </div>
                <div>
                  <h3 className="font-semibold">Anthropic</h3>
                  <p className="text-sm text-muted-foreground">Claude 3 models</p>
                </div>
              </div>
              {settings?.anthropic.configured ? (
                <span className="flex items-center gap-1 text-green-500 text-sm">
                  <CheckCircle size={16} />
                  Configured
                </span>
              ) : (
                <span className="flex items-center gap-1 text-muted-foreground text-sm">
                  <XCircle size={16} />
                  Not Configured
                </span>
              )}
            </div>

            <div className="mt-4 space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Model:</span>
                <span>{settings?.anthropic.model || 'claude-3-sonnet'}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">API Key:</span>
                <span className="font-mono text-xs">
                  {settings?.anthropic.configured ? '••••••••••••••••' : 'Not set'}
                </span>
              </div>
            </div>

            <div className="mt-4 pt-4 border-t">
              <button
                onClick={() => handleTest('anthropic')}
                disabled={!settings?.anthropic.configured || isTesting}
                className="w-full px-4 py-2 bg-accent hover:bg-accent/80 rounded-md text-sm disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {isTesting ? <Loader2 size={14} className="animate-spin" /> : null}
                Test Connection
              </button>
              {testResults.anthropic && (
                <p className={cn(
                  'text-sm mt-2 text-center',
                  testResults.anthropic.status === 'success' ? 'text-green-500' : 'text-red-500'
                )}>
                  {testResults.anthropic.message}
                </p>
              )}
            </div>
          </div>
          <div className="bg-muted/30 px-6 py-3 text-xs text-muted-foreground">
            Set ANTHROPIC_API_KEY environment variable
          </div>
        </div>
      </div>

      {/* Usage Information */}
      <div className="bg-card rounded-lg border p-6">
        <h2 className="text-lg font-semibold mb-4">How to Use AI Summarization</h2>
        <div className="space-y-4 text-sm text-muted-foreground">
          <p>
            Once configured, you can generate AI summaries for alerts and incidents:
          </p>
          <ul className="list-disc list-inside space-y-2">
            <li>Open an alert detail page and click "Generate AI Summary"</li>
            <li>Open an incident detail page and click "Generate AI Summary"</li>
            <li>Summaries are cached for 24 hours to reduce API costs</li>
            <li>Use "Regenerate" to force a fresh summary</li>
          </ul>
          <p className="mt-4">
            <strong>Cost considerations:</strong> Each summary uses approximately 500-2000 tokens depending on the alert/incident complexity.
          </p>
        </div>
      </div>

      {/* Configuration Instructions */}
      <div className="bg-card rounded-lg border p-6">
        <h2 className="text-lg font-semibold mb-4">Configuration Instructions</h2>
        <div className="space-y-4">
          <div>
            <h3 className="font-medium mb-2">Environment Variables</h3>
            <pre className="bg-muted p-4 rounded-md text-sm overflow-x-auto">
{`# OpenAI Configuration
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4  # or gpt-3.5-turbo

# Anthropic Configuration
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-3-sonnet-20240229

# Default Provider (openai or anthropic)
DEFAULT_LLM_PROVIDER=openai`}
            </pre>
          </div>
          <p className="text-sm text-muted-foreground">
            Add these to your <code className="bg-muted px-1 rounded">.env</code> file and restart the backend server.
          </p>
        </div>
      </div>
    </div>
  )
}
