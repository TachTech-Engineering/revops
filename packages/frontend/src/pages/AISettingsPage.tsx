import { useState } from 'react'
import {
  Bot,
  CheckCircle,
  XCircle,
  Loader2,
  Eye,
  EyeOff,
  Key,
  Trash2,
  Save,
  AlertCircle,
} from 'lucide-react'
import {
  useGetAISettingsQuery,
  useTestAIConnectionMutation,
  useSaveAPIKeyMutation,
  useDeleteAPIKeyMutation,
  useTestOrganizationAPIKeyMutation,
  useTestAPIKeyDirectMutation,
} from '../api/pantherApi'
import { cn } from '../lib/utils'

export default function AISettingsPage() {
  const { data: settings, isLoading, refetch } = useGetAISettingsQuery()
  const [testConnection] = useTestAIConnectionMutation()
  const [saveAPIKey, { isLoading: isSaving }] = useSaveAPIKeyMutation()
  const [deleteAPIKey, { isLoading: isDeleting }] = useDeleteAPIKeyMutation()
  const [testOrgKey, { isLoading: isTestingOrg }] = useTestOrganizationAPIKeyMutation()
  const [testKeyDirect, { isLoading: isTestingDirect }] = useTestAPIKeyDirectMutation()

  const [testResults, setTestResults] = useState<Record<string, { status: string; message: string }>>({})
  const [showOpenAIKey, setShowOpenAIKey] = useState(false)
  const [showAnthropicKey, setShowAnthropicKey] = useState(false)
  const [openaiKey, setOpenaiKey] = useState('')
  const [anthropicKey, setAnthropicKey] = useState('')
  const [openaiModel, setOpenaiModel] = useState('')
  const [anthropicModel, setAnthropicModel] = useState('')
  const [saveError, setSaveError] = useState<string | null>(null)
  const [saveSuccess, setSaveSuccess] = useState<string | null>(null)

  // Check if organization has configured keys
  const orgOpenAI = settings?.organization_keys?.find(k => k.provider === 'openai')
  const orgAnthropic = settings?.organization_keys?.find(k => k.provider === 'anthropic')

  const handleTest = async (provider: string) => {
    // Test organization key if configured, otherwise test env key
    const orgKey = settings?.organization_keys?.find(k => k.provider === provider)
    try {
      let result
      if (orgKey) {
        result = await testOrgKey(provider).unwrap()
      } else {
        result = await testConnection(provider).unwrap()
      }
      setTestResults(prev => ({ ...prev, [provider]: result }))
    } catch (err) {
      const detail = (err as { data?: { detail?: string } }).data?.detail
      setTestResults(prev => ({
        ...prev,
        [provider]: { status: 'error', message: detail || 'Test failed' }
      }))
    }
  }


  const handleTestAndSave = async (provider: string) => {
    setSaveError(null)
    setSaveSuccess(null)

    const key = provider === 'openai' ? openaiKey : anthropicKey
    const model = provider === 'openai' ? openaiModel : anthropicModel

    if (!key.trim()) {
      setSaveError(`Please enter an API key for ${provider}`)
      return
    }

    try {
      // First test the key
      const testResult = await testKeyDirect({
        provider,
        api_key: key,
        model: model || undefined,
      }).unwrap()

      if (testResult.status !== 'success') {
        setSaveError(testResult.message || 'API key test failed')
        setTestResults(prev => ({ ...prev, [provider]: testResult }))
        return
      }

      // If test passed, save the key
      await saveAPIKey({
        provider,
        api_key: key,
        model: model || undefined,
      }).unwrap()

      setSaveSuccess(`${provider} API key tested and saved successfully!`)
      setTestResults(prev => ({ ...prev, [provider]: { status: 'success', message: 'Key verified and saved' } }))

      // Clear the input
      if (provider === 'openai') {
        setOpenaiKey('')
        setOpenaiModel('')
      } else {
        setAnthropicKey('')
        setAnthropicModel('')
      }
      refetch()

      setTimeout(() => setSaveSuccess(null), 3000)
    } catch (err) {
      const detail = (err as { data?: { detail?: string } }).data?.detail
      setSaveError(detail || `Failed to test/save ${provider} API key`)
      setTestResults(prev => ({
        ...prev,
        [provider]: { status: 'error', message: detail || 'Test failed' }
      }))
    }
  }

  const handleDeleteKey = async (provider: string) => {
    if (!confirm(`Are you sure you want to delete the ${provider} API key?`)) {
      return
    }

    setSaveError(null)
    try {
      await deleteAPIKey(provider).unwrap()
      setSaveSuccess(`${provider} API key deleted successfully`)
      setTestResults(prev => {
        const newResults = { ...prev }
        delete newResults[provider]
        return newResults
      })
      refetch()
      setTimeout(() => setSaveSuccess(null), 3000)
    } catch (err) {
      setSaveError((err as { data?: { detail?: string } }).data?.detail || `Failed to delete ${provider} API key`)
    }
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
          Configure LLM providers for AI-powered features like summarization and rule conversion
        </p>
      </div>

      {/* Status Messages */}
      {saveError && (
        <div className="flex items-center gap-2 p-3 rounded-md bg-destructive/10 text-destructive">
          <AlertCircle size={16} />
          {saveError}
        </div>
      )}
      {saveSuccess && (
        <div className="flex items-center gap-2 p-3 rounded-md bg-green-500/10 text-green-500">
          <CheckCircle size={16} />
          {saveSuccess}
        </div>
      )}

      {/* Configuration Notice */}
      <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
        <h3 className="font-medium text-blue-500 mb-2">How API Keys Work</h3>
        <p className="text-sm text-muted-foreground">
          You can configure API keys in two ways:
        </p>
        <ul className="list-disc list-inside text-sm text-muted-foreground mt-2 space-y-1">
          <li><strong>Organization Keys (Recommended)</strong>: Enter your API keys below. These are encrypted and stored securely for your organization.</li>
          <li><strong>Environment Variables</strong>: System administrators can set API keys via environment variables (OPENAI_API_KEY, ANTHROPIC_API_KEY).</li>
        </ul>
        <p className="text-sm text-muted-foreground mt-2">
          Organization keys take priority over environment variables when both are configured.
        </p>
      </div>

      {/* Provider Cards */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* OpenAI */}
        <div className="bg-card rounded-lg border overflow-hidden">
          <div className="p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-green-500/10 rounded-lg flex items-center justify-center">
                  <span className="text-green-500 font-bold">AI</span>
                </div>
                <div>
                  <h3 className="font-semibold">OpenAI</h3>
                  <p className="text-sm text-muted-foreground">GPT-4 and GPT-3.5 models</p>
                </div>
              </div>
              {orgOpenAI?.configured ? (
                <span className="flex items-center gap-1 text-green-500 text-sm">
                  <CheckCircle size={16} />
                  Org Key Set
                </span>
              ) : settings?.openai.configured ? (
                <span className="flex items-center gap-1 text-yellow-500 text-sm">
                  <CheckCircle size={16} />
                  Env Key Set
                </span>
              ) : (
                <span className="flex items-center gap-1 text-muted-foreground text-sm">
                  <XCircle size={16} />
                  Not Configured
                </span>
              )}
            </div>

            {/* Current Status */}
            <div className="space-y-3 mb-4">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Model:</span>
                <span>{orgOpenAI?.model || settings?.openai.model || 'gpt-4'}</span>
              </div>
              {orgOpenAI && (
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Last Used:</span>
                  <span>{orgOpenAI.last_used_at ? new Date(orgOpenAI.last_used_at).toLocaleString() : 'Never'}</span>
                </div>
              )}
            </div>

            {/* API Key Input */}
            <div className="space-y-3 border-t pt-4">
              <div>
                <label className="block text-sm font-medium mb-1 flex items-center gap-2">
                  <Key size={14} />
                  {orgOpenAI ? 'Update API Key' : 'Add API Key'}
                </label>
                <div className="relative">
                  <input
                    type={showOpenAIKey ? 'text' : 'password'}
                    value={openaiKey}
                    onChange={(e) => setOpenaiKey(e.target.value)}
                    placeholder="sk-..."
                    className="w-full rounded-md border bg-background px-3 py-2 text-sm pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowOpenAIKey(!showOpenAIKey)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    {showOpenAIKey ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Model (Optional)</label>
                <select
                  value={openaiModel}
                  onChange={(e) => setOpenaiModel(e.target.value)}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                >
                  <option value="">Use default (gpt-4)</option>
                  <option value="gpt-4">GPT-4</option>
                  <option value="gpt-4-turbo">GPT-4 Turbo</option>
                  <option value="gpt-4o">GPT-4o</option>
                  <option value="gpt-4o-mini">GPT-4o Mini</option>
                  <option value="gpt-3.5-turbo">GPT-3.5 Turbo</option>
                </select>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => handleTestAndSave('openai')}
                  disabled={isSaving || isTestingDirect || !openaiKey.trim()}
                  className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
                >
                  {(isSaving || isTestingDirect) ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
                  Test & Save
                </button>
                {orgOpenAI && (
                  <button
                    onClick={() => handleDeleteKey('openai')}
                    disabled={isDeleting}
                    className="px-4 py-2 border border-destructive text-destructive rounded-md hover:bg-destructive/10 disabled:opacity-50"
                  >
                    <Trash2 size={14} />
                  </button>
                )}
              </div>
            </div>

            {/* Test Saved Key */}
            <div className="mt-4 pt-4 border-t">
              <button
                onClick={() => handleTest('openai')}
                disabled={!orgOpenAI?.configured && !settings?.openai.configured}
                className="w-full px-4 py-2 bg-accent hover:bg-accent/80 rounded-md text-sm disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {isTestingOrg ? <Loader2 size={14} className="animate-spin" /> : null}
                Test Saved Key
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
        </div>

        {/* Anthropic */}
        <div className="bg-card rounded-lg border overflow-hidden">
          <div className="p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-orange-500/10 rounded-lg flex items-center justify-center">
                  <span className="text-orange-500 font-bold">A</span>
                </div>
                <div>
                  <h3 className="font-semibold">Anthropic</h3>
                  <p className="text-sm text-muted-foreground">Sonnet &amp; Opus models</p>
                </div>
              </div>
              {orgAnthropic?.configured ? (
                <span className="flex items-center gap-1 text-green-500 text-sm">
                  <CheckCircle size={16} />
                  Org Key Set
                </span>
              ) : settings?.anthropic.configured ? (
                <span className="flex items-center gap-1 text-yellow-500 text-sm">
                  <CheckCircle size={16} />
                  Env Key Set
                </span>
              ) : (
                <span className="flex items-center gap-1 text-muted-foreground text-sm">
                  <XCircle size={16} />
                  Not Configured
                </span>
              )}
            </div>

            {/* Current Status */}
            <div className="space-y-3 mb-4">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Model:</span>
                <span>{orgAnthropic?.model || settings?.anthropic.model || 'sonnet-4'}</span>
              </div>
              {orgAnthropic && (
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Last Used:</span>
                  <span>{orgAnthropic.last_used_at ? new Date(orgAnthropic.last_used_at).toLocaleString() : 'Never'}</span>
                </div>
              )}
            </div>

            {/* API Key Input */}
            <div className="space-y-3 border-t pt-4">
              <div>
                <label className="block text-sm font-medium mb-1 flex items-center gap-2">
                  <Key size={14} />
                  {orgAnthropic ? 'Update API Key' : 'Add API Key'}
                </label>
                <div className="relative">
                  <input
                    type={showAnthropicKey ? 'text' : 'password'}
                    value={anthropicKey}
                    onChange={(e) => setAnthropicKey(e.target.value)}
                    placeholder="sk-ant-..."
                    className="w-full rounded-md border bg-background px-3 py-2 text-sm pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowAnthropicKey(!showAnthropicKey)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    {showAnthropicKey ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Model (Optional)</label>
                <select
                  value={anthropicModel}
                  onChange={(e) => setAnthropicModel(e.target.value)}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                >
                  <option value="">Use default (Sonnet 4)</option>
                  <option value="claude-opus-4-5-20251101">Opus 4.5 (Latest)</option>
                  <option value="claude-sonnet-4-20250514">Sonnet 4</option>
                  <option value="claude-3-5-sonnet-20241022">Sonnet 3.5</option>
                  <option value="claude-3-opus-20240229">Opus 3</option>
                  <option value="claude-3-haiku-20240307">Haiku 3</option>
                </select>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => handleTestAndSave('anthropic')}
                  disabled={isSaving || isTestingDirect || !anthropicKey.trim()}
                  className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
                >
                  {(isSaving || isTestingDirect) ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
                  Test & Save
                </button>
                {orgAnthropic && (
                  <button
                    onClick={() => handleDeleteKey('anthropic')}
                    disabled={isDeleting}
                    className="px-4 py-2 border border-destructive text-destructive rounded-md hover:bg-destructive/10 disabled:opacity-50"
                  >
                    <Trash2 size={14} />
                  </button>
                )}
              </div>
            </div>

            {/* Test Saved Key */}
            <div className="mt-4 pt-4 border-t">
              <button
                onClick={() => handleTest('anthropic')}
                disabled={!orgAnthropic?.configured && !settings?.anthropic.configured}
                className="w-full px-4 py-2 bg-accent hover:bg-accent/80 rounded-md text-sm disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {isTestingOrg ? <Loader2 size={14} className="animate-spin" /> : null}
                Test Saved Key
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
        </div>
      </div>

      {/* Usage Information */}
      <div className="bg-card rounded-lg border p-6">
        <h2 className="text-lg font-semibold mb-4">How to Use AI Features</h2>
        <div className="space-y-4 text-sm text-muted-foreground">
          <p>
            Once an API key is configured, you can use AI-powered features throughout the platform:
          </p>
          <ul className="list-disc list-inside space-y-2">
            <li><strong>Alert Summarization</strong>: Open an alert detail page and click "Generate AI Summary"</li>
            <li><strong>Incident Analysis</strong>: Open an incident detail page and click "Generate AI Summary"</li>
            <li><strong>Rule Conversion</strong>: Use the Migration Hub to convert rules between SIEM formats</li>
            <li><strong>AI Chat</strong>: Use the AI assistant to ask questions about alerts and detections</li>
          </ul>
          <p className="mt-4">
            <strong>Cost considerations:</strong> Each AI operation uses API tokens. OpenAI and Anthropic charge based on token usage.
            Summaries are cached for 24 hours to reduce costs.
          </p>
        </div>
      </div>

      {/* Getting API Keys */}
      <div className="bg-card rounded-lg border p-6">
        <h2 className="text-lg font-semibold mb-4">Getting API Keys</h2>
        <div className="grid md:grid-cols-2 gap-6">
          <div>
            <h3 className="font-medium mb-2 flex items-center gap-2">
              <span className="w-6 h-6 bg-green-500/10 rounded flex items-center justify-center text-xs text-green-500 font-bold">AI</span>
              OpenAI
            </h3>
            <ol className="list-decimal list-inside text-sm text-muted-foreground space-y-1">
              <li>Go to <a href="https://platform.openai.com" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">platform.openai.com</a></li>
              <li>Sign in or create an account</li>
              <li>Navigate to API Keys section</li>
              <li>Create a new secret key</li>
              <li>Copy and paste the key above</li>
            </ol>
          </div>
          <div>
            <h3 className="font-medium mb-2 flex items-center gap-2">
              <span className="w-6 h-6 bg-orange-500/10 rounded flex items-center justify-center text-xs text-orange-500 font-bold">A</span>
              Anthropic
            </h3>
            <ol className="list-decimal list-inside text-sm text-muted-foreground space-y-1">
              <li>Go to <a href="https://console.anthropic.com" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">console.anthropic.com</a></li>
              <li>Sign in or create an account</li>
              <li>Navigate to API Keys section</li>
              <li>Create a new API key</li>
              <li>Copy and paste the key above</li>
            </ol>
          </div>
        </div>
      </div>
    </div>
  )
}
