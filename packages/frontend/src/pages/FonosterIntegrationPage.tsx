import { useState } from 'react'
import {
  Phone,
  Settings,
  CheckCircle,
  XCircle,
  RefreshCw,
  PhoneCall,
  MessageSquare,
  Volume2,
  AlertTriangle,
} from 'lucide-react'
import { cn } from '../lib/utils'

interface TelephonyConfig {
  provider: 'mock' | 'twilio'
  // Mock settings
  mockEndpoint: string
  // Twilio settings
  twilioAccountSid: string
  twilioAuthToken: string
  twilioPhoneNumber: string
  // Common
  ttsVoice: string
  enabled: boolean
}

export default function FonosterIntegrationPage() {
  const [config, setConfig] = useState<TelephonyConfig>({
    provider: 'mock',
    mockEndpoint: 'http://localhost:50051',
    twilioAccountSid: '',
    twilioAuthToken: '',
    twilioPhoneNumber: '',
    ttsVoice: 'alice',
    enabled: true,
  })

  const [isTesting, setIsTesting] = useState(false)
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null)
  const [testPhoneNumber, setTestPhoneNumber] = useState('')
  const [isSaving, setIsSaving] = useState(false)

  const handleTest = async () => {
    if (!testPhoneNumber) {
      setTestResult({ success: false, message: 'Please enter a phone number to test' })
      return
    }

    setIsTesting(true)
    setTestResult(null)

    try {
      // Simulate API call to test the connection
      await new Promise((resolve) => setTimeout(resolve, 2000))

      // In real implementation, this would call the backend to test Fonoster connection
      setTestResult({
        success: true,
        message: `Test call initiated to ${testPhoneNumber}. Check your phone!`,
      })
    } catch (error) {
      setTestResult({
        success: false,
        message: 'Failed to connect to Fonoster. Check your credentials.',
      })
    } finally {
      setIsTesting(false)
    }
  }

  const handleSave = async () => {
    setIsSaving(true)
    try {
      // Simulate save
      await new Promise((resolve) => setTimeout(resolve, 1000))
      alert('Fonoster configuration saved successfully!')
    } catch (error) {
      alert('Failed to save configuration')
    } finally {
      setIsSaving(false)
    }
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Phone className="text-primary" />
            Telephony Integration
          </h1>
          <p className="text-muted-foreground mt-1">
            Configure voice calls and SMS for escalation notifications
          </p>
        </div>
        <div className={cn(
          'flex items-center gap-2 px-3 py-1.5 rounded-full text-sm',
          config.enabled ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'
        )}>
          {config.enabled ? <CheckCircle size={14} /> : <XCircle size={14} />}
          {config.enabled ? 'Connected' : 'Disconnected'}
        </div>
      </div>

      {/* Environment Banner */}
      <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
        <h3 className="font-medium text-yellow-400 flex items-center gap-2">
          <AlertTriangle size={16} />
          Local Development Mode
        </h3>
        <p className="text-sm text-muted-foreground mt-1">
          Currently using <strong>mock telephony service</strong> for local development.
          Calls and SMS are simulated and logged to Docker console.
          Check logs with: <code className="bg-muted px-1 rounded">docker logs panther-dashboard-telephony-mock-1</code>
        </p>
      </div>

      {/* Info Banner */}
      <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
        <h3 className="font-medium text-blue-400 flex items-center gap-2">
          <Phone size={16} />
          About Telephony Integration
        </h3>
        <p className="text-sm text-muted-foreground mt-1">
          This integration enables phone calls and SMS for escalation policies.
          For production on GCP, you can self-host Fonoster or use Twilio/Plivo.
        </p>
      </div>

      {/* Configuration Form */}
      <div className="bg-card rounded-lg border p-6 space-y-6">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <Settings size={18} />
          Configuration
        </h2>

        <div className="grid gap-4">
          <div className="flex items-center justify-between p-4 bg-muted/30 rounded-lg">
            <div>
              <p className="font-medium">Enable Telephony</p>
              <p className="text-sm text-muted-foreground">
                Allow phone calls and SMS for escalations
              </p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={config.enabled}
                onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-600 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
            </label>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">Provider</label>
            <select
              value={config.provider}
              onChange={(e) => setConfig({ ...config, provider: e.target.value as 'mock' | 'twilio' })}
              className="w-full px-3 py-2 bg-background border rounded-md"
            >
              <option value="mock">Mock (Local Development)</option>
              <option value="twilio">Twilio (Production)</option>
            </select>
          </div>

          {config.provider === 'mock' && (
            <div className="p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
              <p className="text-sm text-yellow-400">
                Mock mode: Calls and SMS are simulated. Check Docker logs to see notifications.
              </p>
              <code className="text-xs text-muted-foreground mt-1 block">
                docker logs -f panther-dashboard-telephony-mock-1
              </code>
            </div>
          )}

          {config.provider === 'twilio' && (
            <>
              <div className="p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                <p className="text-sm text-blue-400">
                  Get your credentials from{' '}
                  <a href="https://console.twilio.com" target="_blank" rel="noopener noreferrer" className="underline">
                    console.twilio.com
                  </a>
                </p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1">Account SID</label>
                  <input
                    type="text"
                    value={config.twilioAccountSid}
                    onChange={(e) => setConfig({ ...config, twilioAccountSid: e.target.value })}
                    placeholder="ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                    className="w-full px-3 py-2 bg-background border rounded-md font-mono text-sm"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Auth Token</label>
                  <input
                    type="password"
                    value={config.twilioAuthToken}
                    onChange={(e) => setConfig({ ...config, twilioAuthToken: e.target.value })}
                    placeholder="Your auth token"
                    className="w-full px-3 py-2 bg-background border rounded-md"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">Twilio Phone Number</label>
                <input
                  type="text"
                  value={config.twilioPhoneNumber}
                  onChange={(e) => setConfig({ ...config, twilioPhoneNumber: e.target.value })}
                  placeholder="+1234567890"
                  className="w-full px-3 py-2 bg-background border rounded-md"
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Your Twilio phone number (buy one in the Twilio console ~$1/month)
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">Voice</label>
                <select
                  value={config.ttsVoice}
                  onChange={(e) => setConfig({ ...config, ttsVoice: e.target.value })}
                  className="w-full px-3 py-2 bg-background border rounded-md"
                >
                  <option value="alice">Alice (Female)</option>
                  <option value="man">Man</option>
                  <option value="woman">Woman</option>
                  <option value="Polly.Joanna">Polly - Joanna (US Female)</option>
                  <option value="Polly.Matthew">Polly - Matthew (US Male)</option>
                  <option value="Polly.Amy">Polly - Amy (UK Female)</option>
                </select>
              </div>
            </>
          )}
        </div>

        <div className="flex justify-end">
          <button
            onClick={handleSave}
            disabled={isSaving}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
          >
            {isSaving ? <RefreshCw size={14} className="animate-spin" /> : <CheckCircle size={14} />}
            Save Configuration
          </button>
        </div>
      </div>

      {/* Test Section */}
      <div className="bg-card rounded-lg border p-6 space-y-4">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <PhoneCall size={18} />
          Test Connection
        </h2>
        <p className="text-sm text-muted-foreground">
          Send a test call to verify your Fonoster configuration is working correctly.
        </p>

        <div className="flex gap-3">
          <input
            type="tel"
            value={testPhoneNumber}
            onChange={(e) => setTestPhoneNumber(e.target.value)}
            placeholder="+1234567890"
            className="flex-1 px-3 py-2 bg-background border rounded-md"
          />
          <button
            onClick={handleTest}
            disabled={isTesting || !config.enabled}
            className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 disabled:opacity-50"
          >
            {isTesting ? (
              <>
                <RefreshCw size={14} className="animate-spin" />
                Calling...
              </>
            ) : (
              <>
                <Phone size={14} />
                Test Call
              </>
            )}
          </button>
        </div>

        {testResult && (
          <div
            className={cn(
              'p-3 rounded-lg flex items-center gap-2',
              testResult.success
                ? 'bg-green-500/20 text-green-400'
                : 'bg-red-500/20 text-red-400'
            )}
          >
            {testResult.success ? <CheckCircle size={16} /> : <XCircle size={16} />}
            {testResult.message}
          </div>
        )}
      </div>

      {/* Features */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-card rounded-lg border p-4">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 rounded-full bg-blue-500/20 flex items-center justify-center">
              <PhoneCall size={18} className="text-blue-400" />
            </div>
            <h3 className="font-medium">Voice Calls</h3>
          </div>
          <p className="text-sm text-muted-foreground">
            Automated voice calls with text-to-speech for critical alerts
          </p>
        </div>

        <div className="bg-card rounded-lg border p-4">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 rounded-full bg-green-500/20 flex items-center justify-center">
              <MessageSquare size={18} className="text-green-400" />
            </div>
            <h3 className="font-medium">SMS Messages</h3>
          </div>
          <p className="text-sm text-muted-foreground">
            Send SMS alerts to on-call responders when escalations trigger
          </p>
        </div>

        <div className="bg-card rounded-lg border p-4">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 rounded-full bg-purple-500/20 flex items-center justify-center">
              <Volume2 size={18} className="text-purple-400" />
            </div>
            <h3 className="font-medium">Custom Messages</h3>
          </div>
          <p className="text-sm text-muted-foreground">
            Customize the alert message content for calls and SMS
          </p>
        </div>
      </div>

      {/* Local Development */}
      <div className="bg-card rounded-lg border p-6">
        <h2 className="text-lg font-semibold mb-4">Local Development</h2>
        <div className="space-y-3 text-sm">
          <p className="text-muted-foreground">
            The mock telephony service runs in Docker for local testing:
          </p>
          <pre className="bg-muted/50 p-3 rounded-md overflow-x-auto">
            <code>docker-compose up -d telephony-mock</code>
          </pre>
          <p className="text-muted-foreground">
            View simulated calls/SMS in logs:
          </p>
          <pre className="bg-muted/50 p-3 rounded-md overflow-x-auto">
            <code>docker logs -f panther-dashboard-telephony-mock-1</code>
          </pre>
          <p className="text-muted-foreground">
            API endpoints available at{' '}
            <a href="http://localhost:50051" className="text-primary hover:underline">
              http://localhost:50051
            </a>
          </p>
        </div>
      </div>

      {/* GCP Production Deployment */}
      <div className="bg-card rounded-lg border p-6">
        <h2 className="text-lg font-semibold mb-4">Production Deployment (GCP)</h2>
        <div className="space-y-4 text-sm">
          <p className="text-muted-foreground">
            For production, you have two options:
          </p>

          <div className="border-l-2 border-primary pl-4">
            <h3 className="font-medium mb-2">Option 1: Self-Host Fonoster on GCP</h3>
            <ul className="list-disc list-inside text-muted-foreground space-y-1">
              <li>Deploy Fonoster on a GCE VM or GKE cluster</li>
              <li>Set up a SIP trunk provider (Telnyx, Twilio SIP, VoIP.ms)</li>
              <li>Purchase a phone number from the SIP provider</li>
              <li>Configure Fonoster with your SIP credentials</li>
              <li>Update this dashboard to point to your Fonoster instance</li>
            </ul>
          </div>

          <div className="border-l-2 border-green-500 pl-4">
            <h3 className="font-medium mb-2">Option 2: Use Twilio/Plivo (Easier)</h3>
            <ul className="list-disc list-inside text-muted-foreground space-y-1">
              <li>Sign up for Twilio or Plivo account</li>
              <li>Get API credentials and a phone number</li>
              <li>Update the telephony service to use their SDK</li>
              <li>No infrastructure to manage, pay-per-use</li>
            </ul>
          </div>

          <div className="p-3 bg-muted/30 rounded-lg">
            <p className="text-muted-foreground">
              <strong>Estimated costs:</strong> SIP trunks are ~$0.01/min for calls,
              ~$0.01/SMS. Twilio/Plivo have similar pricing with free trial credits.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
