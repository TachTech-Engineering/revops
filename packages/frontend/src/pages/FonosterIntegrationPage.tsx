import { useEffect, useState } from 'react'
import { AlertTriangle, CheckCircle2, Loader2, Phone, RefreshCw } from 'lucide-react'
import {
  useGetFonosterConfigQuery,
  useUpdateFonosterConfigMutation,
  useTestFonosterConnectionMutation,
  useSendFonosterTestCallMutation,
  useSendFonosterTestSmsMutation,
} from '../api/pantherApi'
import type { ConnectionTestResult } from '../api/pantherApi'

/**
 * Voice and SMS escalation via Fonoster.
 *
 * This page was a mock while a complete backend sat unused: /fonoster/config,
 * /test-connection, /test-call and /test-sms have existed since the per-org
 * telephony work, and nothing in the frontend ever called them. It now reads
 * and writes the real per-organization configuration.
 */
export default function FonosterIntegrationPage() {
  const { data: config, isLoading, refetch } = useGetFonosterConfigQuery()
  const [updateConfig, { isLoading: isSaving }] = useUpdateFonosterConfigMutation()
  const [testConnection, { isLoading: isTesting }] = useTestFonosterConnectionMutation()
  const [testCall, { isLoading: isCalling }] = useSendFonosterTestCallMutation()
  const [testSms, { isLoading: isTexting }] = useSendFonosterTestSmsMutation()

  const [form, setForm] = useState({
    api_endpoint: '',
    access_key_id: '',
    access_key_secret: '',
    default_caller_id: '',
    tts_voice: 'en-US-Standard-A',
    enabled: false,
  })
  const [phone, setPhone] = useState('')
  const [result, setResult] = useState<ConnectionTestResult | null>(null)

  // The GET masks access_key_id and never returns the secret, so the secret
  // field stays blank and is only sent when the operator types a new one.
  useEffect(() => {
    if (config) {
      setForm((prev) => ({
        ...prev,
        api_endpoint: config.api_endpoint ?? '',
        access_key_id: config.access_key_id ?? '',
        default_caller_id: config.default_caller_id ?? '',
        tts_voice: config.tts_voice ?? 'en-US-Standard-A',
        enabled: Boolean(config.enabled),
      }))
    }
  }, [config])

  const show = (r: ConnectionTestResult) => setResult(r)
  const asError = (err: unknown, fallback: string): ConnectionTestResult => ({
    success: false,
    message: (err as { data?: { detail?: string } })?.data?.detail ?? fallback,
  })

  const handleSave = async () => {
    setResult(null)
    try {
      await updateConfig(form).unwrap()
      setForm((f) => ({ ...f, access_key_secret: '' }))
      refetch()
      show({ success: true, message: 'Configuration saved.' })
    } catch (err) {
      show(asError(err, 'Could not save the configuration.'))
    }
  }

  const run = async (
    fn: () => Promise<unknown>,
    fallback: string,
    successMessage: string
  ) => {
    setResult(null)
    try {
      const res = (await fn()) as ConnectionTestResult | undefined
      show(
        res && typeof res.success === 'boolean'
          ? res
          : { success: true, message: successMessage }
      )
    } catch (err) {
      show(asError(err, fallback))
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 p-6 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading telephony configuration...
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Fonoster</h1>
        <p className="text-muted-foreground">
          Voice calls and SMS for escalation, configured per organization.
        </p>
      </div>

      <div className="rounded-lg border bg-background p-6">
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Phone className="h-5 w-5" />
            <h2 className="text-lg font-semibold">Connection</h2>
          </div>
          <span className="text-sm text-muted-foreground">
            {config?.enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>

        {[
          { key: 'api_endpoint', label: 'API endpoint', secret: false },
          { key: 'access_key_id', label: 'Access key ID', secret: false },
          { key: 'access_key_secret', label: 'Access key secret', secret: true },
          { key: 'default_caller_id', label: 'Default caller ID', secret: false },
          { key: 'tts_voice', label: 'Text-to-speech voice', secret: false },
        ].map((field) => (
          <div key={field.key} className="mb-4">
            <label className="mb-1 block text-sm font-medium">{field.label}</label>
            <input
              type={field.secret ? 'password' : 'text'}
              value={(form as Record<string, string | boolean>)[field.key] as string}
              onChange={(e) => setForm({ ...form, [field.key]: e.target.value })}
              placeholder={field.secret && config ? 'stored - leave blank to keep unchanged' : ''}
              className="w-full rounded-md border bg-background px-3 py-2 text-sm"
            />
          </div>
        ))}

        <label className="mb-4 flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={form.enabled}
            onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
          />
          Enabled
        </label>

        <div className="flex flex-wrap gap-2">
          <button
            onClick={handleSave}
            disabled={isSaving}
            className="rounded-md bg-primary px-4 py-2 text-sm text-primary-foreground disabled:opacity-50"
          >
            {isSaving ? 'Saving...' : 'Save'}
          </button>
          <button
            onClick={() =>
              run(
                () => testConnection().unwrap(),
                'The test request failed.',
                'Connection succeeded.'
              )
            }
            disabled={isTesting}
            className="flex items-center gap-2 rounded-md border px-4 py-2 text-sm disabled:opacity-50"
          >
            {isTesting ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4" />
            )}
            Test connection
          </button>
        </div>
      </div>

      <div className="rounded-lg border bg-background p-6">
        <h2 className="mb-2 text-lg font-semibold">Send a test</h2>
        <p className="mb-4 text-sm text-muted-foreground">
          Places a real call or sends a real message. Use your own number.
        </p>
        <div className="flex flex-col gap-2 md:flex-row">
          <input
            value={phone}
            onChange={(e) => setPhone(e.target.value)}
            placeholder="+15551234567"
            className="flex-1 rounded-md border bg-background px-3 py-2 text-sm"
          />
          <button
            onClick={() =>
              run(
                () => testCall({ phone_number: phone }).unwrap(),
                'The test call failed.',
                'Test call placed.'
              )
            }
            disabled={!phone || isCalling}
            className="rounded-md border px-4 py-2 text-sm disabled:opacity-50"
          >
            {isCalling ? 'Calling...' : 'Test call'}
          </button>
          <button
            onClick={() =>
              run(
                () => testSms({ phone_number: phone }).unwrap(),
                'The test message failed.',
                'Test message sent.'
              )
            }
            disabled={!phone || isTexting}
            className="rounded-md border px-4 py-2 text-sm disabled:opacity-50"
          >
            {isTexting ? 'Sending...' : 'Test SMS'}
          </button>
        </div>
      </div>

      {result && (
        <div
          className={`flex items-start gap-2 rounded-md border p-3 text-sm ${
            result.success
              ? 'border-green-500/40 bg-green-500/10 text-green-600'
              : 'border-red-500/40 bg-red-500/10 text-red-500'
          }`}
        >
          {result.success ? (
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
          ) : (
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          )}
          <span>{result.message}</span>
        </div>
      )}
    </div>
  )
}
