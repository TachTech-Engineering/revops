import { useMemo, useState } from 'react'
import { AlertTriangle, CheckCircle2, Loader2, Plug, RefreshCw, Trash2 } from 'lucide-react'
import {
  useListConnectorsQuery,
  useGetConnectorTypesQuery,
  useCreateConnectorMutation,
  useUpdateConnectorMutation,
  useDeleteConnectorMutation,
  useTestConnectorMutation,
} from '../../api/pantherApi'
import type { ConnectionTestResult, ConnectorResponse } from '../../api/pantherApi'

/**
 * Real configuration for one integration, backed by the connectors API.
 *
 * Every integration page used to be a mock: hardcoded "Connected", fabricated
 * channel and rule lists, a Save that appended to React state and vanished on
 * refresh, and a Test button that slept two seconds and reported success
 * without contacting anything. In a tool people rely on for incident
 * notification that is worse than having no page at all -- it tells an
 * operator that alerting works when nothing is configured.
 *
 * This panel shows what is actually stored, saves through the connectors API
 * (which encrypts credentials at rest and scopes them to the caller's
 * organization), and its Test button calls the real endpoint and reports
 * exactly what came back.
 */

interface SchemaField {
  key: string
  title: string
  description?: string
  isSecret: boolean
  required: boolean
}

function parseSchema(schema: Record<string, unknown> | undefined): SchemaField[] {
  if (!schema) return []
  const properties = (schema.properties ?? {}) as Record<string, Record<string, unknown>>
  const required = (schema.required ?? []) as string[]
  return Object.entries(properties).map(([key, spec]) => ({
    key,
    title: (spec.title as string) ?? key,
    description: spec.description as string | undefined,
    isSecret: spec.format === 'password',
    required: required.includes(key),
  }))
}

export interface IntegrationConnectorPanelProps {
  /** Backend connector_type, e.g. "slack". Must match a registered connector. */
  connectorType: string
  /** Human name for headings and empty states. */
  displayName: string
  /** Optional guidance rendered above the form. */
  setupHint?: React.ReactNode
}

export default function IntegrationConnectorPanel({
  connectorType,
  displayName,
  setupHint,
}: IntegrationConnectorPanelProps) {
  const { data: types } = useGetConnectorTypesQuery()
  const {
    data: connectorList,
    isLoading,
    refetch,
  } = useListConnectorsQuery({ connector_type: connectorType })

  const [createConnector, { isLoading: isCreating }] = useCreateConnectorMutation()
  const [updateConnector, { isLoading: isUpdating }] = useUpdateConnectorMutation()
  const [deleteConnector] = useDeleteConnectorMutation()
  const [testConnector, { isLoading: isTesting }] = useTestConnectorMutation()

  const [form, setForm] = useState<Record<string, string>>({})
  const [name, setName] = useState(`${displayName} integration`)
  const [testResult, setTestResult] = useState<ConnectionTestResult | null>(null)
  const [saveError, setSaveError] = useState<string | null>(null)

  const typeInfo = useMemo(
    () => types?.find((t) => t.type === connectorType),
    [types, connectorType]
  )
  const credentialFields = useMemo(
    () => parseSchema(typeInfo?.credential_schema),
    [typeInfo]
  )
  const configFields = useMemo(() => parseSchema(typeInfo?.config_schema), [typeInfo])

  // The list is already scoped to the caller's organization by the API.
  const existing: ConnectorResponse | undefined = connectorList?.items?.[0]

  const handleSave = async () => {
    setSaveError(null)
    setTestResult(null)
    const credentials: Record<string, string> = {}
    const config: Record<string, string> = {}
    credentialFields.forEach((f) => {
      if (form[f.key]) credentials[f.key] = form[f.key]
    })
    configFields.forEach((f) => {
      if (form[f.key]) config[f.key] = form[f.key]
    })

    try {
      if (existing) {
        await updateConnector({
          id: existing.id,
          update: {
            // Credentials are only sent when the operator typed new ones;
            // blank fields must not wipe what is already stored.
            ...(Object.keys(credentials).length ? { credentials } : {}),
            config,
          },
        }).unwrap()
      } else {
        await createConnector({
          name,
          category: 'action',
          connector_type: connectorType,
          credentials,
          config,
        }).unwrap()
      }
      setForm({})
      refetch()
    } catch (err) {
      const detail =
        (err as { data?: { detail?: string } })?.data?.detail ?? 'Could not save the connector.'
      setSaveError(detail)
    }
  }

  const handleTest = async () => {
    if (!existing) return
    setTestResult(null)
    try {
      const result = await testConnector(existing.id).unwrap()
      setTestResult(result)
    } catch (err) {
      const detail =
        (err as { data?: { detail?: string } })?.data?.detail ?? 'The test request failed.'
      setTestResult({ success: false, message: detail })
    }
  }

  const handleDelete = async () => {
    if (!existing) return
    if (!confirm(`Remove the ${displayName} connector? Stored credentials are deleted.`)) return
    await deleteConnector(existing.id)
    setTestResult(null)
    refetch()
  }

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 rounded-lg border bg-background p-6 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading {displayName} configuration...
      </div>
    )
  }

  if (!typeInfo) {
    // Honest empty state: the backend has no connector of this type, so there
    // is nothing this page could save. Saying so beats a form that discards
    // whatever is typed into it.
    return (
      <div className="rounded-lg border bg-background p-6">
        <div className="flex items-center gap-2 text-sm">
          <AlertTriangle className="h-4 w-4 text-amber-500" />
          <span className="font-medium">{displayName} is not available on this deployment</span>
        </div>
        <p className="mt-2 text-sm text-muted-foreground">
          No <code>{connectorType}</code> connector is registered in the backend, so there is
          nothing to configure here yet. Alerts cannot be delivered to {displayName} until one
          exists.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="rounded-lg border bg-background p-6">
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Plug className="h-5 w-5" />
            <h2 className="text-lg font-semibold">Connection</h2>
          </div>
          {existing ? (
            <span className="flex items-center gap-2 text-sm">
              <span
                className={`h-2 w-2 rounded-full ${
                  existing.status === 'connected' ? 'bg-green-500' : 'bg-amber-500'
                }`}
              />
              {existing.status}
            </span>
          ) : (
            <span className="text-sm text-muted-foreground">Not configured</span>
          )}
        </div>

        {setupHint && <div className="mb-4 text-sm text-muted-foreground">{setupHint}</div>}

        {existing?.last_error && (
          <div className="mb-4 rounded-md border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-500">
            Last error: {existing.last_error}
          </div>
        )}

        {!existing && (
          <div className="mb-4">
            <label className="mb-1 block text-sm font-medium">Name</label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full rounded-md border bg-background px-3 py-2 text-sm"
            />
          </div>
        )}

        {[...credentialFields, ...configFields].map((field) => (
          <div key={field.key} className="mb-4">
            <label className="mb-1 block text-sm font-medium">
              {field.title}
              {field.required && <span className="text-red-500"> *</span>}
            </label>
            <input
              type={field.isSecret ? 'password' : 'text'}
              value={form[field.key] ?? ''}
              onChange={(e) => setForm({ ...form, [field.key]: e.target.value })}
              placeholder={
                field.isSecret && existing ? 'stored - leave blank to keep unchanged' : ''
              }
              className="w-full rounded-md border bg-background px-3 py-2 text-sm"
            />
            {field.description && (
              <p className="mt-1 text-xs text-muted-foreground">{field.description}</p>
            )}
          </div>
        ))}

        {saveError && <div className="mb-3 text-sm text-red-500">{saveError}</div>}

        <div className="flex flex-wrap gap-2">
          <button
            onClick={handleSave}
            disabled={isCreating || isUpdating}
            className="rounded-md bg-primary px-4 py-2 text-sm text-primary-foreground disabled:opacity-50"
          >
            {isCreating || isUpdating ? 'Saving...' : existing ? 'Update' : 'Save'}
          </button>
          <button
            onClick={handleTest}
            disabled={!existing || isTesting}
            title={existing ? undefined : 'Save the connection first'}
            className="flex items-center gap-2 rounded-md border px-4 py-2 text-sm disabled:opacity-50"
          >
            {isTesting ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4" />
            )}
            Test connection
          </button>
          {existing && (
            <button
              onClick={handleDelete}
              className="flex items-center gap-2 rounded-md border px-4 py-2 text-sm text-red-500"
            >
              <Trash2 className="h-4 w-4" />
              Remove
            </button>
          )}
        </div>

        {/* The real result of the real call, success or failure. */}
        {testResult && (
          <div
            className={`mt-4 flex items-start gap-2 rounded-md border p-3 text-sm ${
              testResult.success
                ? 'border-green-500/40 bg-green-500/10 text-green-600'
                : 'border-red-500/40 bg-red-500/10 text-red-500'
            }`}
          >
            {testResult.success ? (
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
            ) : (
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            )}
            <span>{testResult.message}</span>
          </div>
        )}
      </div>
    </div>
  )
}
