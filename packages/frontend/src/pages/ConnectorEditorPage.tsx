import { useState, useEffect } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, Save, Play, AlertCircle, CheckCircle } from 'lucide-react'
import {
  useGetConnectorQuery,
  useGetConnectorTypesQuery,
  useCreateConnectorMutation,
  useUpdateConnectorMutation,
  useTestConnectorMutation,
  ConnectorCategory,
  ConnectorCreate,
} from '../api/pantherApi'
import { cn } from '../lib/utils'

interface FormData {
  name: string
  description: string
  category: ConnectorCategory
  connector_type: string
  credentials: Record<string, string>
  config: Record<string, unknown>
  sync_enabled: boolean
  sync_interval_minutes: number
}

export default function ConnectorEditorPage() {
  const navigate = useNavigate()
  const { connectorId } = useParams()
  const isEditing = !!connectorId && connectorId !== 'new'

  const { data: existingConnector, isLoading: isLoadingConnector } = useGetConnectorQuery(connectorId!, {
    skip: !isEditing,
  })

  const { data: connectorTypes } = useGetConnectorTypesQuery()

  const [createConnector, { isLoading: isCreating }] = useCreateConnectorMutation()
  const [updateConnector, { isLoading: isUpdating }] = useUpdateConnectorMutation()
  const [testConnector, { isLoading: isTesting }] = useTestConnectorMutation()

  const [formData, setFormData] = useState<FormData>({
    name: '',
    description: '',
    category: 'data_source',
    connector_type: '',
    credentials: {},
    config: {},
    sync_enabled: true,
    sync_interval_minutes: 5,
  })

  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null)
  const [errors, setErrors] = useState<Record<string, string>>({})

  useEffect(() => {
    if (existingConnector) {
      setFormData({
        name: existingConnector.name,
        description: existingConnector.description || '',
        category: existingConnector.category,
        connector_type: existingConnector.connector_type,
        credentials: {},
        config: existingConnector.config || {},
        sync_enabled: existingConnector.sync_enabled,
        sync_interval_minutes: existingConnector.sync_interval_minutes,
      })
    }
  }, [existingConnector])

  const selectedTypeInfo = connectorTypes?.find(
    (t) => t.type === formData.connector_type && t.category === formData.category
  )

  const handleCategoryChange = (category: ConnectorCategory) => {
    setFormData((prev) => ({
      ...prev,
      category,
      connector_type: '',
      credentials: {},
      config: {},
    }))
    setTestResult(null)
  }

  const handleTypeChange = (type: string) => {
    setFormData((prev) => ({
      ...prev,
      connector_type: type,
      credentials: {},
      config: {},
    }))
    setTestResult(null)
  }

  const handleCredentialChange = (key: string, value: string) => {
    setFormData((prev) => ({
      ...prev,
      credentials: { ...prev.credentials, [key]: value },
    }))
    setTestResult(null)
  }

  const handleConfigChange = (key: string, value: unknown) => {
    setFormData((prev) => ({
      ...prev,
      config: { ...prev.config, [key]: value },
    }))
  }

  const validateForm = (): boolean => {
    const newErrors: Record<string, string> = {}

    if (!formData.name.trim()) {
      newErrors.name = 'Name is required'
    }
    if (!formData.connector_type) {
      newErrors.connector_type = 'Connector type is required'
    }

    // Validate required credentials
    if (selectedTypeInfo?.credential_schema) {
      const required = (selectedTypeInfo.credential_schema as Record<string, unknown>).required as string[] || []
      required.forEach((field) => {
        if (!formData.credentials[field]) {
          newErrors[`credential_${field}`] = `${field} is required`
        }
      })
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleTest = async () => {
    if (!validateForm()) return

    setTestResult(null)
    try {
      // For new connectors, we need to create a temp connector or the backend should support testing without saving
      if (isEditing) {
        const result = await testConnector(connectorId!).unwrap()
        setTestResult(result)
      } else {
        // Create, test, then delete if test only
        setTestResult({ success: false, message: 'Save the connector first to test the connection' })
      }
    } catch (err) {
      setTestResult({ success: false, message: 'Failed to test connection' })
    }
  }

  const handleSubmit = async () => {
    if (!validateForm()) return

    try {
      const payload: ConnectorCreate = {
        name: formData.name,
        description: formData.description || undefined,
        category: formData.category,
        connector_type: formData.connector_type,
        credentials: Object.keys(formData.credentials).length > 0 ? formData.credentials : undefined,
        config: Object.keys(formData.config).length > 0 ? formData.config : undefined,
        sync_enabled: formData.category === 'data_source' ? formData.sync_enabled : undefined,
        sync_interval_minutes: formData.category === 'data_source' ? formData.sync_interval_minutes : undefined,
      }

      if (isEditing) {
        await updateConnector({
          id: connectorId!,
          update: {
            name: payload.name,
            description: payload.description,
            credentials: payload.credentials,
            config: payload.config,
            sync_enabled: payload.sync_enabled,
            sync_interval_minutes: payload.sync_interval_minutes,
          },
        }).unwrap()
      } else {
        await createConnector(payload).unwrap()
      }
      navigate('/connectors')
    } catch (err) {
      console.error('Failed to save connector:', err)
    }
  }

  const filteredTypes = connectorTypes?.filter((t) => t.category === formData.category) || []

  if (isEditing && isLoadingConnector) {
    return <div className="p-6 text-center text-muted-foreground">Loading connector...</div>
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <div className="flex items-center gap-4">
        <button onClick={() => navigate('/connectors')} className="p-2 hover:bg-accent rounded-md">
          <ArrowLeft size={20} />
        </button>
        <div>
          <h1 className="text-3xl font-bold">{isEditing ? 'Edit Connector' : 'New Connector'}</h1>
          <p className="text-muted-foreground">
            {isEditing ? 'Update connector configuration' : 'Configure a new data source or action connector'}
          </p>
        </div>
      </div>

      {/* Category Selection */}
      {!isEditing && (
        <div className="rounded-lg border bg-background p-6">
          <label className="block text-sm font-medium mb-3">Connector Category</label>
          <div className="grid grid-cols-2 gap-4">
            <button
              type="button"
              onClick={() => handleCategoryChange('data_source')}
              className={cn(
                'p-4 rounded-lg border-2 text-left transition-colors',
                formData.category === 'data_source'
                  ? 'border-primary bg-primary/10'
                  : 'border-muted hover:border-accent'
              )}
            >
              <div className="font-semibold">Data Source</div>
              <div className="text-sm text-muted-foreground">Ingest alerts from SIEMs</div>
            </button>
            <button
              type="button"
              onClick={() => handleCategoryChange('action')}
              className={cn(
                'p-4 rounded-lg border-2 text-left transition-colors',
                formData.category === 'action'
                  ? 'border-primary bg-primary/10'
                  : 'border-muted hover:border-accent'
              )}
            >
              <div className="font-semibold">Action Connector</div>
              <div className="text-sm text-muted-foreground">Execute responses and notifications</div>
            </button>
          </div>
        </div>
      )}

      {/* Connector Type Selection */}
      {!isEditing && (
        <div className="rounded-lg border bg-background p-6">
          <label className="block text-sm font-medium mb-3">Connector Type</label>
          {errors.connector_type && (
            <p className="text-sm text-destructive mb-2">{errors.connector_type}</p>
          )}
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            {filteredTypes.map((type) => (
              <button
                key={type.type}
                type="button"
                onClick={() => handleTypeChange(type.type)}
                className={cn(
                  'p-3 rounded-lg border text-left transition-colors',
                  formData.connector_type === type.type
                    ? 'border-primary bg-primary/10'
                    : 'border-muted hover:border-accent'
                )}
              >
                <div className="font-medium">{type.name}</div>
                <div className="text-xs text-muted-foreground line-clamp-2">{type.description}</div>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Basic Info */}
      <div className="rounded-lg border bg-background p-6 space-y-4">
        <h2 className="font-semibold">Basic Information</h2>

        <div>
          <label className="block text-sm font-medium mb-1">Name</label>
          <input
            type="text"
            value={formData.name}
            onChange={(e) => setFormData((prev) => ({ ...prev, name: e.target.value }))}
            className={cn(
              'w-full px-3 py-2 rounded-md border bg-background',
              errors.name && 'border-destructive'
            )}
            placeholder="My Connector"
          />
          {errors.name && <p className="text-sm text-destructive mt-1">{errors.name}</p>}
        </div>

        <div>
          <label className="block text-sm font-medium mb-1">Description</label>
          <textarea
            value={formData.description}
            onChange={(e) => setFormData((prev) => ({ ...prev, description: e.target.value }))}
            className="w-full px-3 py-2 rounded-md border bg-background"
            rows={2}
            placeholder="Optional description"
          />
        </div>
      </div>

      {/* Credentials */}
      {selectedTypeInfo && selectedTypeInfo.credential_schema && (
        <div className="rounded-lg border bg-background p-6 space-y-4">
          <h2 className="font-semibold">Credentials</h2>
          <p className="text-sm text-muted-foreground">
            Credentials are encrypted at rest and never exposed after saving
          </p>

          {Object.entries(
            (selectedTypeInfo.credential_schema as Record<string, unknown>).properties as Record<string, Record<string, string>> || {}
          ).map(([key, schema]) => (
            <div key={key}>
              <label className="block text-sm font-medium mb-1">
                {schema.title || key}
                {((selectedTypeInfo.credential_schema as Record<string, unknown>).required as string[] || []).includes(key) && (
                  <span className="text-destructive ml-1">*</span>
                )}
              </label>
              <input
                type={key.toLowerCase().includes('password') || key.toLowerCase().includes('secret') || key.toLowerCase().includes('token') || key.toLowerCase().includes('key') ? 'password' : 'text'}
                value={formData.credentials[key] || ''}
                onChange={(e) => handleCredentialChange(key, e.target.value)}
                className={cn(
                  'w-full px-3 py-2 rounded-md border bg-background',
                  errors[`credential_${key}`] && 'border-destructive'
                )}
                placeholder={schema.description || ''}
              />
              {errors[`credential_${key}`] && (
                <p className="text-sm text-destructive mt-1">{errors[`credential_${key}`]}</p>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Configuration */}
      {selectedTypeInfo && selectedTypeInfo.config_schema && Object.keys((selectedTypeInfo.config_schema as Record<string, unknown>).properties || {}).length > 0 && (
        <div className="rounded-lg border bg-background p-6 space-y-4">
          <h2 className="font-semibold">Configuration</h2>

          {Object.entries(
            (selectedTypeInfo.config_schema as Record<string, unknown>).properties as Record<string, Record<string, unknown>> || {}
          ).map(([key, schema]) => (
            <div key={key}>
              <label className="block text-sm font-medium mb-1">
                {(schema.title as string) || key}
              </label>
              {schema.type === 'boolean' ? (
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={Boolean(formData.config[key])}
                    onChange={(e) => handleConfigChange(key, e.target.checked)}
                    className="rounded"
                  />
                  <span className="text-sm text-muted-foreground">{schema.description as string}</span>
                </label>
              ) : (
                <input
                  type="text"
                  value={String(formData.config[key] || '')}
                  onChange={(e) => handleConfigChange(key, e.target.value)}
                  className="w-full px-3 py-2 rounded-md border bg-background"
                  placeholder={(schema.description as string) || ''}
                />
              )}
            </div>
          ))}
        </div>
      )}

      {/* Sync Settings (Data Sources only) */}
      {formData.category === 'data_source' && (
        <div className="rounded-lg border bg-background p-6 space-y-4">
          <h2 className="font-semibold">Sync Settings</h2>

          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={formData.sync_enabled}
              onChange={(e) => setFormData((prev) => ({ ...prev, sync_enabled: e.target.checked }))}
              className="rounded"
            />
            <span>Enable automatic sync</span>
          </label>

          {formData.sync_enabled && (
            <div>
              <label className="block text-sm font-medium mb-1">Sync Interval (minutes)</label>
              <input
                type="number"
                min={1}
                max={1440}
                value={formData.sync_interval_minutes}
                onChange={(e) =>
                  setFormData((prev) => ({ ...prev, sync_interval_minutes: parseInt(e.target.value) || 5 }))
                }
                className="w-32 px-3 py-2 rounded-md border bg-background"
              />
            </div>
          )}
        </div>
      )}

      {/* Test Result */}
      {testResult && (
        <div
          className={cn(
            'p-4 rounded-lg flex items-center gap-3',
            testResult.success ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'
          )}
        >
          {testResult.success ? <CheckCircle size={20} /> : <AlertCircle size={20} />}
          <span>{testResult.message}</span>
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center gap-4">
        <button
          onClick={handleSubmit}
          disabled={isCreating || isUpdating}
          className="flex items-center gap-2 px-6 py-2 bg-primary text-primary-foreground rounded-md font-medium hover:bg-primary/90 disabled:opacity-50"
        >
          <Save size={18} />
          {isCreating || isUpdating ? 'Saving...' : 'Save Connector'}
        </button>
        {isEditing && (
          <button
            onClick={handleTest}
            disabled={isTesting}
            className="flex items-center gap-2 px-4 py-2 bg-muted text-muted-foreground rounded-md font-medium hover:bg-accent disabled:opacity-50"
          >
            <Play size={18} />
            {isTesting ? 'Testing...' : 'Test Connection'}
          </button>
        )}
        <button
          onClick={() => navigate('/connectors')}
          className="px-4 py-2 text-muted-foreground hover:text-foreground"
        >
          Cancel
        </button>
      </div>
    </div>
  )
}
