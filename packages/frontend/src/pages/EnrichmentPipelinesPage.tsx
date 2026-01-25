import { useState } from 'react'
import {
  useListEnrichmentPipelinesQuery,
  useGetEnrichmentTypesQuery,
  useCreateEnrichmentPipelineMutation,
  useUpdateEnrichmentPipelineMutation,
  useDeleteEnrichmentPipelineMutation,
  useTestEnrichmentPipelineMutation,
  type EnrichmentPipelineResponse,
  type EnrichmentPipelineCreate,
  type EnrichmentType,
} from '../api/pantherApi'

const typeLabels: Record<EnrichmentType, string> = {
  ip_geolocation: 'IP Geolocation',
  ip_reputation: 'IP Reputation',
  domain_whois: 'Domain WHOIS',
  domain_reputation: 'Domain Reputation',
  file_hash: 'File Hash',
  user_lookup: 'User Lookup',
  asset_lookup: 'Asset Lookup',
  custom_api: 'Custom API',
}

export default function EnrichmentPipelinesPage() {
  const [showActiveOnly, setShowActiveOnly] = useState(false)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [editingPipeline, setEditingPipeline] = useState<EnrichmentPipelineResponse | null>(null)
  const [testingPipeline, setTestingPipeline] = useState<EnrichmentPipelineResponse | null>(null)

  const { data: pipelines, isLoading, error } = useListEnrichmentPipelinesQuery({
    activeOnly: showActiveOnly,
  })

  const [createPipeline] = useCreateEnrichmentPipelineMutation()
  const [updatePipeline] = useUpdateEnrichmentPipelineMutation()
  const [deletePipeline] = useDeleteEnrichmentPipelineMutation()

  const handleCreate = async (data: EnrichmentPipelineCreate) => {
    try {
      await createPipeline(data).unwrap()
      setShowCreateModal(false)
    } catch (err) {
      console.error('Failed to create enrichment pipeline:', err)
    }
  }

  const handleUpdate = async (id: string, update: Partial<EnrichmentPipelineCreate>) => {
    try {
      await updatePipeline({ id, update }).unwrap()
      setEditingPipeline(null)
    } catch (err) {
      console.error('Failed to update enrichment pipeline:', err)
    }
  }

  const handleToggleActive = async (pipeline: EnrichmentPipelineResponse) => {
    try {
      await updatePipeline({
        id: pipeline.id,
        update: { is_active: !pipeline.is_active },
      }).unwrap()
    } catch (err) {
      console.error('Failed to toggle pipeline:', err)
    }
  }

  const handleDelete = async (id: string) => {
    if (confirm('Are you sure you want to delete this enrichment pipeline?')) {
      try {
        await deletePipeline(id).unwrap()
      } catch (err) {
        console.error('Failed to delete enrichment pipeline:', err)
      }
    }
  }

  if (error) {
    return (
      <div className="p-4">
        <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4 text-destructive">
          Failed to load enrichment pipelines
        </div>
      </div>
    )
  }

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Enrichment Pipelines</h1>
          <p className="text-muted-foreground mt-1">
            Configure automatic enrichment for alerts with threat intelligence and context
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors"
        >
          Create Pipeline
        </button>
      </div>

      {/* Filter */}
      <div className="mb-6">
        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          <input
            type="checkbox"
            checked={showActiveOnly}
            onChange={(e) => setShowActiveOnly(e.target.checked)}
            className="rounded border-border bg-background text-primary focus:ring-primary"
          />
          Show active pipelines only
        </label>
      </div>

      {/* Pipelines List */}
      {isLoading ? (
        <div className="flex justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      ) : (
        <div className="space-y-4">
          {pipelines?.map((pipeline) => (
            <div key={pipeline.id} className="bg-card border border-border rounded-lg shadow-sm p-6">
              <div className="flex justify-between items-start">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="text-lg font-semibold text-foreground">{pipeline.name}</h3>
                    <span
                      className={`px-2 py-0.5 text-xs font-medium rounded-full ${
                        pipeline.is_active
                          ? 'bg-green-500/20 text-green-400'
                          : 'bg-muted text-muted-foreground'
                      }`}
                    >
                      {pipeline.is_active ? 'Active' : 'Inactive'}
                    </span>
                    {pipeline.auto_enrich && (
                      <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-blue-500/20 text-blue-400">
                        Auto-enrich
                      </span>
                    )}
                  </div>
                  {pipeline.description && (
                    <p className="text-muted-foreground mb-3">{pipeline.description}</p>
                  )}

                  {/* Pipeline Details */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div>
                      <span className="text-muted-foreground">Type:</span>
                      <span className="ml-2 font-medium text-foreground">
                        {typeLabels[pipeline.enrichment_type]}
                      </span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Source:</span>
                      <span className="ml-2 font-mono text-xs bg-muted px-1.5 py-0.5 rounded text-foreground">
                        {pipeline.source_field}
                      </span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Target:</span>
                      <span className="ml-2 font-mono text-xs bg-muted px-1.5 py-0.5 rounded text-foreground">
                        {pipeline.target_field}
                      </span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Cache TTL:</span>
                      <span className="ml-2 font-medium text-foreground">{pipeline.cache_ttl_minutes} min</span>
                    </div>
                  </div>

                  <p className="text-xs text-muted-foreground mt-4">
                    Created by {pipeline.created_by} on {new Date(pipeline.created_at).toLocaleDateString()}
                  </p>
                </div>

                <div className="flex items-center gap-2 ml-4">
                  <button
                    onClick={() => setTestingPipeline(pipeline)}
                    className="px-3 py-1.5 text-sm border border-primary/50 rounded text-primary hover:bg-primary/10 transition-colors"
                  >
                    Test
                  </button>
                  <button
                    onClick={() => handleToggleActive(pipeline)}
                    className={`px-3 py-1.5 text-sm rounded border transition-colors ${
                      pipeline.is_active
                        ? 'border-border text-muted-foreground hover:bg-muted'
                        : 'border-green-500/50 text-green-400 hover:bg-green-500/10'
                    }`}
                  >
                    {pipeline.is_active ? 'Disable' : 'Enable'}
                  </button>
                  <button
                    onClick={() => setEditingPipeline(pipeline)}
                    className="px-3 py-1.5 text-sm border border-border rounded text-muted-foreground hover:bg-muted transition-colors"
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => handleDelete(pipeline.id)}
                    className="px-3 py-1.5 text-sm border border-destructive/50 rounded text-destructive hover:bg-destructive/10 transition-colors"
                  >
                    Delete
                  </button>
                </div>
              </div>
            </div>
          ))}
          {pipelines?.length === 0 && (
            <div className="bg-card border border-border rounded-lg shadow-sm p-12 text-center text-muted-foreground">
              No enrichment pipelines found. Create one to start enriching alerts automatically.
            </div>
          )}
        </div>
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <EnrichmentPipelineModal
          onClose={() => setShowCreateModal(false)}
          onSave={handleCreate}
        />
      )}

      {/* Edit Modal */}
      {editingPipeline && (
        <EnrichmentPipelineModal
          pipeline={editingPipeline}
          onClose={() => setEditingPipeline(null)}
          onSave={(data) => handleUpdate(editingPipeline.id, data)}
        />
      )}

      {/* Test Modal */}
      {testingPipeline && (
        <TestPipelineModal
          pipeline={testingPipeline}
          onClose={() => setTestingPipeline(null)}
        />
      )}
    </div>
  )
}

function EnrichmentPipelineModal({
  pipeline,
  onClose,
  onSave,
}: {
  pipeline?: EnrichmentPipelineResponse
  onClose: () => void
  onSave: (data: EnrichmentPipelineCreate) => void
}) {
  const { data: enrichmentTypes } = useGetEnrichmentTypesQuery()

  const [name, setName] = useState(pipeline?.name || '')
  const [description, setDescription] = useState(pipeline?.description || '')
  const [enrichmentType, setEnrichmentType] = useState<EnrichmentType>(
    pipeline?.enrichment_type || 'ip_geolocation'
  )
  const [sourceField, setSourceField] = useState(pipeline?.source_field || '')
  const [targetField, setTargetField] = useState(pipeline?.target_field || '')
  const [apiEndpoint, setApiEndpoint] = useState(pipeline?.api_endpoint || '')
  const [apiKeyEnv, setApiKeyEnv] = useState(pipeline?.api_key_env || '')
  const [cacheTtl, setCacheTtl] = useState(pipeline?.cache_ttl_minutes || 60)
  const [isActive, setIsActive] = useState(pipeline?.is_active ?? true)
  const [autoEnrich, setAutoEnrich] = useState(pipeline?.auto_enrich ?? false)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSave({
      name,
      description: description || undefined,
      enrichment_type: enrichmentType,
      source_field: sourceField,
      target_field: targetField,
      api_endpoint: apiEndpoint || undefined,
      api_key_env: apiKeyEnv || undefined,
      cache_ttl_minutes: cacheTtl,
      is_active: isActive,
      auto_enrich: autoEnrich,
    })
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-card border border-border rounded-lg shadow-xl w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex justify-between items-center px-6 py-4 border-b border-border sticky top-0 bg-card">
          <h2 className="text-lg font-semibold text-foreground">
            {pipeline ? 'Edit Enrichment Pipeline' : 'Create Enrichment Pipeline'}
          </h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-6">
          {/* Basic Info */}
          <div className="space-y-4">
            <h3 className="font-medium text-foreground">Basic Information</h3>

            <div>
              <label className="block text-sm font-medium text-foreground mb-1">Name *</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
                placeholder="e.g., IP Geolocation Enrichment"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-foreground mb-1">Description</label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={2}
                className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
              />
            </div>

            {!pipeline && (
              <div>
                <label className="block text-sm font-medium text-foreground mb-1">
                  Enrichment Type *
                </label>
                <select
                  value={enrichmentType}
                  onChange={(e) => setEnrichmentType(e.target.value as EnrichmentType)}
                  className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
                >
                  {enrichmentTypes?.map((type) => (
                    <option key={type.value} value={type.value}>
                      {type.label}
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>

          {/* Field Mapping */}
          <div className="space-y-4">
            <h3 className="font-medium text-foreground">Field Mapping</h3>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-foreground mb-1">
                  Source Field *
                </label>
                <input
                  type="text"
                  value={sourceField}
                  onChange={(e) => setSourceField(e.target.value)}
                  required
                  className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
                  placeholder="e.g., p_alert.context.source_ip"
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Dot-notation path to extract value from alert
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-foreground mb-1">
                  Target Field *
                </label>
                <input
                  type="text"
                  value={targetField}
                  onChange={(e) => setTargetField(e.target.value)}
                  required
                  className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
                  placeholder="e.g., enrichment.geo"
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Field name for storing enrichment result
                </p>
              </div>
            </div>
          </div>

          {/* API Configuration (for custom API) */}
          {enrichmentType === 'custom_api' && (
            <div className="space-y-4">
              <h3 className="font-medium text-foreground">API Configuration</h3>

              <div>
                <label className="block text-sm font-medium text-foreground mb-1">
                  API Endpoint
                </label>
                <input
                  type="text"
                  value={apiEndpoint}
                  onChange={(e) => setApiEndpoint(e.target.value)}
                  className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
                  placeholder="https://api.example.com/lookup/{value}"
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Use {'{value}'} as placeholder for the enrichment value
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-foreground mb-1">
                  API Key Environment Variable
                </label>
                <input
                  type="text"
                  value={apiKeyEnv}
                  onChange={(e) => setApiKeyEnv(e.target.value)}
                  className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
                  placeholder="e.g., CUSTOM_API_KEY"
                />
              </div>
            </div>
          )}

          {/* Settings */}
          <div className="space-y-4">
            <h3 className="font-medium text-foreground">Settings</h3>

            <div>
              <label className="block text-sm font-medium text-foreground mb-1">
                Cache TTL (minutes)
              </label>
              <input
                type="number"
                value={cacheTtl}
                onChange={(e) => setCacheTtl(parseInt(e.target.value) || 60)}
                min={1}
                className="w-full px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
              />
              <p className="text-xs text-muted-foreground mt-1">
                How long to cache enrichment results
              </p>
            </div>

            <div className="space-y-3">
              <label className="flex items-center gap-3">
                <input
                  type="checkbox"
                  checked={isActive}
                  onChange={(e) => setIsActive(e.target.checked)}
                  className="rounded border-border bg-background text-primary focus:ring-primary"
                />
                <span className="text-sm text-foreground">Pipeline is active</span>
              </label>

              <label className="flex items-center gap-3">
                <input
                  type="checkbox"
                  checked={autoEnrich}
                  onChange={(e) => setAutoEnrich(e.target.checked)}
                  className="rounded border-border bg-background text-primary focus:ring-primary"
                />
                <span className="text-sm text-foreground">
                  Automatically enrich new alerts
                </span>
              </label>
            </div>
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t border-border">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 border border-border rounded-lg text-foreground hover:bg-muted transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!name || !sourceField || !targetField}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50 transition-colors"
            >
              {pipeline ? 'Save Changes' : 'Create Pipeline'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function TestPipelineModal({
  pipeline,
  onClose,
}: {
  pipeline: EnrichmentPipelineResponse
  onClose: () => void
}) {
  const [testValue, setTestValue] = useState('')
  const [testPipeline, { data: result, isLoading, error }] = useTestEnrichmentPipelineMutation()

  const handleTest = async () => {
    if (!testValue.trim()) return
    try {
      await testPipeline({ pipelineId: pipeline.id, value: testValue }).unwrap()
    } catch (err) {
      console.error('Test failed:', err)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-card border border-border rounded-lg shadow-xl w-full max-w-xl mx-4">
        <div className="flex justify-between items-center px-6 py-4 border-b border-border">
          <h2 className="text-lg font-semibold text-foreground">Test Pipeline: {pipeline.name}</h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-foreground mb-1">
              Test Value
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={testValue}
                onChange={(e) => setTestValue(e.target.value)}
                placeholder={`Enter a ${typeLabels[pipeline.enrichment_type].toLowerCase()} value`}
                className="flex-1 px-3 py-2 border border-border bg-background text-foreground rounded-lg focus:ring-2 focus:ring-primary focus:border-primary"
              />
              <button
                onClick={handleTest}
                disabled={!testValue.trim() || isLoading}
                className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50 transition-colors"
              >
                {isLoading ? 'Testing...' : 'Test'}
              </button>
            </div>
          </div>

          {error && (
            <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-3 text-destructive text-sm">
              Test failed. Please try again.
            </div>
          )}

          {result && (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-foreground">Source:</span>
                <span className={`px-2 py-0.5 text-xs rounded-full ${
                  result.source === 'cache' ? 'bg-yellow-500/20 text-yellow-400' : 'bg-green-500/20 text-green-400'
                }`}>
                  {result.source === 'cache' ? 'Cached' : 'Live'}
                </span>
              </div>
              <div>
                <span className="text-sm font-medium text-foreground">Result:</span>
                <pre className="mt-1 p-3 bg-muted rounded-lg text-xs overflow-auto max-h-64 text-foreground">
                  {JSON.stringify(result.data, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>

        <div className="px-6 py-4 border-t border-border flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 border border-border rounded-lg text-foreground hover:bg-muted transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
