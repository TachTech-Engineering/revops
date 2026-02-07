import { useState, useEffect } from 'react'
import { useSelector } from 'react-redux'
import { RootState } from '../store'
import {
  Shield,
  Plus,
  Trash2,
  Edit2,
  Check,
  X,
  TestTube,
  Eye,
  EyeOff,
  ExternalLink,
  AlertCircle,
  CheckCircle,
} from 'lucide-react'

const API_BASE = import.meta.env.VITE_API_BASE_URL || ''

interface SSOConfig {
  id: string
  provider: string
  display_name: string | null
  is_enabled: boolean
  client_id: string
  domain: string | null
  tenant_id: string | null
  metadata_url: string | null
  entity_id: string | null
  sso_url: string | null
  allowed_email_domains: string | null
  auto_create_users: boolean
  default_role: string
  created_at: string
  updated_at: string
}

interface SSOFormData {
  provider: string
  display_name: string
  client_id: string
  client_secret: string
  domain: string
  tenant_id: string
  metadata_url: string
  entity_id: string
  sso_url: string
  certificate: string
  allowed_email_domains: string
  auto_create_users: boolean
  default_role: string
}

const PROVIDER_OPTIONS = [
  { id: 'google', name: 'Google Workspace', icon: 'google' },
  { id: 'okta', name: 'Okta', icon: 'okta' },
  { id: 'azure_ad', name: 'Microsoft Azure AD', icon: 'azure_ad' },
]

const ROLE_OPTIONS = [
  { id: 'viewer', name: 'Viewer', description: 'Read-only access' },
  { id: 'analyst', name: 'Analyst', description: 'Can manage alerts and incidents' },
  { id: 'admin', name: 'Admin', description: 'Full access' },
]

const defaultFormData: SSOFormData = {
  provider: 'google',
  display_name: '',
  client_id: '',
  client_secret: '',
  domain: '',
  tenant_id: '',
  metadata_url: '',
  entity_id: '',
  sso_url: '',
  certificate: '',
  allowed_email_domains: '',
  auto_create_users: true,
  default_role: 'viewer',
}

export default function SSOSettingsPage() {
  const { accessToken, organizationId, userRole } = useSelector((state: RootState) => state.auth)
  const [configs, setConfigs] = useState<SSOConfig[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [formData, setFormData] = useState<SSOFormData>(defaultFormData)
  const [showSecret, setShowSecret] = useState(false)
  const [isSaving, setIsSaving] = useState(false)
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null)
  const [testingId, setTestingId] = useState<string | null>(null)

  // Check if user is admin
  const isAdmin = userRole === 'admin'

  useEffect(() => {
    if (organizationId) {
      fetchConfigs()
    }
  }, [organizationId])

  const fetchConfigs = async () => {
    if (!organizationId) return

    setIsLoading(true)
    setError(null)

    try {
      const response = await fetch(
        `${API_BASE}/api/v1/organizations/${organizationId}/sso`,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        }
      )

      if (response.ok) {
        const data = await response.json()
        setConfigs(data.configs || [])
      } else {
        const errorData = await response.json().catch(() => ({}))
        setError(errorData.detail || 'Failed to load SSO configurations')
      }
    } catch (err) {
      setError('Failed to connect to server')
    } finally {
      setIsLoading(false)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!organizationId) return

    setIsSaving(true)
    setError(null)

    try {
      const url = editingId
        ? `${API_BASE}/api/v1/organizations/${organizationId}/sso/${editingId}`
        : `${API_BASE}/api/v1/organizations/${organizationId}/sso`

      const method = editingId ? 'PATCH' : 'POST'

      // Build request body
      const body: Record<string, unknown> = {
        provider: formData.provider,
        display_name: formData.display_name || null,
        client_id: formData.client_id,
        auto_create_users: formData.auto_create_users,
        default_role: formData.default_role,
        allowed_email_domains: formData.allowed_email_domains || null,
      }

      // Only include client_secret if provided (for new configs or updates)
      if (formData.client_secret) {
        body.client_secret = formData.client_secret
      }

      // Provider-specific fields
      if (formData.provider === 'okta') {
        body.domain = formData.domain
      } else if (formData.provider === 'azure_ad') {
        body.tenant_id = formData.tenant_id
      } else if (formData.provider === 'saml') {
        body.metadata_url = formData.metadata_url || null
        body.entity_id = formData.entity_id || null
        body.sso_url = formData.sso_url || null
        if (formData.certificate) {
          body.certificate = formData.certificate
        }
      }

      const response = await fetch(url, {
        method,
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      })

      if (response.ok) {
        await fetchConfigs()
        setShowForm(false)
        setEditingId(null)
        setFormData(defaultFormData)
      } else {
        const errorData = await response.json().catch(() => ({}))
        setError(errorData.detail || 'Failed to save SSO configuration')
      }
    } catch (err) {
      setError('Failed to connect to server')
    } finally {
      setIsSaving(false)
    }
  }

  const handleDelete = async (configId: string) => {
    if (!organizationId) return
    if (!confirm('Are you sure you want to delete this SSO configuration?')) return

    try {
      const response = await fetch(
        `${API_BASE}/api/v1/organizations/${organizationId}/sso/${configId}`,
        {
          method: 'DELETE',
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        }
      )

      if (response.ok) {
        await fetchConfigs()
      } else {
        const errorData = await response.json().catch(() => ({}))
        setError(errorData.detail || 'Failed to delete SSO configuration')
      }
    } catch (err) {
      setError('Failed to connect to server')
    }
  }

  const handleTest = async (configId: string) => {
    if (!organizationId) return

    setTestingId(configId)
    setTestResult(null)

    try {
      const response = await fetch(
        `${API_BASE}/api/v1/organizations/${organizationId}/sso/${configId}/test`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        }
      )

      const data = await response.json()
      setTestResult({
        success: data.success,
        message: data.message || data.error || 'Test completed',
      })
    } catch (err) {
      setTestResult({
        success: false,
        message: 'Failed to connect to server',
      })
    } finally {
      setTestingId(null)
    }
  }

  const handleEdit = (config: SSOConfig) => {
    setFormData({
      provider: config.provider,
      display_name: config.display_name || '',
      client_id: config.client_id,
      client_secret: '', // Don't show existing secret
      domain: config.domain || '',
      tenant_id: config.tenant_id || '',
      metadata_url: config.metadata_url || '',
      entity_id: config.entity_id || '',
      sso_url: config.sso_url || '',
      certificate: '',
      allowed_email_domains: config.allowed_email_domains || '',
      auto_create_users: config.auto_create_users,
      default_role: config.default_role,
    })
    setEditingId(config.id)
    setShowForm(true)
  }

  const getProviderName = (provider: string) => {
    const p = PROVIDER_OPTIONS.find((o) => o.id === provider)
    return p?.name || provider
  }

  if (!isAdmin) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold">SSO Settings</h1>
          <p className="text-muted-foreground">Single Sign-On configuration</p>
        </div>
        <div className="rounded-lg border border-yellow-500/20 bg-yellow-500/10 p-4">
          <p className="text-yellow-500">Only organization administrators can manage SSO settings.</p>
        </div>
      </div>
    )
  }

  if (!organizationId) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold">SSO Settings</h1>
          <p className="text-muted-foreground">Single Sign-On configuration</p>
        </div>
        <div className="rounded-lg border border-yellow-500/20 bg-yellow-500/10 p-4">
          <p className="text-yellow-500">You must be part of an organization to configure SSO.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">SSO Settings</h1>
          <p className="text-muted-foreground">Configure Single Sign-On for your organization</p>
        </div>
        {!showForm && (
          <button
            onClick={() => {
              setFormData(defaultFormData)
              setEditingId(null)
              setShowForm(true)
            }}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
          >
            <Plus size={16} />
            Add SSO Provider
          </button>
        )}
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/20 bg-red-500/10 p-4 flex items-start gap-3">
          <AlertCircle className="text-red-500 flex-shrink-0 mt-0.5" size={18} />
          <p className="text-red-500">{error}</p>
        </div>
      )}

      {testResult && (
        <div
          className={`rounded-lg border p-4 flex items-start gap-3 ${
            testResult.success
              ? 'border-green-500/20 bg-green-500/10'
              : 'border-red-500/20 bg-red-500/10'
          }`}
        >
          {testResult.success ? (
            <CheckCircle className="text-green-500 flex-shrink-0 mt-0.5" size={18} />
          ) : (
            <AlertCircle className="text-red-500 flex-shrink-0 mt-0.5" size={18} />
          )}
          <p className={testResult.success ? 'text-green-500' : 'text-red-500'}>
            {testResult.message}
          </p>
        </div>
      )}

      {/* SSO Configuration Form */}
      {showForm && (
        <div className="rounded-lg border bg-background p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-lg font-semibold">
              {editingId ? 'Edit SSO Configuration' : 'Add SSO Provider'}
            </h2>
            <button
              onClick={() => {
                setShowForm(false)
                setEditingId(null)
                setFormData(defaultFormData)
              }}
              className="p-2 hover:bg-accent rounded"
            >
              <X size={18} />
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Provider Selection */}
            <div>
              <label className="block text-sm font-medium mb-2">Identity Provider</label>
              <div className="grid grid-cols-3 gap-3">
                {PROVIDER_OPTIONS.map((provider) => (
                  <button
                    key={provider.id}
                    type="button"
                    onClick={() => setFormData((p) => ({ ...p, provider: provider.id }))}
                    disabled={editingId !== null}
                    className={`p-4 rounded-lg border text-left ${
                      formData.provider === provider.id
                        ? 'border-primary bg-primary/10'
                        : 'hover:bg-accent'
                    } ${editingId ? 'opacity-50 cursor-not-allowed' : ''}`}
                  >
                    <div className="font-medium">{provider.name}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Display Name */}
            <div>
              <label className="block text-sm font-medium mb-2">
                Display Name <span className="text-muted-foreground">(optional)</span>
              </label>
              <input
                type="text"
                value={formData.display_name}
                onChange={(e) => setFormData((p) => ({ ...p, display_name: e.target.value }))}
                placeholder={`Sign in with ${getProviderName(formData.provider)}`}
                className="w-full px-3 py-2 rounded-md border bg-background"
              />
              <p className="text-xs text-muted-foreground mt-1">
                Custom label for the login button
              </p>
            </div>

            {/* OAuth Credentials */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium mb-2">Client ID</label>
                <input
                  type="text"
                  value={formData.client_id}
                  onChange={(e) => setFormData((p) => ({ ...p, client_id: e.target.value }))}
                  required
                  className="w-full px-3 py-2 rounded-md border bg-background"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">
                  Client Secret {editingId && <span className="text-muted-foreground">(leave blank to keep existing)</span>}
                </label>
                <div className="relative">
                  <input
                    type={showSecret ? 'text' : 'password'}
                    value={formData.client_secret}
                    onChange={(e) => setFormData((p) => ({ ...p, client_secret: e.target.value }))}
                    required={!editingId}
                    className="w-full px-3 py-2 pr-10 rounded-md border bg-background"
                  />
                  <button
                    type="button"
                    onClick={() => setShowSecret(!showSecret)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-muted-foreground hover:text-foreground"
                  >
                    {showSecret ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>
            </div>

            {/* Provider-specific fields */}
            {formData.provider === 'okta' && (
              <div>
                <label className="block text-sm font-medium mb-2">Okta Domain</label>
                <input
                  type="text"
                  value={formData.domain}
                  onChange={(e) => setFormData((p) => ({ ...p, domain: e.target.value }))}
                  placeholder="your-org.okta.com"
                  required
                  className="w-full px-3 py-2 rounded-md border bg-background"
                />
              </div>
            )}

            {formData.provider === 'azure_ad' && (
              <div>
                <label className="block text-sm font-medium mb-2">Azure AD Tenant ID</label>
                <input
                  type="text"
                  value={formData.tenant_id}
                  onChange={(e) => setFormData((p) => ({ ...p, tenant_id: e.target.value }))}
                  placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                  required
                  className="w-full px-3 py-2 rounded-md border bg-background"
                />
              </div>
            )}

            {/* Email Domain Restrictions */}
            <div>
              <label className="block text-sm font-medium mb-2">
                Allowed Email Domains <span className="text-muted-foreground">(optional)</span>
              </label>
              <input
                type="text"
                value={formData.allowed_email_domains}
                onChange={(e) => setFormData((p) => ({ ...p, allowed_email_domains: e.target.value }))}
                placeholder="acme.com, acme.org"
                className="w-full px-3 py-2 rounded-md border bg-background"
              />
              <p className="text-xs text-muted-foreground mt-1">
                Comma-separated list. Leave blank to allow any email domain.
              </p>
            </div>

            {/* Auto-provisioning */}
            <div className="flex items-center gap-3">
              <input
                type="checkbox"
                id="auto_create_users"
                checked={formData.auto_create_users}
                onChange={(e) => setFormData((p) => ({ ...p, auto_create_users: e.target.checked }))}
                className="h-4 w-4 rounded border"
              />
              <label htmlFor="auto_create_users" className="text-sm">
                Auto-create users on first SSO login
              </label>
            </div>

            {/* Default Role */}
            <div>
              <label className="block text-sm font-medium mb-2">Default Role for New Users</label>
              <div className="grid grid-cols-3 gap-3">
                {ROLE_OPTIONS.map((role) => (
                  <button
                    key={role.id}
                    type="button"
                    onClick={() => setFormData((p) => ({ ...p, default_role: role.id }))}
                    className={`p-3 rounded-lg border text-left ${
                      formData.default_role === role.id
                        ? 'border-primary bg-primary/10'
                        : 'hover:bg-accent'
                    }`}
                  >
                    <div className="font-medium text-sm">{role.name}</div>
                    <div className="text-xs text-muted-foreground">{role.description}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Actions */}
            <div className="flex justify-end gap-3 pt-4 border-t">
              <button
                type="button"
                onClick={() => {
                  setShowForm(false)
                  setEditingId(null)
                  setFormData(defaultFormData)
                }}
                className="px-4 py-2 rounded-md border hover:bg-accent"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSaving}
                className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
              >
                {isSaving ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Saving...
                  </>
                ) : (
                  <>
                    <Check size={16} />
                    {editingId ? 'Update' : 'Create'} Configuration
                  </>
                )}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Existing Configurations */}
      {isLoading ? (
        <div className="flex items-center justify-center h-32">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
        </div>
      ) : configs.length === 0 && !showForm ? (
        <div className="rounded-lg border bg-background p-8 text-center">
          <Shield className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
          <h3 className="text-lg font-semibold mb-2">No SSO Providers Configured</h3>
          <p className="text-muted-foreground mb-4">
            Add an identity provider to enable Single Sign-On for your organization.
          </p>
          <button
            onClick={() => setShowForm(true)}
            className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
          >
            <Plus size={16} />
            Add SSO Provider
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {configs.map((config) => (
            <div key={config.id} className="rounded-lg border bg-background p-4">
              <div className="flex items-start justify-between">
                <div className="flex items-start gap-4">
                  <div
                    className={`p-3 rounded-lg ${
                      config.is_enabled ? 'bg-green-500/10' : 'bg-muted'
                    }`}
                  >
                    <Shield
                      className={config.is_enabled ? 'text-green-500' : 'text-muted-foreground'}
                      size={24}
                    />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold">
                        {config.display_name || getProviderName(config.provider)}
                      </h3>
                      <span
                        className={`text-xs px-2 py-0.5 rounded ${
                          config.is_enabled
                            ? 'bg-green-500/10 text-green-500'
                            : 'bg-muted text-muted-foreground'
                        }`}
                      >
                        {config.is_enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </div>
                    <p className="text-sm text-muted-foreground">
                      {config.provider === 'okta' && config.domain && `Domain: ${config.domain}`}
                      {config.provider === 'azure_ad' && config.tenant_id && `Tenant: ${config.tenant_id}`}
                      {config.provider === 'google' && 'Google Workspace'}
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">
                      Client ID: {config.client_id.substring(0, 20)}...
                      {config.allowed_email_domains && (
                        <> | Domains: {config.allowed_email_domains}</>
                      )}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleTest(config.id)}
                    disabled={testingId === config.id}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-sm rounded border hover:bg-accent disabled:opacity-50"
                  >
                    {testingId === config.id ? (
                      <div className="w-4 h-4 border-2 border-muted-foreground/30 border-t-muted-foreground rounded-full animate-spin" />
                    ) : (
                      <TestTube size={14} />
                    )}
                    Test
                  </button>
                  <button
                    onClick={() => handleEdit(config)}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-sm rounded border hover:bg-accent"
                  >
                    <Edit2 size={14} />
                    Edit
                  </button>
                  <button
                    onClick={() => handleDelete(config.id)}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-sm rounded border border-red-500/20 text-red-500 hover:bg-red-500/10"
                  >
                    <Trash2 size={14} />
                    Delete
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Help Section */}
      <div className="rounded-lg border bg-background p-6">
        <h3 className="font-semibold mb-4">Setup Instructions</h3>
        <div className="space-y-4 text-sm text-muted-foreground">
          <div>
            <h4 className="font-medium text-foreground">Google Workspace</h4>
            <ol className="list-decimal ml-4 mt-1 space-y-1">
              <li>Go to Google Cloud Console and create a new OAuth 2.0 credential</li>
              <li>Set the redirect URI to: <code className="text-xs bg-muted px-1 py-0.5 rounded">{window.location.origin}/api/v1/auth/sso/[config_id]/callback</code></li>
              <li>Copy the Client ID and Client Secret</li>
            </ol>
          </div>
          <div>
            <h4 className="font-medium text-foreground">Okta</h4>
            <ol className="list-decimal ml-4 mt-1 space-y-1">
              <li>In Okta Admin, create a new OIDC Web Application</li>
              <li>Set the redirect URI to: <code className="text-xs bg-muted px-1 py-0.5 rounded">{window.location.origin}/api/v1/auth/sso/[config_id]/callback</code></li>
              <li>Copy the Client ID, Client Secret, and your Okta domain</li>
            </ol>
          </div>
          <div>
            <h4 className="font-medium text-foreground">Microsoft Azure AD</h4>
            <ol className="list-decimal ml-4 mt-1 space-y-1">
              <li>In Azure Portal, register a new application</li>
              <li>Add a Web redirect URI: <code className="text-xs bg-muted px-1 py-0.5 rounded">{window.location.origin}/api/v1/auth/sso/[config_id]/callback</code></li>
              <li>Copy the Application (client) ID, create a client secret, and note the Directory (tenant) ID</li>
            </ol>
          </div>
        </div>
      </div>
    </div>
  )
}
