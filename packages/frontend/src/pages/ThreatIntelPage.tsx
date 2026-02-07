import { useState } from 'react'
import {
  Search,
  Shield,
  Globe,
  Hash,
  Link,
  Mail,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Plus,
  Loader2,
} from 'lucide-react'
import {
  useUnifiedThreatIntelLookupQuery,
  useGetThreatIntelSourcesQuery,
  useCreateIOCMutation,
  type IOCType,
} from '../api/pantherApi'
import { cn } from '../lib/utils'

const RISK_COLORS: Record<string, string> = {
  critical: 'bg-red-500 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  clean: 'bg-green-500 text-white',
  unknown: 'bg-gray-500 text-white',
}

const INDICATOR_TYPES = [
  { value: 'ip_address', label: 'IP Address', icon: Globe },
  { value: 'domain', label: 'Domain', icon: Globe },
  { value: 'url', label: 'URL', icon: Link },
  { value: 'file_hash_md5', label: 'MD5 Hash', icon: Hash },
  { value: 'file_hash_sha1', label: 'SHA1 Hash', icon: Hash },
  { value: 'file_hash_sha256', label: 'SHA256 Hash', icon: Hash },
  { value: 'email', label: 'Email', icon: Mail },
]

export default function ThreatIntelPage() {
  const [indicator, setIndicator] = useState('')
  const [indicatorType, setIndicatorType] = useState('ip_address')
  const [searchTriggered, setSearchTriggered] = useState(false)

  const { data: sources } = useGetThreatIntelSourcesQuery()
  const { data: results, isLoading, isFetching } = useUnifiedThreatIntelLookupQuery(
    { indicator, indicator_type: indicatorType },
    { skip: !searchTriggered || !indicator }
  )

  const [createIOC] = useCreateIOCMutation()

  const handleSearch = () => {
    if (indicator) {
      setSearchTriggered(true)
    }
  }

  const handleAddToIOC = async () => {
    if (!results) return
    try {
      await createIOC({
        ioc_type: indicatorType as IOCType,
        value: indicator,
        severity: results.aggregate_risk_level === 'critical' ? 'critical' :
                  results.aggregate_risk_level === 'high' ? 'high' :
                  results.aggregate_risk_level === 'medium' ? 'medium' : 'low',
        description: `Added from threat intel lookup - Risk score: ${results.aggregate_score}`,
        tags: ['threat-intel'],
      })
      alert('Added to IOC database')
    } catch (e) {
      alert('Failed to add to IOC database')
    }
  }

  const TypeIcon = INDICATOR_TYPES.find(t => t.value === indicatorType)?.icon || Shield

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-semibold flex items-center gap-2">
          <Shield size={24} />
          Threat Intelligence Lookup
        </h1>
        <p className="text-muted-foreground mt-1">
          Search indicators across multiple threat intelligence sources
        </p>
      </div>

      {/* Search Form */}
      <div className="bg-card rounded-lg border p-6">
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex-1">
            <label className="block text-sm font-medium mb-2">Indicator Value</label>
            <div className="relative">
              <TypeIcon size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
              <input
                type="text"
                value={indicator}
                onChange={(e) => {
                  setIndicator(e.target.value)
                  setSearchTriggered(false)
                }}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                placeholder="Enter IP, domain, hash, URL, or email..."
                className="w-full pl-10 pr-4 py-3 bg-background border rounded-md"
              />
            </div>
          </div>
          <div className="w-full md:w-48">
            <label className="block text-sm font-medium mb-2">Type</label>
            <select
              value={indicatorType}
              onChange={(e) => {
                setIndicatorType(e.target.value)
                setSearchTriggered(false)
              }}
              className="w-full px-3 py-3 bg-background border rounded-md"
            >
              {INDICATOR_TYPES.map((type) => (
                <option key={type.value} value={type.value}>{type.label}</option>
              ))}
            </select>
          </div>
          <div className="flex items-end">
            <button
              onClick={handleSearch}
              disabled={!indicator || isLoading}
              className="px-6 py-3 bg-primary text-primary-foreground rounded-md flex items-center gap-2 disabled:opacity-50"
            >
              {isLoading || isFetching ? (
                <Loader2 size={18} className="animate-spin" />
              ) : (
                <Search size={18} />
              )}
              Search
            </button>
          </div>
        </div>

        {/* Available Sources */}
        {sources && (
          <div className="mt-4 pt-4 border-t">
            <p className="text-sm text-muted-foreground mb-2">Available Sources:</p>
            <div className="flex flex-wrap gap-2">
              {Object.entries(sources).map(([name, info]) => (
                <span
                  key={name}
                  className={cn(
                    'text-xs px-2 py-1 rounded flex items-center gap-1',
                    info.configured ? 'bg-green-500/10 text-green-500' : 'bg-gray-500/10 text-gray-500'
                  )}
                >
                  {info.configured ? <CheckCircle size={12} /> : <XCircle size={12} />}
                  {name}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Results */}
      {results && (
        <div className="space-y-4">
          {/* Aggregate Score */}
          <div className="bg-card rounded-lg border p-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold">Aggregate Risk Assessment</h2>
                <p className="text-sm text-muted-foreground mt-1">
                  {results.indicator} ({results.indicator_type})
                </p>
              </div>
              <div className="flex items-center gap-4">
                <div className="text-right">
                  <p className="text-3xl font-bold">{results.aggregate_score}</p>
                  <p className="text-xs text-muted-foreground">Risk Score</p>
                </div>
                <span className={cn(
                  'px-4 py-2 rounded-lg font-semibold text-lg',
                  RISK_COLORS[results.aggregate_risk_level]
                )}>
                  {results.aggregate_risk_level.toUpperCase()}
                </span>
              </div>
            </div>
            <div className="flex items-center gap-4 mt-4">
              <p className="text-sm text-muted-foreground">
                Checked {results.total_providers_checked} sources, {results.providers_with_data} returned data
              </p>
              {results.aggregate_risk_level !== 'clean' && results.aggregate_risk_level !== 'unknown' && (
                <button
                  onClick={handleAddToIOC}
                  className="flex items-center gap-2 px-3 py-1 bg-primary text-primary-foreground rounded-md text-sm"
                >
                  <Plus size={14} />
                  Add to IOC Database
                </button>
              )}
            </div>
          </div>

          {/* Provider Results */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {Object.entries(results.providers).map(([provider, data]) => (
              <ProviderResultCard key={provider} provider={provider} data={data} />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function ProviderResultCard({
  provider,
  data,
}: {
  provider: string
  data: { data?: Record<string, unknown>; error?: string; available: boolean }
}) {
  const [expanded, setExpanded] = useState(false)

  if (!data.available) {
    return (
      <div className="bg-card rounded-lg border p-4">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold capitalize">{provider}</h3>
          <span className="text-xs text-red-500 flex items-center gap-1">
            <XCircle size={12} />
            Error
          </span>
        </div>
        <p className="text-sm text-muted-foreground mt-2">{data.error || 'Provider unavailable'}</p>
      </div>
    )
  }

  const providerData = data.data || {}
  const riskLevel = providerData.risk_level as string || 'unknown'
  const found = providerData.found as boolean

  return (
    <div className="bg-card rounded-lg border overflow-hidden">
      <div className="p-4">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold capitalize">{provider}</h3>
          {found !== undefined && (
            <span className={cn(
              'text-xs px-2 py-0.5 rounded',
              found ? RISK_COLORS[riskLevel] || 'bg-yellow-500' : 'bg-green-500/10 text-green-500'
            )}>
              {found ? riskLevel : 'Not Found'}
            </span>
          )}
        </div>

        {/* Key metrics based on provider */}
        <div className="mt-3 space-y-2">
          {provider === 'abuseipdb' && providerData.abuse_confidence_score !== undefined && (
            <>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Abuse Score:</span>
                <span className="font-medium">{String(providerData.abuse_confidence_score)}%</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Reports:</span>
                <span>{String(providerData.total_reports ?? 0)}</span>
              </div>
              {providerData.country_code && (
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Country:</span>
                  <span>{String(providerData.country_code)}</span>
                </div>
              )}
            </>
          )}

          {provider === 'otx' && (
            <>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Pulse Count:</span>
                <span className="font-medium">{String(providerData.pulse_count ?? 0)}</span>
              </div>
              {(providerData.tags as string[])?.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-2">
                  {(providerData.tags as string[]).slice(0, 5).map((tag, i) => (
                    <span key={i} className="text-xs bg-accent px-1.5 py-0.5 rounded">{tag}</span>
                  ))}
                </div>
              )}
            </>
          )}

          {provider === 'abusech' && (
            <>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Found:</span>
                <span className={found ? 'text-red-500 font-medium' : 'text-green-500'}>{found ? 'Yes' : 'No'}</span>
              </div>
              {providerData.signature && (
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Malware:</span>
                  <span className="text-red-500">{providerData.signature as string}</span>
                </div>
              )}
            </>
          )}
        </div>

        {/* Expand for raw data */}
        <button
          onClick={() => setExpanded(!expanded)}
          className="text-xs text-muted-foreground hover:text-foreground mt-3"
        >
          {expanded ? 'Hide details' : 'Show details'}
        </button>
      </div>

      {expanded && (
        <div className="border-t bg-muted/30 p-4">
          <pre className="text-xs overflow-auto max-h-48">
            {JSON.stringify(providerData, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}
