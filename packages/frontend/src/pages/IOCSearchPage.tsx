import { useState } from 'react'
import { Search, Globe, Shield, Clock, ExternalLink } from 'lucide-react'
import {
  useSearchIOCMutation,
  useGetIndicatorTypesQuery,
  useLookupThreatIntelMutation,
  useGetThreatIntelStatusQuery,
} from '../api/pantherApi'

export default function IOCSearchPage() {
  const [indicator, setIndicator] = useState('')
  const [indicatorType, setIndicatorType] = useState('')
  const [timeRange, setTimeRange] = useState(7)

  const { data: indicatorTypes } = useGetIndicatorTypesQuery()
  const { data: threatIntelStatus } = useGetThreatIntelStatusQuery()
  const [searchIOC, { data: searchResult, isLoading: isSearching }] = useSearchIOCMutation()
  const [lookupThreatIntel, { data: threatIntelResult, isLoading: isLookingUp }] = useLookupThreatIntelMutation()

  const handleSearch = async () => {
    if (!indicator.trim()) return
    await searchIOC({
      indicator: indicator.trim(),
      indicator_type: indicatorType || undefined,
      time_range_days: timeRange,
    })
  }

  const handleThreatIntelLookup = async () => {
    if (!indicator.trim() || !searchResult) return
    await lookupThreatIntel({
      indicator: indicator.trim(),
      indicator_type: searchResult.indicator_type,
    })
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">IOC Search</h1>
        <p className="text-muted-foreground">Search for indicators of compromise across your logs</p>
      </div>

      {/* Search Form */}
      <div className="rounded-lg border bg-background p-6">
        <div className="flex flex-col gap-4 md:flex-row">
          <div className="flex-1">
            <label className="block text-sm font-medium mb-2">Indicator</label>
            <input
              type="text"
              value={indicator}
              onChange={(e) => setIndicator(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              placeholder="IP, domain, hash, email, or username..."
              className="w-full rounded-md border bg-background px-4 py-2 text-sm"
            />
          </div>
          <div className="w-full md:w-48">
            <label className="block text-sm font-medium mb-2">Type (auto-detect)</label>
            <select
              value={indicatorType}
              onChange={(e) => setIndicatorType(e.target.value)}
              className="w-full rounded-md border bg-background px-3 py-2 text-sm"
            >
              <option value="">Auto-detect</option>
              {indicatorTypes?.map((type) => (
                <option key={type.value} value={type.value}>
                  {type.label}
                </option>
              ))}
            </select>
          </div>
          <div className="w-full md:w-36">
            <label className="block text-sm font-medium mb-2">Time Range</label>
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(Number(e.target.value))}
              className="w-full rounded-md border bg-background px-3 py-2 text-sm"
            >
              <option value={1}>Last 24 hours</option>
              <option value={7}>Last 7 days</option>
              <option value={14}>Last 14 days</option>
              <option value={30}>Last 30 days</option>
            </select>
          </div>
          <div className="flex items-end">
            <button
              onClick={handleSearch}
              disabled={isSearching || !indicator.trim()}
              className="flex items-center gap-2 px-6 py-2 bg-primary text-primary-foreground rounded-md font-medium hover:bg-primary/90 disabled:opacity-50"
            >
              <Search size={18} />
              {isSearching ? 'Searching...' : 'Search'}
            </button>
          </div>
        </div>
      </div>

      {/* Results */}
      {searchResult && (
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Log Search Results */}
          <div className="rounded-lg border bg-background p-6">
            <h3 className="font-semibold mb-4 flex items-center gap-2">
              <Search size={18} />
              Log Search Results
            </h3>

            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-sm text-muted-foreground">Indicator:</span>
                  <span className="ml-2 font-mono">{searchResult.indicator}</span>
                </div>
                <span className="px-2 py-1 bg-muted rounded text-xs">
                  {searchResult.indicator_type}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="p-3 bg-muted/50 rounded">
                  <div className="text-2xl font-bold">{searchResult.total_matches}</div>
                  <div className="text-sm text-muted-foreground">Total Matches</div>
                </div>
                <div className="p-3 bg-muted/50 rounded">
                  <div className="text-2xl font-bold">{searchResult.sources.length}</div>
                  <div className="text-sm text-muted-foreground">Log Sources</div>
                </div>
              </div>

              {searchResult.first_seen && (
                <div className="flex items-center gap-4 text-sm">
                  <div className="flex items-center gap-1">
                    <Clock size={14} className="text-muted-foreground" />
                    <span className="text-muted-foreground">First seen:</span>
                    <span>{new Date(searchResult.first_seen).toLocaleString()}</span>
                  </div>
                </div>
              )}

              {searchResult.sources.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium mb-2">By Source</h4>
                  <div className="space-y-2">
                    {searchResult.sources.map((source, i) => (
                      <div key={i} className="flex items-center justify-between p-2 bg-muted/30 rounded">
                        <span className="text-sm">{source.source}</span>
                        <span className="text-sm font-medium">{source.count} hits</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {searchResult.total_matches === 0 && (
                <div className="text-center py-6 text-muted-foreground">
                  No matches found in logs
                </div>
              )}
            </div>
          </div>

          {/* Threat Intel */}
          <div className="rounded-lg border bg-background p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold flex items-center gap-2">
                <Globe size={18} />
                Threat Intelligence
              </h3>
              <button
                onClick={handleThreatIntelLookup}
                disabled={isLookingUp}
                className="flex items-center gap-1 px-3 py-1 text-sm border rounded hover:bg-accent disabled:opacity-50"
              >
                {isLookingUp ? 'Looking up...' : 'Lookup'}
              </button>
            </div>

            {!threatIntelResult && !isLookingUp && (
              <div className="text-center py-8 text-muted-foreground">
                Click "Lookup" to check threat intelligence feeds
              </div>
            )}

            {threatIntelResult && (
              <div className="space-y-4">
                {/* VirusTotal */}
                <div className="p-4 bg-muted/30 rounded">
                  <div className="flex items-center gap-2 mb-2">
                    <Shield size={16} />
                    <span className="font-medium">VirusTotal</span>
                    {!!threatIntelResult.virustotal?.found && (
                      <a
                        href={`https://www.virustotal.com/gui/search/${searchResult.indicator}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="ml-auto text-xs text-primary hover:underline flex items-center gap-1"
                      >
                        View <ExternalLink size={12} />
                      </a>
                    )}
                  </div>
                  {threatIntelResult.virustotal?.error ? (
                    <p className="text-sm text-muted-foreground">{String(threatIntelResult.virustotal.error)}</p>
                  ) : threatIntelResult.virustotal?.found ? (
                    <div className="space-y-2 text-sm">
                      {!!threatIntelResult.virustotal.last_analysis_stats && (
                        <div className="flex items-center gap-2">
                          <span className="text-muted-foreground">Detection:</span>
                          <span className="text-red-400">
                            {(threatIntelResult.virustotal.last_analysis_stats as Record<string, number>).malicious || 0} malicious
                          </span>
                          <span className="text-yellow-400">
                            {(threatIntelResult.virustotal.last_analysis_stats as Record<string, number>).suspicious || 0} suspicious
                          </span>
                        </div>
                      )}
                      {!!threatIntelResult.virustotal.country && (
                        <div>
                          <span className="text-muted-foreground">Country:</span>
                          <span className="ml-2">{threatIntelResult.virustotal.country as string}</span>
                        </div>
                      )}
                      {!!threatIntelResult.virustotal.as_owner && (
                        <div>
                          <span className="text-muted-foreground">AS Owner:</span>
                          <span className="ml-2">{threatIntelResult.virustotal.as_owner as string}</span>
                        </div>
                      )}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground">Not found in VirusTotal</p>
                  )}
                </div>

                {/* AbuseIPDB */}
                {searchResult.indicator_type === 'ip' && (
                  <div className="p-4 bg-muted/30 rounded">
                    <div className="flex items-center gap-2 mb-2">
                      <Shield size={16} />
                      <span className="font-medium">AbuseIPDB</span>
                    </div>
                    {threatIntelResult.abuseipdb?.error ? (
                      <p className="text-sm text-muted-foreground">{threatIntelResult.abuseipdb.error as string}</p>
                    ) : threatIntelResult.abuseipdb?.found ? (
                      <div className="space-y-2 text-sm">
                        <div className="flex items-center gap-2">
                          <span className="text-muted-foreground">Confidence Score:</span>
                          <span className={`font-medium ${
                            (threatIntelResult.abuseipdb.abuse_confidence_score as number) > 50 ? 'text-red-400' :
                            (threatIntelResult.abuseipdb.abuse_confidence_score as number) > 20 ? 'text-yellow-400' :
                            'text-green-400'
                          }`}>
                            {threatIntelResult.abuseipdb.abuse_confidence_score as number}%
                          </span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Reports:</span>
                          <span className="ml-2">{threatIntelResult.abuseipdb.total_reports as number}</span>
                        </div>
                        {!!threatIntelResult.abuseipdb.isp && (
                          <div>
                            <span className="text-muted-foreground">ISP:</span>
                            <span className="ml-2">{threatIntelResult.abuseipdb.isp as string}</span>
                          </div>
                        )}
                        {!!threatIntelResult.abuseipdb.is_tor && (
                          <span className="px-2 py-0.5 bg-yellow-500/20 text-yellow-400 rounded text-xs">
                            Tor Exit Node
                          </span>
                        )}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground">Not found in AbuseIPDB</p>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Status */}
            {threatIntelStatus && (
              <div className="mt-4 pt-4 border-t text-xs text-muted-foreground">
                <span>Configured: </span>
                {threatIntelStatus.virustotal.configured && <span className="text-green-400">VirusTotal</span>}
                {threatIntelStatus.virustotal.configured && threatIntelStatus.abuseipdb.configured && ', '}
                {threatIntelStatus.abuseipdb.configured && <span className="text-green-400">AbuseIPDB</span>}
                {!threatIntelStatus.virustotal.configured && !threatIntelStatus.abuseipdb.configured && (
                  <span>None (add API keys in environment)</span>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {!searchResult && (
        <div className="rounded-lg border bg-background p-12 text-center text-muted-foreground">
          <Search size={48} className="mx-auto mb-4 opacity-20" />
          <p>Enter an indicator to search across your logs and threat intel feeds</p>
          <p className="text-sm mt-2">Supports: IP addresses, domains, hashes, emails, usernames</p>
        </div>
      )}
    </div>
  )
}
