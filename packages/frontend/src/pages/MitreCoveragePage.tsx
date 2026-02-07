import { useState } from 'react'
import { Shield, Plus, Search, X, ChevronDown, ChevronRight, Edit, Trash2, AlertTriangle, Activity } from 'lucide-react'
import {
  useGetMitreCoverageQuery,
  useGetMitreAlertCoverageQuery,
  useGetMitreTacticsQuery,
  useGetMitreMappingsQuery,
  useCreateMitreMappingMutation,
  useUpdateMitreMappingMutation,
  useDeleteMitreMappingMutation,
  type MitreMappingResponse,
  type MitreMappingCreate,
  type MitreTactic,
  type TacticCoverage,
  type AlertTacticCoverage,
} from '../api/pantherApi'
import { useListRulesQuery } from '../api/pantherApi'
import { cn } from '../lib/utils'

type CoverageTab = 'alerts' | 'rules'

export default function MitreCoveragePage() {
  const [activeTab, setActiveTab] = useState<CoverageTab>('alerts')
  const [alertDays, setAlertDays] = useState(30)
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [editingMapping, setEditingMapping] = useState<MitreMappingResponse | null>(null)
  const [searchTerm, setSearchTerm] = useState('')
  const [expandedTactics, setExpandedTactics] = useState<Set<string>>(new Set())

  const { data: coverage, isLoading: coverageLoading } = useGetMitreCoverageQuery()
  const { data: alertCoverage, isLoading: alertCoverageLoading } = useGetMitreAlertCoverageQuery({ days: alertDays })
  const { data: tactics } = useGetMitreTacticsQuery()
  const { data: mappings, isLoading: mappingsLoading } = useGetMitreMappingsQuery({
    tactic: selectedTactic || undefined,
  })
  const { data: rules } = useListRulesQuery({ pageSize: 1000 })
  const [createMapping] = useCreateMitreMappingMutation()
  const [updateMapping] = useUpdateMitreMappingMutation()
  const [deleteMapping] = useDeleteMitreMappingMutation()

  const toggleTacticExpansion = (tactic: string) => {
    const newExpanded = new Set(expandedTactics)
    if (newExpanded.has(tactic)) {
      newExpanded.delete(tactic)
    } else {
      newExpanded.add(tactic)
    }
    setExpandedTactics(newExpanded)
  }

  const handleCreateMapping = async (data: MitreMappingCreate) => {
    try {
      await createMapping(data).unwrap()
      setShowCreateModal(false)
    } catch (error) {
      console.error('Failed to create mapping:', error)
    }
  }

  const handleUpdateMapping = async (id: string, data: Partial<MitreMappingCreate>) => {
    try {
      await updateMapping({ id, update: data }).unwrap()
      setEditingMapping(null)
    } catch (error) {
      console.error('Failed to update mapping:', error)
    }
  }

  const handleDeleteMapping = async (id: string) => {
    if (!confirm('Are you sure you want to delete this MITRE mapping?')) return
    try {
      await deleteMapping(id).unwrap()
    } catch (error) {
      console.error('Failed to delete mapping:', error)
    }
  }

  const filteredMappings = mappings?.filter(
    (m) =>
      m.technique_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      m.technique_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      m.rule_name.toLowerCase().includes(searchTerm.toLowerCase())
  )

  const getCoverageColor = (count: number): string => {
    if (count === 0) return 'bg-gray-100 dark:bg-gray-800'
    if (count <= 2) return 'bg-yellow-100 dark:bg-yellow-900/30'
    if (count <= 5) return 'bg-green-100 dark:bg-green-900/30'
    return 'bg-green-200 dark:bg-green-800/50'
  }

  const getCoverageTextColor = (count: number): string => {
    if (count === 0) return 'text-gray-400'
    if (count <= 2) return 'text-yellow-700 dark:text-yellow-400'
    return 'text-green-700 dark:text-green-400'
  }

  const isLoading = activeTab === 'alerts' ? alertCoverageLoading : coverageLoading

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="w-8 h-8 text-blue-500" />
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
              MITRE ATT&CK Coverage
            </h1>
            <p className="text-gray-600 dark:text-gray-400">
              Track MITRE coverage from alerts and rule mappings
            </p>
          </div>
        </div>
        {activeTab === 'rules' && (
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            <Plus className="w-4 h-4" />
            Add Mapping
          </button>
        )}
        {activeTab === 'alerts' && (
          <select
            value={alertDays}
            onChange={(e) => setAlertDays(Number(e.target.value))}
            className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
          >
            <option value={7}>Last 7 days</option>
            <option value={14}>Last 14 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
          </select>
        )}
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-gray-200 dark:border-gray-700">
        <button
          onClick={() => setActiveTab('alerts')}
          className={cn(
            'flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors',
            activeTab === 'alerts'
              ? 'border-blue-500 text-blue-600 dark:text-blue-400'
              : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400'
          )}
        >
          <Activity className="w-4 h-4" />
          Alert Coverage
        </button>
        <button
          onClick={() => setActiveTab('rules')}
          className={cn(
            'flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors',
            activeTab === 'rules'
              ? 'border-blue-500 text-blue-600 dark:text-blue-400'
              : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400'
          )}
        >
          <Shield className="w-4 h-4" />
          Rule Mappings
        </button>
      </div>

      {/* Alert Coverage Tab */}
      {activeTab === 'alerts' && alertCoverage && (
        <>
          {/* Alert Coverage Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <div className="text-2xl font-bold text-orange-600">{alertCoverage.total_alerts_with_mitre.toLocaleString()}</div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Alerts with MITRE Data</div>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <div className="text-2xl font-bold text-blue-600">{alertCoverage.total_techniques_detected}</div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Techniques Detected</div>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <div className="text-2xl font-bold text-purple-600">{alertCoverage.total_tactics_detected}</div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Tactics Detected</div>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <div className="text-2xl font-bold text-gray-600">{alertCoverage.period_days}</div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Day Period</div>
            </div>
          </div>

          {/* Alert Coverage Matrix */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div className="p-4 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                Detected Techniques by Tactic
              </h2>
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                Based on alerts ingested from your connected data sources
              </p>
            </div>
            <div className="p-4">
              {alertCoverage.by_tactic.map((tactic: AlertTacticCoverage) => (
                <div key={tactic.tactic} className="mb-2">
                  <button
                    onClick={() => toggleTacticExpansion(tactic.tactic)}
                    className={cn(
                      'w-full flex items-center justify-between p-3 rounded-lg transition-colors',
                      tactic.alert_count > 0
                        ? 'bg-orange-50 dark:bg-orange-900/20'
                        : 'bg-gray-100 dark:bg-gray-800'
                    )}
                  >
                    <div className="flex items-center gap-3">
                      {expandedTactics.has(tactic.tactic) ? (
                        <ChevronDown className="w-5 h-5 text-gray-500" />
                      ) : (
                        <ChevronRight className="w-5 h-5 text-gray-500" />
                      )}
                      <span className="font-medium text-gray-900 dark:text-white">
                        {tactic.label}
                      </span>
                    </div>
                    <div className="flex items-center gap-4 text-sm">
                      <span className={cn(
                        'font-semibold',
                        tactic.alert_count > 0 ? 'text-orange-600' : 'text-gray-400'
                      )}>
                        {tactic.alert_count.toLocaleString()} alerts
                      </span>
                      <span className={cn(
                        tactic.technique_count > 0 ? 'text-blue-600' : 'text-gray-400'
                      )}>
                        {tactic.technique_count} techniques
                      </span>
                    </div>
                  </button>

                  {expandedTactics.has(tactic.tactic) && tactic.techniques.length > 0 && (
                    <div className="ml-8 mt-2 space-y-1">
                      {tactic.techniques.map((tech) => (
                        <div
                          key={tech.technique_id}
                          className="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-700/50 rounded"
                        >
                          <div>
                            <span className="font-mono text-sm text-blue-600 dark:text-blue-400 mr-2">
                              {tech.technique_id}
                            </span>
                            <span className="text-gray-900 dark:text-white">{tech.technique_name}</span>
                          </div>
                          <div className="flex items-center gap-4 text-sm">
                            <span className="text-orange-600 font-medium">
                              {tech.alert_count.toLocaleString()} alerts
                            </span>
                            <span className="text-gray-500">
                              {tech.rule_count} rules
                            </span>
                            {tech.severities && Object.keys(tech.severities).length > 0 && (
                              <div className="flex gap-1">
                                {tech.severities.critical && (
                                  <span className="px-1.5 py-0.5 text-xs bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 rounded">
                                    {tech.severities.critical} crit
                                  </span>
                                )}
                                {tech.severities.high && (
                                  <span className="px-1.5 py-0.5 text-xs bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400 rounded">
                                    {tech.severities.high} high
                                  </span>
                                )}
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Top Techniques */}
          {alertCoverage.top_techniques.length > 0 && (
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
              <div className="p-4 border-b border-gray-200 dark:border-gray-700">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Top Detected Techniques
                </h2>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                  <thead className="bg-gray-50 dark:bg-gray-900/50">
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Technique</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Alerts</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Rules</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Top Triggering Rules</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                    {alertCoverage.top_techniques.slice(0, 10).map((tech) => (
                      <tr key={tech.technique_id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                        <td className="px-4 py-3">
                          <span className="font-mono text-sm text-blue-600 dark:text-blue-400">
                            {tech.technique_id}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="font-semibold text-orange-600">
                            {tech.alert_count.toLocaleString()}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-gray-600 dark:text-gray-400">
                          {tech.rule_count}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-1">
                            {tech.rules.slice(0, 3).map((rule, idx) => (
                              <span
                                key={idx}
                                className="px-2 py-0.5 text-xs bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded truncate max-w-[200px]"
                                title={rule}
                              >
                                {rule}
                              </span>
                            ))}
                            {tech.rules.length > 3 && (
                              <span className="text-xs text-gray-500">+{tech.rules.length - 3} more</span>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}

      {/* Rule Mappings Tab - Original Content */}
      {activeTab === 'rules' && (
        <>
          {/* Summary Stats */}
          {coverage && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                <div className="text-2xl font-bold text-blue-600">{coverage.total_techniques}</div>
                <div className="text-sm text-gray-600 dark:text-gray-400">Techniques Covered</div>
              </div>
              <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                <div className="text-2xl font-bold text-green-600">{coverage.total_mapped_rules}</div>
                <div className="text-sm text-gray-600 dark:text-gray-400">Rules Mapped</div>
              </div>
              <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                <div className="text-2xl font-bold text-purple-600">
                  {coverage.by_tactic.filter((t) => t.technique_count > 0).length}
                </div>
                <div className="text-sm text-gray-600 dark:text-gray-400">
                  Tactics with Coverage (of {coverage.by_tactic.length})
                </div>
              </div>
            </div>
          )}

      {/* Coverage Matrix */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="p-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            Coverage Matrix by Tactic
          </h2>
        </div>
        <div className="p-4">
          {coverage?.by_tactic.map((tactic: TacticCoverage) => (
            <div
              key={tactic.tactic}
              className="mb-2"
            >
              <button
                onClick={() => {
                  toggleTacticExpansion(tactic.tactic)
                  setSelectedTactic(tactic.tactic)
                }}
                className={`w-full flex items-center justify-between p-3 rounded-lg transition-colors ${getCoverageColor(tactic.technique_count)}`}
              >
                <div className="flex items-center gap-3">
                  {expandedTactics.has(tactic.tactic) ? (
                    <ChevronDown className="w-5 h-5 text-gray-500" />
                  ) : (
                    <ChevronRight className="w-5 h-5 text-gray-500" />
                  )}
                  <span className="font-medium text-gray-900 dark:text-white">
                    {tactic.label}
                  </span>
                </div>
                <span className={`font-semibold ${getCoverageTextColor(tactic.technique_count)}`}>
                  {tactic.technique_count} technique{tactic.technique_count !== 1 ? 's' : ''}
                </span>
              </button>

              {expandedTactics.has(tactic.tactic) && tactic.techniques.length > 0 && (
                <div className="ml-8 mt-2 space-y-1">
                  {tactic.techniques.map((tech) => (
                    <div
                      key={tech.technique_id}
                      className="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-700/50 rounded"
                    >
                      <div>
                        <span className="font-mono text-sm text-blue-600 dark:text-blue-400 mr-2">
                          {tech.technique_id}
                        </span>
                        <span className="text-gray-900 dark:text-white">{tech.technique_name}</span>
                      </div>
                      <span className="text-sm text-gray-600 dark:text-gray-400">
                        {tech.rule_count} rule{tech.rule_count !== 1 ? 's' : ''}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Mappings List */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="p-4 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
              Rule Mappings
              {selectedTactic && (
                <span className="ml-2 text-sm font-normal text-gray-500">
                  (filtered by tactic)
                </span>
              )}
            </h2>
            <div className="flex items-center gap-4">
              {selectedTactic && (
                <button
                  onClick={() => setSelectedTactic(null)}
                  className="text-sm text-blue-600 hover:text-blue-700"
                >
                  Clear filter
                </button>
              )}
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search mappings..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-9 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
            </div>
          </div>
        </div>

        {mappingsLoading ? (
          <div className="p-8 text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mx-auto" />
          </div>
        ) : filteredMappings && filteredMappings.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-900/50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Technique
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Tactic
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Rule
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Notes
                  </th>
                  <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {filteredMappings.map((mapping) => (
                  <tr key={mapping.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                    <td className="px-4 py-3">
                      <div>
                        <span className="font-mono text-sm text-blue-600 dark:text-blue-400">
                          {mapping.technique_id}
                        </span>
                        {mapping.subtechnique_id && (
                          <span className="font-mono text-sm text-gray-500">
                            .{mapping.subtechnique_id.split('.')[1]}
                          </span>
                        )}
                      </div>
                      <div className="text-sm text-gray-900 dark:text-white">
                        {mapping.technique_name}
                        {mapping.subtechnique_name && (
                          <span className="text-gray-500">: {mapping.subtechnique_name}</span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center px-2 py-1 text-xs font-medium rounded-full bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300">
                        {tactics?.find((t) => t.value === mapping.tactic)?.label || mapping.tactic}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="text-sm text-gray-900 dark:text-white font-medium">
                        {mapping.rule_name}
                      </div>
                      <div className="text-xs text-gray-500 font-mono">{mapping.rule_id}</div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-gray-600 dark:text-gray-400">
                        {mapping.notes || '-'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => setEditingMapping(mapping)}
                          className="p-1.5 text-gray-400 hover:text-blue-600 dark:hover:text-blue-400"
                        >
                          <Edit className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDeleteMapping(mapping.id)}
                          className="p-1.5 text-gray-400 hover:text-red-600 dark:hover:text-red-400"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-8 text-center text-gray-500 dark:text-gray-400">
            No MITRE mappings found.{' '}
            <button
              onClick={() => setShowCreateModal(true)}
              className="text-blue-600 hover:text-blue-700"
            >
              Create one
            </button>
          </div>
        )}
      </div>
        </>
      )}

      {/* Create/Edit Modal */}
      {(showCreateModal || editingMapping) && (
        <MappingModal
          mapping={editingMapping}
          tactics={tactics || []}
          rules={rules?.data || []}
          onClose={() => {
            setShowCreateModal(false)
            setEditingMapping(null)
          }}
          onSave={(data) => {
            if (editingMapping) {
              handleUpdateMapping(editingMapping.id, data)
            } else {
              handleCreateMapping(data as MitreMappingCreate)
            }
          }}
        />
      )}
    </div>
  )
}

interface MappingModalProps {
  mapping: MitreMappingResponse | null
  tactics: { value: string; label: string }[]
  rules: { id: string; displayName?: string }[]
  onClose: () => void
  onSave: (data: Partial<MitreMappingCreate>) => void
}

function MappingModal({ mapping, tactics, rules, onClose, onSave }: MappingModalProps) {
  const [formData, setFormData] = useState<Partial<MitreMappingCreate>>({
    rule_id: mapping?.rule_id || '',
    rule_name: mapping?.rule_name || '',
    technique_id: mapping?.technique_id || '',
    technique_name: mapping?.technique_name || '',
    subtechnique_id: mapping?.subtechnique_id || undefined,
    subtechnique_name: mapping?.subtechnique_name || undefined,
    tactic: mapping?.tactic || undefined,
    notes: mapping?.notes || undefined,
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSave(formData)
  }

  const handleRuleChange = (ruleId: string) => {
    const rule = rules.find((r) => r.id === ruleId)
    setFormData({
      ...formData,
      rule_id: ruleId,
      rule_name: rule?.displayName || ruleId,
    })
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-lg w-full mx-4">
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            {mapping ? 'Edit MITRE Mapping' : 'Add MITRE Mapping'}
          </h3>
          <button
            onClick={onClose}
            className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          {!mapping && (
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Detection Rule
              </label>
              <select
                value={formData.rule_id}
                onChange={(e) => handleRuleChange(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                required
              >
                <option value="">Select a rule...</option>
                {rules.map((rule) => (
                  <option key={rule.id} value={rule.id}>
                    {rule.displayName || rule.id}
                  </option>
                ))}
              </select>
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Tactic
            </label>
            <select
              value={formData.tactic || ''}
              onChange={(e) =>
                setFormData({ ...formData, tactic: e.target.value as MitreTactic })
              }
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
              required
            >
              <option value="">Select a tactic...</option>
              {tactics.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Technique ID
              </label>
              <input
                type="text"
                value={formData.technique_id || ''}
                onChange={(e) => setFormData({ ...formData, technique_id: e.target.value })}
                placeholder="T1059"
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Technique Name
              </label>
              <input
                type="text"
                value={formData.technique_name || ''}
                onChange={(e) => setFormData({ ...formData, technique_name: e.target.value })}
                placeholder="Command and Scripting Interpreter"
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
                required
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Sub-technique ID (optional)
              </label>
              <input
                type="text"
                value={formData.subtechnique_id || ''}
                onChange={(e) =>
                  setFormData({ ...formData, subtechnique_id: e.target.value || undefined })
                }
                placeholder="T1059.001"
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Sub-technique Name (optional)
              </label>
              <input
                type="text"
                value={formData.subtechnique_name || ''}
                onChange={(e) =>
                  setFormData({ ...formData, subtechnique_name: e.target.value || undefined })
                }
                placeholder="PowerShell"
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Notes (optional)
            </label>
            <textarea
              value={formData.notes || ''}
              onChange={(e) => setFormData({ ...formData, notes: e.target.value || undefined })}
              placeholder="Additional context about this mapping..."
              rows={3}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              {mapping ? 'Save Changes' : 'Create Mapping'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
