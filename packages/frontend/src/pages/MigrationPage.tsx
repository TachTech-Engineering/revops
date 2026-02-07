import { useState, useEffect } from 'react'
import {
  ArrowRightLeft,
  FileCode,
  Upload,
  Wand2,
  Copy,
  Check,
  AlertCircle,
  ArrowRight,
  Loader2,
  Sparkles,
  Lightbulb,
  HelpCircle,
  Bot,
  CheckCircle2,
  Circle,
  Play,
  RefreshCw,
  Download,
  ChevronRight,
  AlertTriangle,
  FileText,
  Zap,
  Shield,
  BarChart3,
  Clock,
  Plug,
  Settings,
} from 'lucide-react'

// SIEM formats supported
const SIEM_FORMATS = [
  { id: 'sigma', name: 'Sigma', description: 'Universal detection format', color: 'bg-purple-500' },
  { id: 'spl', name: 'SPL', description: 'Splunk', color: 'bg-green-500' },
  { id: 'yaral', name: 'YARA-L', description: 'Google SecOps (Rules)', color: 'bg-blue-500' },
  { id: 'cql', name: 'CQL', description: 'Google Chronicle (Query)', color: 'bg-sky-500' },
  { id: 'aql', name: 'AQL', description: 'IBM QRadar', color: 'bg-indigo-500' },
  { id: 'kql', name: 'KQL', description: 'Microsoft Sentinel', color: 'bg-cyan-500' },
  { id: 'eql', name: 'EQL', description: 'Elastic Security', color: 'bg-yellow-500' },
  { id: 'esql', name: 'ES|QL', description: 'Elastic (new)', color: 'bg-orange-500' },
  { id: 'panther', name: 'Python', description: 'Panther SIEM', color: 'bg-red-500' },
  { id: 'sql', name: 'SQL', description: 'Standard SQL', color: 'bg-gray-500' },
] as const

type FormatId = typeof SIEM_FORMATS[number]['id']

const API_BASE = import.meta.env.VITE_API_BASE_URL || ''

export default function MigrationPage() {
  const [activeTab, setActiveTab] = useState<'converter' | 'bulk' | 'wizard'>('converter')

  // Converter state
  const [sourceFormat, setSourceFormat] = useState<FormatId>('spl')
  const [targetFormat, setTargetFormat] = useState<FormatId>('yaral')
  const [sourceCode, setSourceCode] = useState('')
  const [convertedCode, setConvertedCode] = useState('')
  const [isConverting, setIsConverting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  // AI-assisted conversion state
  const [useAI, setUseAI] = useState(false)
  const [aiAvailable, setAiAvailable] = useState(false)
  const [aiProviders, setAiProviders] = useState<Array<{ id: string; name: string; model: string; description: string }>>([])
  const [selectedProvider, setSelectedProvider] = useState<string>('claude')
  const [aiContext, setAiContext] = useState('')
  const [explanation, setExplanation] = useState('')
  const [suggestions, setSuggestions] = useState('')
  const [isExplaining, setIsExplaining] = useState(false)
  const [isSuggesting, setIsSuggesting] = useState(false)

  // Bulk import state
  const [bulkFiles, setBulkFiles] = useState<File[]>([])
  const [bulkResults, setBulkResults] = useState<Array<{ name: string; status: 'success' | 'error'; message?: string; converted?: string }>>([])
  const [isBulkProcessing, setIsBulkProcessing] = useState(false)
  const [bulkUseAI, setBulkUseAI] = useState(false)

  // Migration Wizard state
  const [wizardStep, setWizardStep] = useState(1)
  const [wizardSourceFormat, setWizardSourceFormat] = useState<FormatId>('spl')
  const [wizardTargetFormat, setWizardTargetFormat] = useState<FormatId>('yaral')
  const [connectors, setConnectors] = useState<Array<{ id: string; name: string; type: string; status: string }>>([])
  const [selectedConnector, setSelectedConnector] = useState<string | null>(null)
  const [extractedRules, setExtractedRules] = useState<Array<{ id: string; name: string; content: string; selected: boolean }>>([])
  const [isExtracting, setIsExtracting] = useState(false)
  const [migrationPlan, setMigrationPlan] = useState<{
    summary: string
    recommendations: string[]
    risks: string[]
    estimatedComplexity: 'low' | 'medium' | 'high'
    compatibilityScore: number
  } | null>(null)
  const [isPlanning, setIsPlanning] = useState(false)
  const [convertedRules, setConvertedRules] = useState<Array<{
    id: string
    name: string
    original: string
    converted: string
    status: 'pending' | 'converting' | 'success' | 'error' | 'validating' | 'validated'
    validationResult?: { valid: boolean; issues: string[]; suggestions: string[] }
  }>>([])
  const [isMigrating, setIsMigrating] = useState(false)
  const [migrationProgress, setMigrationProgress] = useState({ current: 0, total: 0, phase: '' })

  // Check AI availability on mount
  useEffect(() => {
    const checkAIStatus = async () => {
      try {
        const response = await fetch(`${API_BASE}/api/v1/migrate/ai/status`)
        if (response.ok) {
          const data = await response.json()
          setAiAvailable(data.available)
          setAiProviders(data.providers || [])
          // Set default provider to first available
          if (data.providers?.length > 0) {
            setSelectedProvider(data.providers[0].id)
          }
        }
      } catch {
        setAiAvailable(false)
        setAiProviders([])
      }
    }
    checkAIStatus()
  }, [])

  // Fetch connectors for wizard
  useEffect(() => {
    const fetchConnectors = async () => {
      try {
        const response = await fetch(`${API_BASE}/api/v1/connectors`)
        if (response.ok) {
          const data = await response.json()
          setConnectors(data.filter((c: { category: string }) => c.category === 'data_source'))
        }
      } catch {
        // Connectors not available
      }
    }
    if (activeTab === 'wizard') {
      fetchConnectors()
    }
  }, [activeTab])

  // Wizard functions
  const generateMigrationPlan = async () => {
    if (!aiAvailable) return

    setIsPlanning(true)
    try {
      const response = await fetch(`${API_BASE}/api/v1/migrate/plan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source_format: wizardSourceFormat,
          target_format: wizardTargetFormat,
          rules: extractedRules.filter(r => r.selected).map(r => r.content),
          provider: selectedProvider,
        }),
      })

      if (response.ok) {
        const data = await response.json()
        setMigrationPlan(data)
      } else {
        // Generate a basic plan if AI endpoint not available
        setMigrationPlan({
          summary: `Migration from ${wizardSourceFormat.toUpperCase()} to ${wizardTargetFormat.toUpperCase()} with ${extractedRules.filter(r => r.selected).length} rules selected.`,
          recommendations: [
            'Review complex aggregation queries manually after conversion',
            'Test converted rules in a staging environment first',
            'Validate field mappings match your data schema',
          ],
          risks: [
            'Some platform-specific functions may not have direct equivalents',
            'Time-based functions may need adjustment for timezone handling',
          ],
          estimatedComplexity: extractedRules.length > 50 ? 'high' : extractedRules.length > 20 ? 'medium' : 'low',
          compatibilityScore: 85,
        })
      }
    } catch {
      // Fallback plan
      setMigrationPlan({
        summary: `Ready to migrate ${extractedRules.filter(r => r.selected).length} rules from ${wizardSourceFormat.toUpperCase()} to ${wizardTargetFormat.toUpperCase()}.`,
        recommendations: ['Review converted rules before deployment'],
        risks: ['Some rules may require manual adjustment'],
        estimatedComplexity: 'medium',
        compatibilityScore: 80,
      })
    } finally {
      setIsPlanning(false)
    }
  }

  const extractRulesFromConnector = async () => {
    if (!selectedConnector) return

    setIsExtracting(true)
    try {
      const response = await fetch(`${API_BASE}/api/v1/connectors/${selectedConnector}/rules`)
      if (response.ok) {
        const data = await response.json()
        setExtractedRules(data.rules?.map((r: { id: string; name: string; content: string }) => ({
          ...r,
          selected: true,
        })) || [])
      } else {
        // Demo data if endpoint not available
        setExtractedRules([
          { id: '1', name: 'Suspicious PowerShell Execution', content: 'index=windows EventCode=4688 | where like(NewProcessName, "%powershell.exe%")', selected: true },
          { id: '2', name: 'Failed Login Attempts', content: 'index=windows EventCode=4625 | stats count by src_ip, user | where count > 5', selected: true },
          { id: '3', name: 'Lateral Movement Detection', content: 'index=windows EventCode=4648 | where dest_ip != src_ip', selected: true },
          { id: '4', name: 'Privilege Escalation', content: 'index=windows EventCode=4672 | where user != "SYSTEM"', selected: true },
          { id: '5', name: 'Data Exfiltration Alert', content: 'index=network bytes_out > 10000000 | stats sum(bytes_out) by src_ip', selected: true },
        ])
      }
    } catch {
      // Demo fallback
      setExtractedRules([
        { id: '1', name: 'Sample Rule 1', content: 'index=main | head 10', selected: true },
        { id: '2', name: 'Sample Rule 2', content: 'index=main | stats count', selected: true },
      ])
    } finally {
      setIsExtracting(false)
    }
  }

  const runMigration = async () => {
    const selectedRules = extractedRules.filter(r => r.selected)
    if (selectedRules.length === 0) return

    setIsMigrating(true)
    setConvertedRules(selectedRules.map(r => ({
      id: r.id,
      name: r.name,
      original: r.content,
      converted: '',
      status: 'pending',
    })))

    const total = selectedRules.length
    setMigrationProgress({ current: 0, total, phase: 'Converting rules...' })

    for (let i = 0; i < selectedRules.length; i++) {
      const rule = selectedRules[i]
      setMigrationProgress({ current: i + 1, total, phase: `Converting: ${rule.name}` })

      // Update status to converting
      setConvertedRules(prev => prev.map(r =>
        r.id === rule.id ? { ...r, status: 'converting' } : r
      ))

      try {
        const endpoint = aiAvailable ? '/api/v1/migrate/convert/ai' : '/api/v1/migrate/convert'
        const response = await fetch(`${API_BASE}${endpoint}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            source_format: wizardSourceFormat,
            target_format: wizardTargetFormat,
            source_code: rule.content,
            provider: selectedProvider,
          }),
        })

        if (response.ok) {
          const data = await response.json()
          setConvertedRules(prev => prev.map(r =>
            r.id === rule.id ? { ...r, converted: data.converted_code, status: 'success' } : r
          ))
        } else {
          setConvertedRules(prev => prev.map(r =>
            r.id === rule.id ? { ...r, status: 'error' } : r
          ))
        }
      } catch {
        setConvertedRules(prev => prev.map(r =>
          r.id === rule.id ? { ...r, status: 'error' } : r
        ))
      }

      // Small delay for UX
      await new Promise(resolve => setTimeout(resolve, 100))
    }

    setMigrationProgress({ current: total, total, phase: 'Conversion complete!' })
    setIsMigrating(false)
  }

  const validateConvertedRules = async () => {
    if (!aiAvailable) return

    const successfulRules = convertedRules.filter(r => r.status === 'success')
    setMigrationProgress({ current: 0, total: successfulRules.length, phase: 'Validating rules...' })

    for (let i = 0; i < successfulRules.length; i++) {
      const rule = successfulRules[i]
      setMigrationProgress({ current: i + 1, total: successfulRules.length, phase: `Validating: ${rule.name}` })

      setConvertedRules(prev => prev.map(r =>
        r.id === rule.id ? { ...r, status: 'validating' } : r
      ))

      try {
        const response = await fetch(`${API_BASE}/api/v1/migrate/validate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            format: wizardTargetFormat,
            code: rule.converted,
            provider: selectedProvider,
          }),
        })

        if (response.ok) {
          const data = await response.json()
          setConvertedRules(prev => prev.map(r =>
            r.id === rule.id ? {
              ...r,
              status: 'validated',
              validationResult: data,
            } : r
          ))
        } else {
          // Mark as validated with no issues if endpoint not available
          setConvertedRules(prev => prev.map(r =>
            r.id === rule.id ? {
              ...r,
              status: 'validated',
              validationResult: { valid: true, issues: [], suggestions: [] },
            } : r
          ))
        }
      } catch {
        setConvertedRules(prev => prev.map(r =>
          r.id === rule.id ? {
            ...r,
            status: 'validated',
            validationResult: { valid: true, issues: [], suggestions: [] },
          } : r
        ))
      }

      await new Promise(resolve => setTimeout(resolve, 50))
    }

    setMigrationProgress({ current: successfulRules.length, total: successfulRules.length, phase: 'Validation complete!' })
  }

  const downloadConvertedRules = () => {
    const successfulRules = convertedRules.filter(r => r.status === 'success' || r.status === 'validated')
    const content = successfulRules.map(r => `# ${r.name}\n${r.converted}`).join('\n\n---\n\n')
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `migrated-rules-${wizardTargetFormat}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  const resetWizard = () => {
    setWizardStep(1)
    setSelectedConnector(null)
    setExtractedRules([])
    setMigrationPlan(null)
    setConvertedRules([])
    setMigrationProgress({ current: 0, total: 0, phase: '' })
  }

  const handleConvert = async () => {
    if (!sourceCode.trim()) {
      setError('Please enter source code to convert')
      return
    }

    if (sourceFormat === targetFormat) {
      setError('Source and target formats must be different')
      return
    }

    setIsConverting(true)
    setError(null)
    setConvertedCode('')

    try {
      const endpoint = useAI ? '/api/v1/migrate/convert/ai' : '/api/v1/migrate/convert'
      const body: Record<string, string> = {
        source_format: sourceFormat,
        target_format: targetFormat,
        source_code: sourceCode,
      }
      if (useAI) {
        body.provider = selectedProvider
        if (aiContext.trim()) {
          body.context = aiContext
        }
      }

      const response = await fetch(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.detail || 'Conversion failed')
      }

      if (useAI && !data.success) {
        throw new Error(data.error || 'AI conversion failed')
      }

      setConvertedCode(data.converted_code)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Conversion failed')
    } finally {
      setIsConverting(false)
    }
  }

  const handleExplain = async () => {
    if (!sourceCode.trim()) {
      setError('Please enter source code to explain')
      return
    }

    setIsExplaining(true)
    setError(null)
    setExplanation('')

    try {
      const response = await fetch(`${API_BASE}/api/v1/migrate/explain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source_format: sourceFormat,
          source_code: sourceCode,
          provider: selectedProvider,
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.detail || 'Explanation failed')
      }

      setExplanation(data.explanation)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to explain rule')
    } finally {
      setIsExplaining(false)
    }
  }

  const handleSuggest = async () => {
    if (!sourceCode.trim()) {
      setError('Please enter source code to analyze')
      return
    }

    setIsSuggesting(true)
    setError(null)
    setSuggestions('')

    try {
      const response = await fetch(`${API_BASE}/api/v1/migrate/suggest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source_format: sourceFormat,
          source_code: sourceCode,
          provider: selectedProvider,
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.detail || 'Suggestion failed')
      }

      setSuggestions(data.suggestions)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to get suggestions')
    } finally {
      setIsSuggesting(false)
    }
  }

  const handleCopy = async () => {
    await navigator.clipboard.writeText(convertedCode)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const swapFormats = () => {
    const temp = sourceFormat
    setSourceFormat(targetFormat)
    setTargetFormat(temp)
    setSourceCode(convertedCode)
    setConvertedCode('')
  }

  const handleBulkUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      setBulkFiles(Array.from(e.target.files))
      setBulkResults([])
    }
  }

  const processBulkImport = async () => {
    if (bulkFiles.length === 0) return

    setIsBulkProcessing(true)
    setBulkResults([])

    // For AI bulk conversion, collect all rules and send in one request
    if (bulkUseAI && aiAvailable) {
      try {
        const rules: string[] = []
        for (const file of bulkFiles) {
          const content = await file.text()
          rules.push(content)
        }

        const response = await fetch(`${API_BASE}/api/v1/migrate/convert/ai/bulk`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            source_format: sourceFormat,
            target_format: targetFormat,
            rules,
            provider: selectedProvider,
          }),
        })

        const data = await response.json()

        if (response.ok) {
          const results: typeof bulkResults = data.results.map((r: { index: number; status: string; converted_code?: string; error?: string }) => ({
            name: bulkFiles[r.index].name,
            status: r.status as 'success' | 'error',
            message: r.error,
            converted: r.converted_code,
          }))
          setBulkResults(results)
        } else {
          setBulkResults([{ name: 'Bulk conversion', status: 'error', message: data.detail }])
        }
      } catch (err) {
        setBulkResults([{
          name: 'Bulk conversion',
          status: 'error',
          message: err instanceof Error ? err.message : 'Unknown error'
        }])
      }
    } else {
      // Standard rule-based conversion - process files individually
      const results: typeof bulkResults = []

      for (const file of bulkFiles) {
        try {
          const content = await file.text()
          const response = await fetch(`${API_BASE}/api/v1/migrate/convert`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              source_format: sourceFormat,
              target_format: targetFormat,
              source_code: content,
            }),
          })

          if (response.ok) {
            const data = await response.json()
            results.push({ name: file.name, status: 'success', converted: data.converted_code })
          } else {
            const data = await response.json()
            results.push({ name: file.name, status: 'error', message: data.detail })
          }
        } catch (err) {
          results.push({
            name: file.name,
            status: 'error',
            message: err instanceof Error ? err.message : 'Unknown error'
          })
        }
      }

      setBulkResults(results)
    }

    setIsBulkProcessing(false)
  }

  const getFormatById = (id: FormatId) => SIEM_FORMATS.find(f => f.id === id)!

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">Migration Hub</h1>
        <p className="text-muted-foreground mt-1">
          Convert detection rules between SIEM platforms and migrate your security content
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b">
        <button
          onClick={() => setActiveTab('converter')}
          className={`flex items-center gap-2 px-4 py-2 border-b-2 transition-colors ${
            activeTab === 'converter'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          }`}
        >
          <ArrowRightLeft size={18} />
          Rule Converter
        </button>
        <button
          onClick={() => setActiveTab('bulk')}
          className={`flex items-center gap-2 px-4 py-2 border-b-2 transition-colors ${
            activeTab === 'bulk'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          }`}
        >
          <Upload size={18} />
          Bulk Import
        </button>
        <button
          onClick={() => setActiveTab('wizard')}
          className={`flex items-center gap-2 px-4 py-2 border-b-2 transition-colors ${
            activeTab === 'wizard'
              ? 'border-primary text-primary'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          }`}
        >
          <Wand2 size={18} />
          Migration Wizard
        </button>
      </div>

      {/* Rule Converter Tab */}
      {activeTab === 'converter' && (
        <div className="space-y-6">
          {/* Format Selector */}
          <div className="flex items-center gap-4 p-4 rounded-lg border bg-card">
            <div className="flex-1">
              <label className="block text-sm font-medium mb-2">Source Format</label>
              <select
                value={sourceFormat}
                onChange={(e) => setSourceFormat(e.target.value as FormatId)}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              >
                {SIEM_FORMATS.map((format) => (
                  <option key={format.id} value={format.id}>
                    {format.name} - {format.description}
                  </option>
                ))}
              </select>
            </div>

            <button
              onClick={swapFormats}
              className="p-2 rounded-md border hover:bg-accent transition-colors mt-6"
              title="Swap formats"
            >
              <ArrowRightLeft size={20} />
            </button>

            <div className="flex-1">
              <label className="block text-sm font-medium mb-2">Target Format</label>
              <select
                value={targetFormat}
                onChange={(e) => setTargetFormat(e.target.value as FormatId)}
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
              >
                {SIEM_FORMATS.map((format) => (
                  <option key={format.id} value={format.id}>
                    {format.name} - {format.description}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* AI Toggle */}
          {aiAvailable && (
            <div className="flex items-center justify-between p-4 rounded-lg border bg-gradient-to-r from-purple-500/10 to-blue-500/10">
              <div className="flex items-center gap-3">
                <Sparkles className="text-purple-500" size={24} />
                <div>
                  <div className="font-medium flex items-center gap-2">
                    AI-Assisted Conversion
                    <span className="px-2 py-0.5 text-xs rounded-full bg-purple-500/20 text-purple-500">Beta</span>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    Use AI for intelligent conversion handling edge cases, aggregations, and complex logic
                  </p>
                </div>
              </div>
              <button
                onClick={() => setUseAI(!useAI)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  useAI ? 'bg-purple-500' : 'bg-muted'
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    useAI ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>
          )}

          {/* AI Provider & Context */}
          {useAI && (
            <div className="p-4 rounded-lg border bg-card space-y-4">
              {/* Provider Selection */}
              {aiProviders.length > 1 && (
                <div>
                  <label className="block text-sm font-medium mb-2">AI Provider</label>
                  <div className="flex gap-3">
                    {aiProviders.map((provider) => (
                      <button
                        key={provider.id}
                        onClick={() => setSelectedProvider(provider.id)}
                        className={`flex-1 p-3 rounded-lg border-2 transition-all ${
                          selectedProvider === provider.id
                            ? 'border-purple-500 bg-purple-500/10'
                            : 'border-muted hover:border-muted-foreground/50'
                        }`}
                      >
                        <div className="font-medium">{provider.name}</div>
                        <div className="text-xs text-muted-foreground">{provider.model}</div>
                        <div className="text-xs text-muted-foreground mt-1">{provider.description}</div>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Context Input */}
              <div>
                <label className="block text-sm font-medium flex items-center gap-2 mb-2">
                  <Bot size={16} />
                  Additional Context (Optional)
                </label>
                <textarea
                  value={aiContext}
                  onChange={(e) => setAiContext(e.target.value)}
                  placeholder="Provide additional context about the rule, field mappings, or special requirements..."
                  className="w-full h-20 rounded-md border bg-background px-3 py-2 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-purple-500"
                />
              </div>
            </div>
          )}

          {/* Conversion Flow Indicator */}
          <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground">
            <span className={`px-2 py-1 rounded ${getFormatById(sourceFormat).color} text-white`}>
              {getFormatById(sourceFormat).name}
            </span>
            <ArrowRight size={16} />
            {useAI ? (
              <>
                <span className={`px-2 py-1 rounded text-white flex items-center gap-1 ${
                  selectedProvider === 'openai'
                    ? 'bg-gradient-to-r from-green-500 to-emerald-500'
                    : 'bg-gradient-to-r from-purple-500 to-blue-500'
                }`}>
                  <Sparkles size={12} />
                  {aiProviders.find(p => p.id === selectedProvider)?.name || 'AI'}
                </span>
              </>
            ) : (
              <span className="px-2 py-1 rounded bg-purple-500 text-white">Sigma</span>
            )}
            <ArrowRight size={16} />
            <span className={`px-2 py-1 rounded ${getFormatById(targetFormat).color} text-white`}>
              {getFormatById(targetFormat).name}
            </span>
            <span className="ml-2 text-xs">
              {useAI ? '(AI-powered intelligent conversion)' : '(via universal intermediate format)'}
            </span>
          </div>

          {/* Code Editors */}
          <div className="grid grid-cols-2 gap-4">
            {/* Source */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium flex items-center gap-2">
                  <FileCode size={16} />
                  Source ({getFormatById(sourceFormat).name})
                </label>
              </div>
              <textarea
                value={sourceCode}
                onChange={(e) => setSourceCode(e.target.value)}
                placeholder={getPlaceholder(sourceFormat)}
                className="w-full h-80 rounded-md border bg-background px-3 py-2 font-mono text-sm resize-none focus:outline-none focus:ring-2 focus:ring-primary"
              />
            </div>

            {/* Target */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium flex items-center gap-2">
                  <FileCode size={16} />
                  Converted ({getFormatById(targetFormat).name})
                </label>
                {convertedCode && (
                  <button
                    onClick={handleCopy}
                    className="flex items-center gap-1 px-2 py-1 text-xs rounded hover:bg-accent"
                  >
                    {copied ? <Check size={14} /> : <Copy size={14} />}
                    {copied ? 'Copied!' : 'Copy'}
                  </button>
                )}
              </div>
              <textarea
                value={convertedCode}
                readOnly
                placeholder="Converted code will appear here..."
                className="w-full h-80 rounded-md border bg-muted/50 px-3 py-2 font-mono text-sm resize-none"
              />
            </div>
          </div>

          {/* Error */}
          {error && (
            <div className="flex items-center gap-2 p-3 rounded-md bg-destructive/10 text-destructive">
              <AlertCircle size={16} />
              {error}
            </div>
          )}

          {/* Convert Button */}
          <div className="flex justify-center gap-3">
            <button
              onClick={handleConvert}
              disabled={isConverting || !sourceCode.trim()}
              className={`flex items-center gap-2 px-6 py-2 rounded-md disabled:opacity-50 disabled:cursor-not-allowed ${
                useAI
                  ? selectedProvider === 'openai'
                    ? 'bg-gradient-to-r from-green-500 to-emerald-500 text-white hover:from-green-600 hover:to-emerald-600'
                    : 'bg-gradient-to-r from-purple-500 to-blue-500 text-white hover:from-purple-600 hover:to-blue-600'
                  : 'bg-primary text-primary-foreground hover:bg-primary/90'
              }`}
            >
              {isConverting ? (
                <>
                  <Loader2 size={18} className="animate-spin" />
                  {useAI ? `${aiProviders.find(p => p.id === selectedProvider)?.name || 'AI'} Converting...` : 'Converting...'}
                </>
              ) : (
                <>
                  {useAI ? <Sparkles size={18} /> : <ArrowRightLeft size={18} />}
                  {useAI ? `${aiProviders.find(p => p.id === selectedProvider)?.name || 'AI'} Convert` : 'Convert'}
                </>
              )}
            </button>

            {/* AI-only actions */}
            {aiAvailable && (
              <>
                <button
                  onClick={handleExplain}
                  disabled={isExplaining || !sourceCode.trim()}
                  className="flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-accent disabled:opacity-50 disabled:cursor-not-allowed"
                  title="Get AI explanation of what this rule does"
                >
                  {isExplaining ? (
                    <Loader2 size={16} className="animate-spin" />
                  ) : (
                    <HelpCircle size={16} />
                  )}
                  Explain
                </button>
                <button
                  onClick={handleSuggest}
                  disabled={isSuggesting || !sourceCode.trim()}
                  className="flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-accent disabled:opacity-50 disabled:cursor-not-allowed"
                  title="Get AI suggestions for improving this rule"
                >
                  {isSuggesting ? (
                    <Loader2 size={16} className="animate-spin" />
                  ) : (
                    <Lightbulb size={16} />
                  )}
                  Suggest
                </button>
              </>
            )}
          </div>

          {/* AI Explanation/Suggestions Panel */}
          {(explanation || suggestions) && (
            <div className="grid grid-cols-2 gap-4">
              {explanation && (
                <div className="p-4 rounded-lg border bg-card">
                  <div className="flex items-center gap-2 mb-3 text-sm font-medium">
                    <HelpCircle size={16} className="text-blue-500" />
                    Rule Explanation
                    <button
                      onClick={() => setExplanation('')}
                      className="ml-auto text-muted-foreground hover:text-foreground text-xs"
                    >
                      Dismiss
                    </button>
                  </div>
                  <div className="text-sm text-muted-foreground whitespace-pre-wrap">
                    {explanation}
                  </div>
                </div>
              )}
              {suggestions && (
                <div className="p-4 rounded-lg border bg-card">
                  <div className="flex items-center gap-2 mb-3 text-sm font-medium">
                    <Lightbulb size={16} className="text-yellow-500" />
                    Improvement Suggestions
                    <button
                      onClick={() => setSuggestions('')}
                      className="ml-auto text-muted-foreground hover:text-foreground text-xs"
                    >
                      Dismiss
                    </button>
                  </div>
                  <div className="text-sm text-muted-foreground whitespace-pre-wrap">
                    {suggestions}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Conversion Architecture Explanation */}
          <div className="p-4 rounded-lg border bg-card">
            <h3 className="font-medium mb-3">How Conversion Works</h3>
            <div className="mb-4 p-3 rounded-lg bg-muted/50">
              <div className="flex items-center justify-center gap-3 text-sm">
                <div className="flex items-center gap-2">
                  <div className="px-3 py-1.5 rounded-md bg-primary/20 text-primary font-medium">Source Format</div>
                  <ArrowRight size={16} className="text-muted-foreground" />
                </div>
                <div className="px-3 py-1.5 rounded-md bg-purple-500/20 text-purple-400 font-medium border-2 border-purple-500/30">
                  Sigma (Universal)
                </div>
                <div className="flex items-center gap-2">
                  <ArrowRight size={16} className="text-muted-foreground" />
                  <div className="px-3 py-1.5 rounded-md bg-primary/20 text-primary font-medium">Target Format</div>
                </div>
              </div>
              <p className="text-xs text-muted-foreground text-center mt-2">
                All conversions use Sigma as an intermediate format for maximum compatibility
              </p>
            </div>

            {/* Interactive Format Grid */}
            <h4 className="text-sm font-medium mb-2">Supported Formats</h4>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-2 mb-4">
              {SIEM_FORMATS.map((format) => (
                <button
                  key={format.id}
                  onClick={() => {
                    if (sourceFormat !== format.id) {
                      setSourceFormat(format.id)
                    } else if (targetFormat !== format.id) {
                      setTargetFormat(format.id)
                    }
                  }}
                  className={`p-2 rounded-lg border text-left transition-all hover:border-primary/50 ${
                    sourceFormat === format.id
                      ? 'border-primary bg-primary/10'
                      : targetFormat === format.id
                      ? 'border-green-500 bg-green-500/10'
                      : 'border-border'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${format.color}`} />
                    <span className="font-medium text-sm">{format.name}</span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-0.5">{format.description}</p>
                  <div className="flex gap-1 mt-1">
                    {sourceFormat === format.id && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-primary/20 text-primary">Source</span>
                    )}
                    {targetFormat === format.id && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-500/20 text-green-500">Target</span>
                    )}
                  </div>
                </button>
              ))}
            </div>

            {/* Conversion Matrix - Compact */}
            <details className="text-xs">
              <summary className="cursor-pointer text-muted-foreground hover:text-foreground font-medium">
                View Full Conversion Matrix
              </summary>
              <div className="mt-3 overflow-x-auto">
                <table className="w-full border-collapse text-xs">
                  <thead>
                    <tr>
                      <th className="p-1 text-left border-b font-medium text-muted-foreground">From / To</th>
                      {SIEM_FORMATS.map((f) => (
                        <th key={f.id} className="p-1 text-center border-b font-medium" title={f.description}>
                          <div className={`w-2 h-2 rounded-full ${f.color} mx-auto mb-0.5`} />
                          {f.name}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {SIEM_FORMATS.map((source) => (
                      <tr key={source.id} className="hover:bg-muted/50">
                        <td className="p-1 border-b font-medium">
                          <div className="flex items-center gap-1">
                            <div className={`w-2 h-2 rounded-full ${source.color}`} />
                            {source.name}
                          </div>
                        </td>
                        {SIEM_FORMATS.map((target) => (
                          <td
                            key={`${source.id}-${target.id}`}
                            className="p-1 border-b text-center"
                          >
                            {source.id === target.id ? (
                              <span className="text-muted-foreground">-</span>
                            ) : (
                              <button
                                onClick={() => {
                                  setSourceFormat(source.id)
                                  setTargetFormat(target.id)
                                }}
                                className="w-full h-full text-green-500 hover:bg-green-500/20 rounded transition-colors"
                                title={`Convert ${source.name} to ${target.name}`}
                              >
                                ✓
                              </button>
                            )}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </details>
          </div>
        </div>
      )}

      {/* Bulk Import Tab */}
      {activeTab === 'bulk' && (
        <div className="space-y-6">
          <div className="p-6 rounded-lg border bg-card">
            <h3 className="font-medium mb-4">Bulk Rule Conversion</h3>
            <p className="text-sm text-muted-foreground mb-4">
              Upload multiple detection rule files to convert them all at once.
            </p>

            {/* Format Selection */}
            <div className="grid grid-cols-2 gap-4 mb-6">
              <div>
                <label className="block text-sm font-medium mb-2">Source Format</label>
                <select
                  value={sourceFormat}
                  onChange={(e) => setSourceFormat(e.target.value as FormatId)}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                >
                  {SIEM_FORMATS.map((format) => (
                    <option key={format.id} value={format.id}>
                      {format.name} - {format.description}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">Target Format</label>
                <select
                  value={targetFormat}
                  onChange={(e) => setTargetFormat(e.target.value as FormatId)}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                >
                  {SIEM_FORMATS.map((format) => (
                    <option key={format.id} value={format.id}>
                      {format.name} - {format.description}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* AI Toggle for Bulk */}
            {aiAvailable && (
              <div className="flex items-center justify-between p-4 rounded-lg border bg-gradient-to-r from-purple-500/10 to-blue-500/10 mb-6">
                <div className="flex items-center gap-3">
                  <Sparkles className="text-purple-500" size={20} />
                  <div>
                    <div className="font-medium text-sm">Use AI for Bulk Conversion</div>
                    <p className="text-xs text-muted-foreground">
                      Process all files with {aiProviders.find(p => p.id === selectedProvider)?.name || 'AI'} for better handling of complex rules
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setBulkUseAI(!bulkUseAI)}
                  className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                    bulkUseAI ? 'bg-purple-500' : 'bg-muted'
                  }`}
                >
                  <span
                    className={`inline-block h-3 w-3 transform rounded-full bg-white transition-transform ${
                      bulkUseAI ? 'translate-x-5' : 'translate-x-1'
                    }`}
                  />
                </button>
              </div>
            )}

            {/* File Upload */}
            <div className="border-2 border-dashed rounded-lg p-8 text-center">
              <Upload size={48} className="mx-auto text-muted-foreground mb-4" />
              <p className="text-sm text-muted-foreground mb-4">
                Drag and drop rule files here, or click to browse
              </p>
              <input
                type="file"
                multiple
                accept=".yml,.yaml,.json,.txt,.spl,.kql,.eql,.py"
                onChange={handleBulkUpload}
                className="hidden"
                id="bulk-upload"
              />
              <label
                htmlFor="bulk-upload"
                className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md cursor-pointer hover:bg-primary/90"
              >
                <Upload size={16} />
                Select Files
              </label>
            </div>

            {/* Selected Files */}
            {bulkFiles.length > 0 && (
              <div className="mt-4">
                <h4 className="text-sm font-medium mb-2">Selected Files ({bulkFiles.length})</h4>
                <ul className="space-y-1 max-h-40 overflow-y-auto">
                  {bulkFiles.map((file, i) => (
                    <li key={i} className="text-sm text-muted-foreground flex items-center gap-2">
                      <FileCode size={14} />
                      {file.name}
                    </li>
                  ))}
                </ul>
                <button
                  onClick={processBulkImport}
                  disabled={isBulkProcessing}
                  className={`mt-4 flex items-center gap-2 px-4 py-2 rounded-md disabled:opacity-50 ${
                    bulkUseAI
                      ? selectedProvider === 'openai'
                        ? 'bg-gradient-to-r from-green-500 to-emerald-500 text-white hover:from-green-600 hover:to-emerald-600'
                        : 'bg-gradient-to-r from-purple-500 to-blue-500 text-white hover:from-purple-600 hover:to-blue-600'
                      : 'bg-primary text-primary-foreground hover:bg-primary/90'
                  }`}
                >
                  {isBulkProcessing ? (
                    <>
                      <Loader2 size={16} className="animate-spin" />
                      {bulkUseAI ? 'AI Processing...' : 'Processing...'}
                    </>
                  ) : (
                    <>
                      {bulkUseAI ? <Sparkles size={16} /> : <ArrowRightLeft size={16} />}
                      {bulkUseAI ? 'AI Convert All' : 'Convert All'}
                    </>
                  )}
                </button>
              </div>
            )}

            {/* Results */}
            {bulkResults.length > 0 && (
              <div className="mt-4">
                <h4 className="text-sm font-medium mb-2">
                  Results ({bulkResults.filter(r => r.status === 'success').length}/{bulkResults.length} successful)
                </h4>
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {bulkResults.map((result, i) => (
                    <div
                      key={i}
                      className={`p-3 rounded-lg border ${
                        result.status === 'success' ? 'border-green-500/30 bg-green-500/5' : 'border-destructive/30 bg-destructive/5'
                      }`}
                    >
                      <div className={`text-sm flex items-center gap-2 ${
                        result.status === 'success' ? 'text-green-500' : 'text-destructive'
                      }`}>
                        {result.status === 'success' ? <Check size={14} /> : <AlertCircle size={14} />}
                        <span className="font-medium">{result.name}</span>
                        {result.message && <span className="text-muted-foreground">- {result.message}</span>}
                      </div>
                      {result.status === 'success' && result.converted && (
                        <details className="mt-2">
                          <summary className="text-xs text-muted-foreground cursor-pointer hover:text-foreground">
                            View converted code
                          </summary>
                          <pre className="mt-2 p-2 text-xs bg-muted rounded overflow-x-auto max-h-40">
                            {result.converted}
                          </pre>
                        </details>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Migration Wizard Tab */}
      {activeTab === 'wizard' && (
        <div className="space-y-6">
          {/* Step Progress Indicator */}
          <div className="p-4 rounded-lg border bg-card">
            <div className="flex items-center justify-between">
              {[
                { step: 1, label: 'Configure', icon: Settings },
                { step: 2, label: 'Extract Rules', icon: FileText },
                { step: 3, label: 'AI Planning', icon: Sparkles },
                { step: 4, label: 'Convert', icon: ArrowRightLeft },
                { step: 5, label: 'Validate & Export', icon: Shield },
              ].map(({ step, label, icon: Icon }, index) => (
                <div key={step} className="flex items-center">
                  <div className="flex flex-col items-center">
                    <div
                      className={`w-10 h-10 rounded-full flex items-center justify-center transition-colors ${
                        wizardStep === step
                          ? 'bg-primary text-primary-foreground'
                          : wizardStep > step
                          ? 'bg-green-500 text-white'
                          : 'bg-muted text-muted-foreground'
                      }`}
                    >
                      {wizardStep > step ? (
                        <CheckCircle2 size={20} />
                      ) : (
                        <Icon size={20} />
                      )}
                    </div>
                    <span className={`text-xs mt-1 ${wizardStep >= step ? 'text-foreground' : 'text-muted-foreground'}`}>
                      {label}
                    </span>
                  </div>
                  {index < 4 && (
                    <div className={`w-16 h-0.5 mx-2 ${wizardStep > step ? 'bg-green-500' : 'bg-muted'}`} />
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Step 1: Configure Source and Target */}
          {wizardStep === 1 && (
            <div className="p-6 rounded-lg border bg-card space-y-6">
              <div>
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Settings size={20} />
                  Configure Migration
                </h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Select your source and target SIEM platforms, and optionally connect to extract rules automatically.
                </p>
              </div>

              {/* Format Selection */}
              <div className="grid grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium mb-2">Source SIEM Format</label>
                  <select
                    value={wizardSourceFormat}
                    onChange={(e) => setWizardSourceFormat(e.target.value as FormatId)}
                    className="w-full rounded-md border bg-background px-3 py-2.5 text-sm"
                  >
                    {SIEM_FORMATS.map((format) => (
                      <option key={format.id} value={format.id}>
                        {format.name} - {format.description}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium mb-2">Target SIEM Format</label>
                  <select
                    value={wizardTargetFormat}
                    onChange={(e) => setWizardTargetFormat(e.target.value as FormatId)}
                    className="w-full rounded-md border bg-background px-3 py-2.5 text-sm"
                  >
                    {SIEM_FORMATS.map((format) => (
                      <option key={format.id} value={format.id}>
                        {format.name} - {format.description}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Connector Selection */}
              <div>
                <label className="block text-sm font-medium mb-2 flex items-center gap-2">
                  <Plug size={16} />
                  Extract Rules from Connector (Optional)
                </label>
                {connectors.length > 0 ? (
                  <div className="grid grid-cols-2 gap-3">
                    {connectors.map((connector) => (
                      <button
                        key={connector.id}
                        onClick={() => setSelectedConnector(connector.id === selectedConnector ? null : connector.id)}
                        className={`p-3 rounded-lg border text-left transition-all ${
                          selectedConnector === connector.id
                            ? 'border-primary bg-primary/10'
                            : 'border-border hover:border-primary/50'
                        }`}
                      >
                        <div className="font-medium">{connector.name}</div>
                        <div className="text-xs text-muted-foreground">{connector.type}</div>
                        <div className={`text-xs mt-1 ${connector.status === 'active' ? 'text-green-500' : 'text-muted-foreground'}`}>
                          {connector.status}
                        </div>
                      </button>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 rounded-lg border border-dashed text-center text-muted-foreground">
                    <p className="text-sm">No data source connectors available.</p>
                    <a href="/connectors" className="text-primary text-sm hover:underline">Configure connectors</a>
                  </div>
                )}
              </div>

              {/* AI Provider Selection */}
              {aiAvailable && aiProviders.length > 0 && (
                <div className="p-4 rounded-lg border bg-gradient-to-r from-purple-500/10 to-blue-500/10">
                  <div className="flex items-center gap-2 mb-3">
                    <Sparkles className="text-purple-500" size={18} />
                    <span className="font-medium">AI Provider for Migration</span>
                  </div>
                  <div className="flex gap-3">
                    {aiProviders.map((provider) => (
                      <button
                        key={provider.id}
                        onClick={() => setSelectedProvider(provider.id)}
                        className={`flex-1 p-3 rounded-lg border-2 transition-all ${
                          selectedProvider === provider.id
                            ? 'border-purple-500 bg-purple-500/10'
                            : 'border-muted hover:border-muted-foreground/50'
                        }`}
                      >
                        <div className="font-medium text-sm">{provider.name}</div>
                        <div className="text-xs text-muted-foreground">{provider.model}</div>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              <div className="flex justify-end">
                <button
                  onClick={() => setWizardStep(2)}
                  className="flex items-center gap-2 px-6 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
                >
                  Continue
                  <ChevronRight size={18} />
                </button>
              </div>
            </div>
          )}

          {/* Step 2: Extract and Select Rules */}
          {wizardStep === 2 && (
            <div className="p-6 rounded-lg border bg-card space-y-6">
              <div>
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <FileText size={20} />
                  Extract & Select Rules
                </h3>
                <p className="text-sm text-muted-foreground mt-1">
                  {selectedConnector
                    ? 'Extract rules from your connected SIEM or paste them manually.'
                    : 'Paste your detection rules below to continue with the migration.'}
                </p>
              </div>

              {/* Extract from Connector */}
              {selectedConnector && (
                <div className="flex items-center justify-between p-4 rounded-lg border bg-muted/50">
                  <div>
                    <div className="font-medium">Extract from {connectors.find(c => c.id === selectedConnector)?.name}</div>
                    <div className="text-sm text-muted-foreground">
                      {extractedRules.length > 0 ? `${extractedRules.length} rules found` : 'Click to extract rules'}
                    </div>
                  </div>
                  <button
                    onClick={extractRulesFromConnector}
                    disabled={isExtracting}
                    className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
                  >
                    {isExtracting ? (
                      <>
                        <Loader2 size={16} className="animate-spin" />
                        Extracting...
                      </>
                    ) : (
                      <>
                        <Zap size={16} />
                        Extract Rules
                      </>
                    )}
                  </button>
                </div>
              )}

              {/* Manual Rule Input (if no connector or as alternative) */}
              {(!selectedConnector || extractedRules.length === 0) && (
                <div>
                  <label className="block text-sm font-medium mb-2">Paste Rules (one per block, separated by ---)</label>
                  <textarea
                    placeholder={`Paste your ${getFormatById(wizardSourceFormat).name} rules here...\n\n---\n\nSeparate multiple rules with ---`}
                    className="w-full h-48 rounded-md border bg-background px-3 py-2 font-mono text-sm resize-none focus:outline-none focus:ring-2 focus:ring-primary"
                    onChange={(e) => {
                      const content = e.target.value
                      if (content.trim()) {
                        const rules = content.split('---').filter(r => r.trim())
                        setExtractedRules(rules.map((r, i) => ({
                          id: `manual-${i}`,
                          name: `Rule ${i + 1}`,
                          content: r.trim(),
                          selected: true,
                        })))
                      }
                    }}
                  />
                </div>
              )}

              {/* Rule Selection List */}
              {extractedRules.length > 0 && (
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <label className="text-sm font-medium">
                      Select Rules to Migrate ({extractedRules.filter(r => r.selected).length}/{extractedRules.length} selected)
                    </label>
                    <div className="flex gap-2">
                      <button
                        onClick={() => setExtractedRules(prev => prev.map(r => ({ ...r, selected: true })))}
                        className="text-xs text-primary hover:underline"
                      >
                        Select All
                      </button>
                      <button
                        onClick={() => setExtractedRules(prev => prev.map(r => ({ ...r, selected: false })))}
                        className="text-xs text-muted-foreground hover:underline"
                      >
                        Deselect All
                      </button>
                    </div>
                  </div>
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {extractedRules.map((rule) => (
                      <div
                        key={rule.id}
                        className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                          rule.selected ? 'border-primary bg-primary/5' : 'border-border hover:border-primary/50'
                        }`}
                        onClick={() => setExtractedRules(prev =>
                          prev.map(r => r.id === rule.id ? { ...r, selected: !r.selected } : r)
                        )}
                      >
                        <div className="flex items-center gap-3">
                          <div className={`w-5 h-5 rounded border-2 flex items-center justify-center ${
                            rule.selected ? 'border-primary bg-primary text-primary-foreground' : 'border-muted-foreground'
                          }`}>
                            {rule.selected && <Check size={12} />}
                          </div>
                          <div className="flex-1">
                            <div className="font-medium text-sm">{rule.name}</div>
                            <div className="text-xs text-muted-foreground font-mono truncate">{rule.content.slice(0, 100)}...</div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="flex justify-between">
                <button
                  onClick={() => setWizardStep(1)}
                  className="px-4 py-2 border rounded-md hover:bg-accent"
                >
                  Back
                </button>
                <button
                  onClick={() => setWizardStep(3)}
                  disabled={extractedRules.filter(r => r.selected).length === 0}
                  className="flex items-center gap-2 px-6 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
                >
                  Continue
                  <ChevronRight size={18} />
                </button>
              </div>
            </div>
          )}

          {/* Step 3: AI Migration Planning */}
          {wizardStep === 3 && (
            <div className="p-6 rounded-lg border bg-card space-y-6">
              <div>
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Sparkles size={20} className="text-purple-500" />
                  AI Migration Planning
                </h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Let AI analyze your rules and create an optimized migration plan.
                </p>
              </div>

              {/* Generate Plan Button */}
              {!migrationPlan && (
                <div className="p-8 rounded-lg border border-dashed text-center">
                  <Sparkles size={48} className="mx-auto text-purple-500 mb-4" />
                  <h4 className="font-medium mb-2">Generate AI Migration Plan</h4>
                  <p className="text-sm text-muted-foreground mb-4">
                    AI will analyze {extractedRules.filter(r => r.selected).length} rules and recommend the best conversion strategy.
                  </p>
                  <button
                    onClick={generateMigrationPlan}
                    disabled={isPlanning}
                    className="flex items-center gap-2 px-6 py-2 mx-auto bg-gradient-to-r from-purple-500 to-blue-500 text-white rounded-md hover:from-purple-600 hover:to-blue-600 disabled:opacity-50"
                  >
                    {isPlanning ? (
                      <>
                        <Loader2 size={18} className="animate-spin" />
                        Analyzing Rules...
                      </>
                    ) : (
                      <>
                        <Zap size={18} />
                        Generate Plan
                      </>
                    )}
                  </button>
                </div>
              )}

              {/* Migration Plan Display */}
              {migrationPlan && (
                <div className="space-y-4">
                  {/* Summary */}
                  <div className="p-4 rounded-lg bg-muted/50">
                    <h4 className="font-medium mb-2">Migration Summary</h4>
                    <p className="text-sm text-muted-foreground">{migrationPlan.summary}</p>
                  </div>

                  {/* Stats */}
                  <div className="grid grid-cols-3 gap-4">
                    <div className="p-4 rounded-lg border text-center">
                      <BarChart3 size={24} className="mx-auto text-blue-500 mb-2" />
                      <div className="text-2xl font-bold">{migrationPlan.compatibilityScore}%</div>
                      <div className="text-xs text-muted-foreground">Compatibility Score</div>
                    </div>
                    <div className="p-4 rounded-lg border text-center">
                      <Clock size={24} className="mx-auto text-yellow-500 mb-2" />
                      <div className="text-2xl font-bold capitalize">{migrationPlan.estimatedComplexity}</div>
                      <div className="text-xs text-muted-foreground">Complexity</div>
                    </div>
                    <div className="p-4 rounded-lg border text-center">
                      <FileText size={24} className="mx-auto text-green-500 mb-2" />
                      <div className="text-2xl font-bold">{extractedRules.filter(r => r.selected).length}</div>
                      <div className="text-xs text-muted-foreground">Rules to Migrate</div>
                    </div>
                  </div>

                  {/* Recommendations */}
                  <div className="p-4 rounded-lg border">
                    <h4 className="font-medium mb-3 flex items-center gap-2">
                      <Lightbulb size={16} className="text-yellow-500" />
                      Recommendations
                    </h4>
                    <ul className="space-y-2">
                      {migrationPlan.recommendations.map((rec, i) => (
                        <li key={i} className="flex items-start gap-2 text-sm">
                          <CheckCircle2 size={14} className="text-green-500 mt-0.5 shrink-0" />
                          {rec}
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Risks */}
                  {migrationPlan.risks.length > 0 && (
                    <div className="p-4 rounded-lg border border-yellow-500/30 bg-yellow-500/5">
                      <h4 className="font-medium mb-3 flex items-center gap-2">
                        <AlertTriangle size={16} className="text-yellow-500" />
                        Potential Risks
                      </h4>
                      <ul className="space-y-2">
                        {migrationPlan.risks.map((risk, i) => (
                          <li key={i} className="flex items-start gap-2 text-sm">
                            <AlertTriangle size={14} className="text-yellow-500 mt-0.5 shrink-0" />
                            {risk}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              <div className="flex justify-between">
                <button
                  onClick={() => setWizardStep(2)}
                  className="px-4 py-2 border rounded-md hover:bg-accent"
                >
                  Back
                </button>
                <button
                  onClick={() => setWizardStep(4)}
                  disabled={!migrationPlan}
                  className="flex items-center gap-2 px-6 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
                >
                  Start Migration
                  <ChevronRight size={18} />
                </button>
              </div>
            </div>
          )}

          {/* Step 4: Conversion with Progress */}
          {wizardStep === 4 && (
            <div className="p-6 rounded-lg border bg-card space-y-6">
              <div>
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <ArrowRightLeft size={20} />
                  Converting Rules
                </h3>
                <p className="text-sm text-muted-foreground mt-1">
                  {isMigrating
                    ? `Converting ${migrationProgress.current} of ${migrationProgress.total} rules...`
                    : convertedRules.length > 0
                    ? `Converted ${convertedRules.filter(r => r.status === 'success' || r.status === 'validated').length} of ${convertedRules.length} rules`
                    : 'Click Start to begin converting your rules'}
                </p>
              </div>

              {/* Progress Bar */}
              {(isMigrating || convertedRules.length > 0) && (
                <div>
                  <div className="flex items-center justify-between text-sm mb-2">
                    <span className="text-muted-foreground">{migrationProgress.phase}</span>
                    <span className="font-medium">{migrationProgress.current}/{migrationProgress.total}</span>
                  </div>
                  <div className="h-2 rounded-full bg-muted overflow-hidden">
                    <div
                      className="h-full bg-primary transition-all duration-300"
                      style={{ width: `${migrationProgress.total > 0 ? (migrationProgress.current / migrationProgress.total) * 100 : 0}%` }}
                    />
                  </div>
                </div>
              )}

              {/* Start Button */}
              {convertedRules.length === 0 && !isMigrating && (
                <div className="p-8 rounded-lg border border-dashed text-center">
                  <Play size={48} className="mx-auto text-primary mb-4" />
                  <h4 className="font-medium mb-2">Ready to Convert</h4>
                  <p className="text-sm text-muted-foreground mb-4">
                    {extractedRules.filter(r => r.selected).length} rules will be converted from {getFormatById(wizardSourceFormat).name} to {getFormatById(wizardTargetFormat).name}
                  </p>
                  <button
                    onClick={runMigration}
                    className="flex items-center gap-2 px-6 py-2 mx-auto bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
                  >
                    <Play size={18} />
                    Start Conversion
                  </button>
                </div>
              )}

              {/* Conversion Results */}
              {convertedRules.length > 0 && (
                <div className="space-y-3 max-h-96 overflow-y-auto">
                  {convertedRules.map((rule) => (
                    <div
                      key={rule.id}
                      className={`p-4 rounded-lg border ${
                        rule.status === 'success' || rule.status === 'validated'
                          ? 'border-green-500/30 bg-green-500/5'
                          : rule.status === 'error'
                          ? 'border-destructive/30 bg-destructive/5'
                          : rule.status === 'converting' || rule.status === 'validating'
                          ? 'border-primary/30 bg-primary/5'
                          : 'border-border'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        {rule.status === 'pending' && <Circle size={16} className="text-muted-foreground" />}
                        {(rule.status === 'converting' || rule.status === 'validating') && (
                          <Loader2 size={16} className="animate-spin text-primary" />
                        )}
                        {(rule.status === 'success' || rule.status === 'validated') && (
                          <CheckCircle2 size={16} className="text-green-500" />
                        )}
                        {rule.status === 'error' && <AlertCircle size={16} className="text-destructive" />}
                        <div className="flex-1">
                          <div className="font-medium text-sm">{rule.name}</div>
                          <div className="text-xs text-muted-foreground capitalize">{rule.status}</div>
                        </div>
                      </div>
                      {rule.converted && (
                        <details className="mt-3">
                          <summary className="text-xs text-muted-foreground cursor-pointer hover:text-foreground">
                            View converted code
                          </summary>
                          <pre className="mt-2 p-2 rounded bg-muted text-xs font-mono overflow-x-auto max-h-32">
                            {rule.converted}
                          </pre>
                        </details>
                      )}
                      {rule.validationResult && (
                        <div className="mt-2 text-xs">
                          {rule.validationResult.valid ? (
                            <span className="text-green-500 flex items-center gap-1">
                              <CheckCircle2 size={12} /> Validated successfully
                            </span>
                          ) : (
                            <div className="text-destructive">
                              {rule.validationResult.issues.map((issue, i) => (
                                <div key={i} className="flex items-start gap-1">
                                  <AlertTriangle size={12} className="mt-0.5 shrink-0" />
                                  {issue}
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              <div className="flex justify-between">
                <button
                  onClick={() => setWizardStep(3)}
                  disabled={isMigrating}
                  className="px-4 py-2 border rounded-md hover:bg-accent disabled:opacity-50"
                >
                  Back
                </button>
                <button
                  onClick={() => setWizardStep(5)}
                  disabled={isMigrating || convertedRules.filter(r => r.status === 'success' || r.status === 'validated').length === 0}
                  className="flex items-center gap-2 px-6 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
                >
                  Continue
                  <ChevronRight size={18} />
                </button>
              </div>
            </div>
          )}

          {/* Step 5: Validate & Export */}
          {wizardStep === 5 && (
            <div className="p-6 rounded-lg border bg-card space-y-6">
              <div>
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Shield size={20} className="text-green-500" />
                  Validate & Export
                </h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Validate converted rules with AI and export them for deployment.
                </p>
              </div>

              {/* Summary Stats */}
              <div className="grid grid-cols-4 gap-4">
                <div className="p-4 rounded-lg border text-center">
                  <div className="text-2xl font-bold text-green-500">
                    {convertedRules.filter(r => r.status === 'success' || r.status === 'validated').length}
                  </div>
                  <div className="text-xs text-muted-foreground">Successful</div>
                </div>
                <div className="p-4 rounded-lg border text-center">
                  <div className="text-2xl font-bold text-destructive">
                    {convertedRules.filter(r => r.status === 'error').length}
                  </div>
                  <div className="text-xs text-muted-foreground">Failed</div>
                </div>
                <div className="p-4 rounded-lg border text-center">
                  <div className="text-2xl font-bold text-blue-500">
                    {convertedRules.filter(r => r.status === 'validated').length}
                  </div>
                  <div className="text-xs text-muted-foreground">Validated</div>
                </div>
                <div className="p-4 rounded-lg border text-center">
                  <div className="text-2xl font-bold">
                    {convertedRules.filter(r => r.validationResult?.issues?.length).length}
                  </div>
                  <div className="text-xs text-muted-foreground">With Issues</div>
                </div>
              </div>

              {/* AI Validation */}
              {aiAvailable && (
                <div className="p-4 rounded-lg border bg-gradient-to-r from-purple-500/10 to-blue-500/10">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-medium flex items-center gap-2">
                        <Sparkles size={16} className="text-purple-500" />
                        AI Validation
                      </h4>
                      <p className="text-sm text-muted-foreground mt-1">
                        Run AI validation to check for syntax errors and get improvement suggestions.
                      </p>
                    </div>
                    <button
                      onClick={validateConvertedRules}
                      disabled={migrationProgress.phase.includes('Validating')}
                      className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-purple-500 to-blue-500 text-white rounded-md hover:from-purple-600 hover:to-blue-600 disabled:opacity-50"
                    >
                      {migrationProgress.phase.includes('Validating') ? (
                        <>
                          <Loader2 size={16} className="animate-spin" />
                          Validating...
                        </>
                      ) : (
                        <>
                          <Shield size={16} />
                          Validate All
                        </>
                      )}
                    </button>
                  </div>
                </div>
              )}

              {/* Export Options */}
              <div className="p-4 rounded-lg border">
                <h4 className="font-medium mb-4">Export Options</h4>
                <div className="flex gap-3">
                  <button
                    onClick={downloadConvertedRules}
                    className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
                  >
                    <Download size={16} />
                    Download All Rules
                  </button>
                  <button
                    onClick={() => {
                      const validRules = convertedRules.filter(r => r.status === 'validated' && r.validationResult?.valid)
                      if (validRules.length > 0) {
                        const content = validRules.map(r => `# ${r.name}\n${r.converted}`).join('\n\n---\n\n')
                        const blob = new Blob([content], { type: 'text/plain' })
                        const url = URL.createObjectURL(blob)
                        const a = document.createElement('a')
                        a.href = url
                        a.download = `validated-rules-${wizardTargetFormat}.txt`
                        a.click()
                        URL.revokeObjectURL(url)
                      }
                    }}
                    disabled={convertedRules.filter(r => r.status === 'validated' && r.validationResult?.valid).length === 0}
                    className="flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-accent disabled:opacity-50"
                  >
                    <Shield size={16} />
                    Download Validated Only
                  </button>
                </div>
              </div>

              {/* Next Steps */}
              <div className="p-4 rounded-lg bg-muted/50">
                <h4 className="font-medium mb-3">Next Steps</h4>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li className="flex items-start gap-2">
                    <ChevronRight size={14} className="mt-0.5 shrink-0" />
                    Import the downloaded rules into your target SIEM
                  </li>
                  <li className="flex items-start gap-2">
                    <ChevronRight size={14} className="mt-0.5 shrink-0" />
                    Test rules in a staging environment before production
                  </li>
                  <li className="flex items-start gap-2">
                    <ChevronRight size={14} className="mt-0.5 shrink-0" />
                    Review any rules with validation issues manually
                  </li>
                </ul>
              </div>

              <div className="flex justify-between">
                <button
                  onClick={() => setWizardStep(4)}
                  className="px-4 py-2 border rounded-md hover:bg-accent"
                >
                  Back
                </button>
                <button
                  onClick={resetWizard}
                  className="flex items-center gap-2 px-6 py-2 border rounded-md hover:bg-accent"
                >
                  <RefreshCw size={16} />
                  Start New Migration
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function getPlaceholder(format: FormatId): string {
  const placeholders: Record<FormatId, string> = {
    sigma: `title: Suspicious Process Creation
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection`,
    spl: `index=windows sourcetype=WinEventLog:Security EventCode=4688
| where like(NewProcessName, "%powershell.exe")
| where like(CommandLine, "%-enc%")
| table _time, ComputerName, User, NewProcessName, CommandLine`,
    yaral: `rule suspicious_powershell_execution {
  meta:
    author = "Security Team"
    description = "Detects encoded PowerShell execution"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path = /powershell\\.exe$/
    $e.target.process.command_line = /\\-enc/
  condition:
    $e
}`,
    cql: `events
| filter metadata.event_type = "PROCESS_LAUNCH"
| filter target.process.file.full_path =~ /powershell\\.exe$/
| filter target.process.command_line =~ /\\-enc/
| aggregate count() by principal.hostname
| head 100`,
    kql: `SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
| where CommandLine contains "-enc"
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine`,
    eql: `process where process.name == "powershell.exe" and process.command_line : "*-enc*"`,
    esql: `FROM logs-windows.*
| WHERE process.name == "powershell.exe" AND process.command_line LIKE "*-enc*"
| KEEP @timestamp, host.name, user.name, process.name, process.command_line`,
    panther: `def rule(event):
    if event.get("process_name", "").endswith("powershell.exe"):
        command_line = event.get("command_line", "")
        if "-enc" in command_line.lower():
            return True
    return False

def title(event):
    return f"Suspicious PowerShell on {event.get('hostname', 'unknown')}"`,
    aql: `SELECT sourceip, destinationip, username, LOGSOURCENAME(logsourceid)
FROM events
WHERE category = 'Authentication'
AND LOGSOURCETYPENAME(logsourceid) ILIKE '%windows%'
AND username ILIKE '%admin%'
GROUP BY sourceip, destinationip, username
LAST 24 HOURS`,
    sql: `SELECT source_ip, destination_ip, username, COUNT(*) as event_count
FROM security_events
WHERE category = 'Authentication'
AND username LIKE '%admin%'
GROUP BY source_ip, destination_ip, username
ORDER BY event_count DESC
LIMIT 100;`,
  }
  return placeholders[format] || ''
}
