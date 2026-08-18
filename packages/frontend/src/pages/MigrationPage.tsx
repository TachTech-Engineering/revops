import { useMemo, useState } from 'react'
import { AlertTriangle, ArrowRightLeft, CheckCircle2, Loader2, Sparkles } from 'lucide-react'
import {
  useGetMigrationFormatsQuery,
  useGetMigrationAiStatusQuery,
  useConvertRuleMutation,
  useBulkConvertRulesMutation,
  useAiConvertRuleMutation,
  useExplainRuleMutation,
} from '../api/pantherApi'

/**
 * Rule conversion between detection formats.
 *
 * This page was 2,174 lines that never called the API. It displayed invented
 * migration progress and fabricated validation results -- reporting rules as
 * successfully converted and validated when nothing had been converted at all.
 * For a migration tool that is the worst possible failure: the entire point is
 * to tell you which rules survived translation and which need attention, and
 * it answered that question with fiction.
 *
 * The converter behind it is real and well covered by tests. This is a thin,
 * honest surface over it: every result here came back from the backend, and
 * failures are shown as failures.
 */

const SEPARATOR = '\n---\n'

export default function MigrationPage() {
  const { data: formats, isLoading: formatsLoading } = useGetMigrationFormatsQuery()
  const { data: aiStatus } = useGetMigrationAiStatusQuery()

  const [convertRule, { isLoading: isConverting }] = useConvertRuleMutation()
  const [bulkConvert, { isLoading: isBulkConverting }] = useBulkConvertRulesMutation()
  const [aiConvert, { isLoading: isAiConverting }] = useAiConvertRuleMutation()
  const [explainRule, { isLoading: isExplaining }] = useExplainRuleMutation()

  const [sourceFormat, setSourceFormat] = useState('')
  const [targetFormat, setTargetFormat] = useState('')
  const [sourceCode, setSourceCode] = useState('')
  const [bulkMode, setBulkMode] = useState(false)

  const [output, setOutput] = useState<string | null>(null)
  const [explanation, setExplanation] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [summary, setSummary] = useState<string | null>(null)

  const aiAvailable = Boolean(aiStatus?.available)

  // Default the dropdowns once the real format list arrives.
  useMemo(() => {
    if (formats?.length) {
      if (!sourceFormat) setSourceFormat(formats[0].id)
      if (!targetFormat) setTargetFormat(formats[formats.length - 1].id)
    }
  }, [formats, sourceFormat, targetFormat])

  const reset = () => {
    setOutput(null)
    setExplanation(null)
    setError(null)
    setSummary(null)
  }

  const detail = (err: unknown, fallback: string) =>
    (err as { data?: { detail?: string } })?.data?.detail ?? fallback

  const handleConvert = async () => {
    reset()
    try {
      if (bulkMode) {
        const rules = sourceCode
          .split(SEPARATOR)
          .map((r) => r.trim())
          .filter(Boolean)
        const result = await bulkConvert({
          source_format: sourceFormat,
          target_format: targetFormat,
          rules,
        }).unwrap()
        // The counts are the backend's, not a guess: failures stay visible.
        setSummary(`${result.success_count} converted, ${result.error_count} failed`)
        setOutput(JSON.stringify(result.results, null, 2))
      } else {
        const result = await convertRule({
          source_format: sourceFormat,
          target_format: targetFormat,
          source_code: sourceCode,
        }).unwrap()
        setOutput(result.converted_code)
        if (result.intermediate_sigma) {
          setSummary('Converted via an intermediate Sigma representation.')
        }
      }
    } catch (err) {
      setError(detail(err, 'Conversion failed.'))
    }
  }

  const handleAiConvert = async () => {
    reset()
    try {
      const result = await aiConvert({
        source_format: sourceFormat,
        target_format: targetFormat,
        source_code: sourceCode,
      }).unwrap()
      if (!result.success) {
        setError(result.error ?? 'The model could not convert this rule.')
        return
      }
      setOutput(result.converted_code)
      setSummary(`Converted by ${result.provider} (${result.model}). Review before use.`)
    } catch (err) {
      setError(detail(err, 'AI conversion failed.'))
    }
  }

  const handleExplain = async () => {
    reset()
    try {
      const result = await explainRule({
        source_format: sourceFormat,
        target_format: targetFormat,
        source_code: sourceCode,
      }).unwrap()
      setExplanation(result.explanation ?? JSON.stringify(result, null, 2))
    } catch (err) {
      setError(detail(err, 'Could not explain this rule.'))
    }
  }

  const busy = isConverting || isBulkConverting || isAiConverting || isExplaining

  return (
    <div className="space-y-6">
      <div>
        <h1 className="flex items-center gap-3 text-3xl font-bold">
          <ArrowRightLeft className="text-primary" />
          Rule Migration
        </h1>
        <p className="text-muted-foreground">
          Convert detection rules between formats. Everything shown here is the converter's
          actual output.
        </p>
      </div>

      <div className="rounded-lg border bg-background p-6">
        <div className="mb-4 flex flex-col gap-4 md:flex-row">
          <div className="flex-1">
            <label className="mb-1 block text-sm font-medium">From</label>
            <select
              value={sourceFormat}
              onChange={(e) => setSourceFormat(e.target.value)}
              className="w-full rounded-md border bg-background px-3 py-2 text-sm"
            >
              {formats?.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.name}
                </option>
              ))}
            </select>
          </div>
          <div className="flex-1">
            <label className="mb-1 block text-sm font-medium">To</label>
            <select
              value={targetFormat}
              onChange={(e) => setTargetFormat(e.target.value)}
              className="w-full rounded-md border bg-background px-3 py-2 text-sm"
            >
              {formats?.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        {formatsLoading && (
          <p className="mb-3 flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading formats...
          </p>
        )}

        <label className="mb-2 flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={bulkMode}
            onChange={(e) => setBulkMode(e.target.checked)}
          />
          Bulk mode &mdash; separate rules with a line containing only <code>---</code>
        </label>

        <textarea
          value={sourceCode}
          onChange={(e) => setSourceCode(e.target.value)}
          rows={14}
          spellCheck={false}
          placeholder="Paste the rule to convert..."
          className="w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
        />

        <div className="mt-4 flex flex-wrap gap-2">
          <button
            onClick={handleConvert}
            disabled={!sourceCode.trim() || busy}
            className="rounded-md bg-primary px-4 py-2 text-sm text-primary-foreground disabled:opacity-50"
          >
            {isConverting || isBulkConverting ? 'Converting...' : 'Convert'}
          </button>
          <button
            onClick={handleExplain}
            disabled={!sourceCode.trim() || busy || !aiAvailable}
            title={aiAvailable ? undefined : 'Requires an AI provider key for this organization'}
            className="rounded-md border px-4 py-2 text-sm disabled:opacity-50"
          >
            {isExplaining ? 'Explaining...' : 'Explain rule'}
          </button>
          <button
            onClick={handleAiConvert}
            disabled={!sourceCode.trim() || busy || !aiAvailable}
            title={aiAvailable ? undefined : 'Requires an AI provider key for this organization'}
            className="flex items-center gap-2 rounded-md border px-4 py-2 text-sm disabled:opacity-50"
          >
            <Sparkles className="h-4 w-4" />
            {isAiConverting ? 'Converting...' : 'AI convert'}
          </button>
        </div>

        {!aiAvailable && (
          <p className="mt-2 text-xs text-muted-foreground">
            AI-assisted conversion and explanation need an provider key configured for this
            organization; the deterministic converter above works without one.
          </p>
        )}
      </div>

      {error && (
        <div className="flex items-start gap-2 rounded-md border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-500">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {summary && (
        <div className="flex items-start gap-2 rounded-md border border-green-500/40 bg-green-500/10 p-3 text-sm text-green-600">
          <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{summary}</span>
        </div>
      )}

      {output && (
        <div className="rounded-lg border bg-background p-6">
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-lg font-semibold">Output</h2>
            <button
              onClick={() => navigator.clipboard?.writeText(output)}
              className="rounded-md border px-3 py-1 text-xs"
            >
              Copy
            </button>
          </div>
          <pre className="overflow-x-auto rounded-md bg-muted/40 p-3 font-mono text-xs">
            {output}
          </pre>
        </div>
      )}

      {explanation && (
        <div className="rounded-lg border bg-background p-6">
          <h2 className="mb-2 text-lg font-semibold">Explanation</h2>
          <p className="whitespace-pre-wrap text-sm text-muted-foreground">{explanation}</p>
        </div>
      )}
    </div>
  )
}
