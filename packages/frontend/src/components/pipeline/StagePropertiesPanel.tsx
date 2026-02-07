/**
 * StagePropertiesPanel - Configuration panel for selected pipeline stages.
 *
 * Renders a dynamic form based on the stage's config schema,
 * allowing users to configure stage-specific options.
 */

import { useEffect, useState } from 'react'
import { Node } from 'reactflow'
import {
  X,
  Trash2,
  Settings,
  Info,
  Plus,
  Minus,
  Shuffle,
  ArrowRightLeft,
  Braces,
  Filter,
  Percent,
  CopyX,
  GitBranch,
  LucideIcon,
} from 'lucide-react'
import { cn } from '../../lib/utils'
import { StageCategory, useListStageTypesQuery } from '../../api/pantherApi'
import { StageNodeData } from './StageNode'

// Stage type to icon mapping
const stageIcons: Record<string, LucideIcon> = {
  ocsf_transform: Shuffle,
  field_mapper: ArrowRightLeft,
  parse_json: Braces,
  condition_filter: Filter,
  sample: Percent,
  dedupe: CopyX,
  route: GitBranch,
}

// Category styling
const categoryStyles: Record<StageCategory, { text: string }> = {
  transform: { text: 'text-blue-400' },
  filter: { text: 'text-yellow-400' },
  route: { text: 'text-green-400' },
}

interface StagePropertiesPanelProps {
  selectedNode: Node<StageNodeData> | null
  onUpdate: (nodeId: string, config: Record<string, unknown>) => void
  onDelete: (nodeId: string) => void
  onClose: () => void
  className?: string
}

export default function StagePropertiesPanel({
  selectedNode,
  onUpdate,
  onDelete,
  onClose,
  className,
}: StagePropertiesPanelProps) {
  const { data: stageTypes } = useListStageTypesQuery()
  const [localConfig, setLocalConfig] = useState<Record<string, unknown>>({})
  const [isEnabled, setIsEnabled] = useState(true)

  // Find the metadata for the selected stage type
  const stageMetadata = stageTypes?.find(
    (s) => s.stage_type === selectedNode?.data.stageType
  )

  // Sync local state with selected node
  useEffect(() => {
    if (selectedNode) {
      setLocalConfig(selectedNode.data.config || {})
      setIsEnabled(selectedNode.data.enabled !== false)
    }
  }, [selectedNode])

  // Handle config changes
  const handleConfigChange = (key: string, value: unknown) => {
    const newConfig = { ...localConfig, [key]: value }
    setLocalConfig(newConfig)
    if (selectedNode) {
      onUpdate(selectedNode.id, newConfig)
    }
  }

  // Handle array field changes
  const handleArrayAdd = (key: string, defaultValue: unknown = '') => {
    const currentArray = (localConfig[key] as unknown[]) || []
    handleConfigChange(key, [...currentArray, defaultValue])
  }

  const handleArrayRemove = (key: string, index: number) => {
    const currentArray = (localConfig[key] as unknown[]) || []
    handleConfigChange(key, currentArray.filter((_, i) => i !== index))
  }

  const handleArrayItemChange = (key: string, index: number, value: unknown) => {
    const currentArray = [...((localConfig[key] as unknown[]) || [])]
    currentArray[index] = value
    handleConfigChange(key, currentArray)
  }

  if (!selectedNode) {
    return (
      <div className={cn('w-80 border-l bg-background flex flex-col', className)}>
        <div className="flex-1 flex items-center justify-center text-muted-foreground">
          <div className="text-center p-6">
            <Settings size={48} className="mx-auto mb-4 opacity-20" />
            <p>Select a stage to configure</p>
          </div>
        </div>
      </div>
    )
  }

  const Icon = stageIcons[selectedNode.data.stageType] || Shuffle
  const style = categoryStyles[selectedNode.data.category] || categoryStyles.transform

  // Render a form field based on JSON Schema property
  const renderField = (key: string, schema: Record<string, unknown>) => {
    const type = schema.type as string
    const title = (schema.title as string) || key
    const description = schema.description as string
    const value = localConfig[key]
    const enumValues = schema.enum as string[] | undefined

    // Select dropdown for enum values
    if (enumValues) {
      return (
        <div key={key} className="space-y-1">
          <label className="text-sm font-medium">{title}</label>
          <select
            value={(value as string) || ''}
            onChange={(e) => handleConfigChange(key, e.target.value)}
            className="w-full px-3 py-2 rounded-md border bg-background text-sm"
          >
            <option value="">Select...</option>
            {enumValues.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
          {description && (
            <p className="text-xs text-muted-foreground">{description}</p>
          )}
        </div>
      )
    }

    // Array field
    if (type === 'array') {
      const items = (value as unknown[]) || []
      const itemSchema = schema.items as Record<string, unknown>
      const itemType = itemSchema?.type as string

      return (
        <div key={key} className="space-y-2">
          <div className="flex items-center justify-between">
            <label className="text-sm font-medium">{title}</label>
            <button
              onClick={() => handleArrayAdd(key, itemType === 'object' ? {} : '')}
              className="p-1 rounded hover:bg-accent"
              title="Add item"
            >
              <Plus size={14} />
            </button>
          </div>
          {description && (
            <p className="text-xs text-muted-foreground">{description}</p>
          )}
          <div className="space-y-2">
            {items.map((item, index) => (
              <div key={index} className="flex items-center gap-2">
                {itemType === 'object' ? (
                  <div className="flex-1 p-2 rounded border bg-muted/50 text-xs">
                    {JSON.stringify(item)}
                  </div>
                ) : (
                  <input
                    type="text"
                    value={(item as string) || ''}
                    onChange={(e) => handleArrayItemChange(key, index, e.target.value)}
                    className="flex-1 px-3 py-1.5 rounded-md border bg-background text-sm"
                    placeholder={`Item ${index + 1}`}
                  />
                )}
                <button
                  onClick={() => handleArrayRemove(key, index)}
                  className="p-1 rounded hover:bg-accent text-destructive"
                  title="Remove item"
                >
                  <Minus size={14} />
                </button>
              </div>
            ))}
          </div>
        </div>
      )
    }

    // Boolean field
    if (type === 'boolean') {
      return (
        <div key={key} className="flex items-center justify-between">
          <div>
            <label className="text-sm font-medium">{title}</label>
            {description && (
              <p className="text-xs text-muted-foreground">{description}</p>
            )}
          </div>
          <button
            onClick={() => handleConfigChange(key, !value)}
            className={cn(
              'w-10 h-6 rounded-full transition-colors relative',
              value ? 'bg-primary' : 'bg-muted'
            )}
          >
            <div
              className={cn(
                'w-4 h-4 rounded-full bg-white absolute top-1 transition-transform',
                value ? 'translate-x-5' : 'translate-x-1'
              )}
            />
          </button>
        </div>
      )
    }

    // Number field
    if (type === 'number' || type === 'integer') {
      const min = schema.minimum as number | undefined
      const max = schema.maximum as number | undefined
      return (
        <div key={key} className="space-y-1">
          <label className="text-sm font-medium">{title}</label>
          <input
            type="number"
            value={(value as number) || ''}
            onChange={(e) => handleConfigChange(key, parseFloat(e.target.value))}
            min={min}
            max={max}
            step={type === 'integer' ? 1 : 0.01}
            className="w-full px-3 py-2 rounded-md border bg-background text-sm"
            placeholder={`Enter ${title.toLowerCase()}`}
          />
          {description && (
            <p className="text-xs text-muted-foreground">{description}</p>
          )}
        </div>
      )
    }

    // Text field (default)
    return (
      <div key={key} className="space-y-1">
        <label className="text-sm font-medium">{title}</label>
        <input
          type="text"
          value={(value as string) || ''}
          onChange={(e) => handleConfigChange(key, e.target.value)}
          className="w-full px-3 py-2 rounded-md border bg-background text-sm"
          placeholder={`Enter ${title.toLowerCase()}`}
        />
        {description && (
          <p className="text-xs text-muted-foreground">{description}</p>
        )}
      </div>
    )
  }

  return (
    <div className={cn('w-80 border-l bg-background flex flex-col', className)}>
      {/* Header */}
      <div className="p-4 border-b">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className={cn('p-1.5 rounded bg-muted', style.text)}>
              <Icon size={16} />
            </div>
            <div>
              <h3 className="font-semibold">{selectedNode.data.label}</h3>
              <p className={cn('text-xs', style.text)}>{selectedNode.data.category}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-accent text-muted-foreground"
          >
            <X size={18} />
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-4 space-y-4">
        {/* Description */}
        {stageMetadata?.description && (
          <div className="flex gap-2 p-3 rounded-lg bg-muted/50 text-sm">
            <Info size={16} className="shrink-0 text-muted-foreground mt-0.5" />
            <p className="text-muted-foreground">{stageMetadata.description}</p>
          </div>
        )}

        {/* Enabled toggle */}
        <div className="flex items-center justify-between">
          <div>
            <label className="text-sm font-medium">Enabled</label>
            <p className="text-xs text-muted-foreground">
              Disable to skip this stage
            </p>
          </div>
          <button
            onClick={() => {
              setIsEnabled(!isEnabled)
              // Would trigger node update
            }}
            className={cn(
              'w-10 h-6 rounded-full transition-colors relative',
              isEnabled ? 'bg-primary' : 'bg-muted'
            )}
          >
            <div
              className={cn(
                'w-4 h-4 rounded-full bg-white absolute top-1 transition-transform',
                isEnabled ? 'translate-x-5' : 'translate-x-1'
              )}
            />
          </button>
        </div>

        <hr />

        {/* Dynamic config fields */}
        {stageMetadata?.config_schema?.properties ? (
          <div className="space-y-4">
            {Object.entries(stageMetadata.config_schema.properties as Record<string, Record<string, unknown>>).map(
              ([key, schema]) => renderField(key, schema)
            )}
          </div>
        ) : (
          <div className="text-sm text-muted-foreground">
            No configuration options for this stage type.
          </div>
        )}

        {/* JSON view toggle (for debugging) */}
        <details className="text-xs">
          <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
            View raw config
          </summary>
          <pre className="mt-2 p-2 rounded bg-muted overflow-auto text-xs">
            {JSON.stringify(localConfig, null, 2)}
          </pre>
        </details>
      </div>

      {/* Footer */}
      <div className="p-4 border-t">
        <button
          onClick={() => onDelete(selectedNode.id)}
          className="flex items-center justify-center gap-2 w-full px-4 py-2 rounded-md border border-destructive text-destructive hover:bg-destructive/10 text-sm font-medium"
        >
          <Trash2 size={16} />
          Delete Stage
        </button>
      </div>
    </div>
  )
}
