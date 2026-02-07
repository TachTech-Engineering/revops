/**
 * StagePalette - Draggable stage palette for the pipeline editor.
 *
 * Shows available stage types organized by category.
 * Stages can be dragged onto the canvas to add them to the pipeline.
 */

import { DragEvent } from 'react'
import {
  Shuffle,
  ArrowRightLeft,
  Braces,
  Filter,
  Percent,
  CopyX,
  GitBranch,
  LucideIcon,
  ChevronDown,
} from 'lucide-react'
import { cn } from '../../lib/utils'
import { StageTypeMetadata, StageCategory, useListStageTypesQuery } from '../../api/pantherApi'

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

// Category configuration
const categoryConfig: Record<StageCategory, { label: string; color: string; bgColor: string }> = {
  transform: {
    label: 'Transform',
    color: 'text-blue-400',
    bgColor: 'bg-blue-500/10 hover:bg-blue-500/20',
  },
  filter: {
    label: 'Filter',
    color: 'text-yellow-400',
    bgColor: 'bg-yellow-500/10 hover:bg-yellow-500/20',
  },
  route: {
    label: 'Route',
    color: 'text-green-400',
    bgColor: 'bg-green-500/10 hover:bg-green-500/20',
  },
}

interface StagePaletteProps {
  className?: string
}

export default function StagePalette({ className }: StagePaletteProps) {
  const { data: stageTypes, isLoading } = useListStageTypesQuery()

  const onDragStart = (event: DragEvent, stageType: StageTypeMetadata) => {
    event.dataTransfer.setData('application/reactflow', JSON.stringify({
      type: 'stageNode',
      stageType: stageType.stage_type,
      category: stageType.category,
      label: stageType.display_name,
      config: {},
    }))
    event.dataTransfer.effectAllowed = 'move'
  }

  // Group stages by category
  const stagesByCategory: Record<StageCategory, StageTypeMetadata[]> = stageTypes?.reduce((acc, stage) => {
    const category = stage.category as StageCategory
    if (!acc[category]) {
      acc[category] = []
    }
    acc[category].push(stage)
    return acc
  }, {} as Record<StageCategory, StageTypeMetadata[]>) || { transform: [], filter: [], route: [] }

  return (
    <div className={cn('w-64 border-r bg-background flex flex-col', className)}>
      <div className="p-4 border-b">
        <h2 className="font-semibold">Stages</h2>
        <p className="text-xs text-muted-foreground mt-1">
          Drag stages onto the canvas
        </p>
      </div>

      {isLoading ? (
        <div className="p-4 text-center text-muted-foreground text-sm">
          Loading stages...
        </div>
      ) : (
        <div className="flex-1 overflow-auto p-2 space-y-4">
          {(['transform', 'filter', 'route'] as StageCategory[]).map((category) => {
            const stages = stagesByCategory[category] || []
            const config = categoryConfig[category]

            return (
              <div key={category}>
                <div className={cn('flex items-center gap-2 px-2 py-1 text-sm font-medium', config.color)}>
                  <span>{config.label}</span>
                  <span className="text-xs text-muted-foreground">({stages.length})</span>
                </div>

                <div className="mt-1 space-y-1">
                  {stages.map((stage: StageTypeMetadata) => {
                    const Icon = stageIcons[stage.stage_type] || Shuffle

                    return (
                      <div
                        key={stage.stage_type}
                        draggable
                        onDragStart={(e) => onDragStart(e, stage)}
                        className={cn(
                          'flex items-center gap-2 px-3 py-2 rounded-md cursor-grab active:cursor-grabbing transition-colors',
                          config.bgColor
                        )}
                        title={stage.description}
                      >
                        <Icon size={16} className={config.color} />
                        <div className="flex-1 min-w-0">
                          <div className="text-sm font-medium truncate">{stage.display_name}</div>
                        </div>
                      </div>
                    )
                  })}

                  {stages.length === 0 && (
                    <div className="px-3 py-2 text-xs text-muted-foreground">
                      No {category} stages available
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Help Section */}
      <div className="p-4 border-t bg-muted/30">
        <details className="text-xs">
          <summary className="flex items-center gap-1 cursor-pointer text-muted-foreground hover:text-foreground">
            <ChevronDown size={14} />
            <span>How to use</span>
          </summary>
          <div className="mt-2 space-y-2 text-muted-foreground">
            <p>1. Drag stages from here onto the canvas</p>
            <p>2. Connect stages by dragging from output to input handles</p>
            <p>3. Click a stage to configure it</p>
            <p>4. Save your pipeline when done</p>
          </div>
        </details>
      </div>
    </div>
  )
}
