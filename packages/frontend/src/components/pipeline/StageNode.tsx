/**
 * StageNode - React Flow node component for pipeline stages.
 *
 * Renders a visual representation of a pipeline stage with
 * category-specific styling, handles for connections, and
 * configuration display.
 */

import { memo } from 'react'
import { Handle, Position, NodeProps } from 'reactflow'
import {
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
import { StageCategory } from '../../api/pantherApi'

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
const categoryStyles: Record<StageCategory, { bg: string; border: string; text: string; handle: string }> = {
  transform: {
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/50',
    text: 'text-blue-400',
    handle: 'bg-blue-500',
  },
  filter: {
    bg: 'bg-yellow-500/10',
    border: 'border-yellow-500/50',
    text: 'text-yellow-400',
    handle: 'bg-yellow-500',
  },
  route: {
    bg: 'bg-green-500/10',
    border: 'border-green-500/50',
    text: 'text-green-400',
    handle: 'bg-green-500',
  },
}

export interface StageNodeData {
  label: string
  stageType: string
  category: StageCategory
  config: Record<string, unknown>
  enabled: boolean
  outputHandles?: { id: string; label: string }[]
}

function StageNode({ data, selected }: NodeProps<StageNodeData>) {
  const Icon = stageIcons[data.stageType] || Shuffle
  const style = categoryStyles[data.category] || categoryStyles.transform
  const hasMultipleOutputs = data.outputHandles && data.outputHandles.length > 1

  return (
    <div
      className={cn(
        'rounded-lg border-2 min-w-[180px] transition-all',
        style.bg,
        style.border,
        selected && 'ring-2 ring-primary ring-offset-2 ring-offset-background',
        !data.enabled && 'opacity-50'
      )}
    >
      {/* Input Handle */}
      <Handle
        type="target"
        position={Position.Left}
        className={cn('w-3 h-3 rounded-full border-2 border-background', style.handle)}
      />

      {/* Content */}
      <div className="px-3 py-2">
        <div className="flex items-center gap-2">
          <div className={cn('p-1.5 rounded', style.bg)}>
            <Icon size={16} className={style.text} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="font-medium text-sm truncate">{data.label}</div>
            <div className={cn('text-xs', style.text)}>{data.category}</div>
          </div>
        </div>

        {/* Config Preview */}
        {data.config && Object.keys(data.config).length > 0 && (
          <div className="mt-2 pt-2 border-t border-border/50">
            <div className="text-xs text-muted-foreground space-y-0.5">
              {Object.entries(data.config).slice(0, 2).map(([key, value]) => (
                <div key={key} className="flex justify-between gap-2">
                  <span className="truncate">{key}:</span>
                  <span className="font-medium truncate max-w-[80px]">
                    {typeof value === 'object' ? '...' : String(value)}
                  </span>
                </div>
              ))}
              {Object.keys(data.config).length > 2 && (
                <div className="text-center">+{Object.keys(data.config).length - 2} more</div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Output Handles */}
      {hasMultipleOutputs ? (
        // Multiple outputs (e.g., route stage)
        <div className="flex flex-col gap-1 absolute right-0 top-1/2 -translate-y-1/2 translate-x-1/2">
          {data.outputHandles?.map((handle) => (
            <Handle
              key={handle.id}
              id={handle.id}
              type="source"
              position={Position.Right}
              className={cn(
                'w-3 h-3 rounded-full border-2 border-background relative',
                style.handle
              )}
              style={{
                position: 'relative',
                top: 'auto',
                transform: 'none',
              }}
            />
          ))}
        </div>
      ) : (
        // Single output
        <Handle
          type="source"
          position={Position.Right}
          className={cn('w-3 h-3 rounded-full border-2 border-background', style.handle)}
        />
      )}
    </div>
  )
}

export default memo(StageNode)

// Node type registration for React Flow
export const stageNodeTypes = {
  stageNode: StageNode,
}
