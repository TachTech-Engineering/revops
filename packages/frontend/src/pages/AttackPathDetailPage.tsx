import { memo, useMemo } from 'react'
import { Link, useParams } from 'react-router-dom'
import ReactFlow, {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  type Edge,
  type Node,
  type NodeProps,
} from 'reactflow'
import 'reactflow/dist/style.css'
import {
  ArrowLeft,
  Boxes,
  Cloud,
  Database,
  Globe,
  Server,
  User,
} from 'lucide-react'
import {
  useGetAttackPathQuery,
  useDismissAttackPathMutation,
  useReopenAttackPathMutation,
  type AttackPathGraphEdge,
  type AttackPathGraphNode,
} from '../api/pantherApi'
import { cn } from '../lib/utils'
import { formatRelativeTime } from '../lib/dateUtils'
import { getApiErrorMessage } from '../lib/apiError'
import { useToast } from '../components/common/Toast'
import {
  SeverityBadge,
  SourceTypeBadge,
  StatusBadge,
} from '../components/cnapp/badges'
import { assetTypeLabel, riskScoreColor } from '../lib/cnapp'

// ---------------------------------------------------------------------------
// Graph node rendering
// ---------------------------------------------------------------------------

interface PathNodeData {
  label: string
  nodeType: string
  isInternet: boolean
  isAsset: boolean
}

const nodeIcons: Record<string, React.ElementType> = {
  internet: Globe,
  cloud_account: Cloud,
  storage_bucket: Database,
  database: Database,
  iam_identity: User,
  iam_role: User,
  host: Server,
  vm_instance: Server,
}

function PathNodeComponent({ data }: NodeProps<PathNodeData>) {
  const Icon = nodeIcons[data.nodeType] || Boxes
  return (
    <div
      className={cn(
        'rounded-lg border-2 px-4 py-3 min-w-[150px] bg-card',
        data.isInternet && 'bg-red-500/10 border-red-500/60',
        data.isAsset && 'border-primary ring-2 ring-primary/30',
        !data.isInternet && !data.isAsset && 'border-border'
      )}
    >
      <Handle type="target" position={Position.Left} className="!bg-muted-foreground" />
      <div className="flex items-center gap-2">
        <Icon
          size={16}
          className={cn(
            data.isInternet
              ? 'text-red-400'
              : data.isAsset
                ? 'text-primary'
                : 'text-muted-foreground'
          )}
        />
        <div>
          <p
            className={cn(
              'text-sm font-medium',
              data.isInternet ? 'text-red-400' : 'text-foreground'
            )}
          >
            {data.label}
          </p>
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
            {data.nodeType.replace(/_/g, ' ')}
          </p>
        </div>
      </div>
      <Handle type="source" position={Position.Right} className="!bg-muted-foreground" />
    </div>
  )
}

const nodeTypes = { pathNode: memo(PathNodeComponent) }

// Lay the path out left-to-right: BFS depth from the roots (nodes with no
// incoming edge, i.e. the internet node) sets the column; siblings stack.
function layoutPath(
  pathNodes: AttackPathGraphNode[],
  pathEdges: AttackPathGraphEdge[],
  assetId: string
): { nodes: Node<PathNodeData>[]; edges: Edge[] } {
  const depths = new Map<string, number>()
  const incoming = new Set(pathEdges.map((e) => e.target))
  const queue = pathNodes.filter((n) => !incoming.has(n.id)).map((n) => n.id)
  queue.forEach((id) => depths.set(id, 0))
  while (queue.length > 0) {
    const current = queue.shift()!
    const depth = depths.get(current) ?? 0
    for (const edge of pathEdges) {
      if (edge.source === current && (depths.get(edge.target) ?? -1) < depth + 1) {
        depths.set(edge.target, depth + 1)
        queue.push(edge.target)
      }
    }
  }

  const perDepthCount = new Map<number, number>()
  const nodes: Node<PathNodeData>[] = pathNodes.map((n, i) => {
    const depth = depths.get(n.id) ?? i
    const row = perDepthCount.get(depth) ?? 0
    perDepthCount.set(depth, row + 1)
    return {
      id: n.id,
      type: 'pathNode',
      position: { x: depth * 240, y: row * 110 },
      data: {
        label: n.label,
        nodeType: n.type,
        isInternet: n.type === 'internet',
        isAsset: n.asset_id === assetId,
      },
      draggable: false,
      connectable: false,
    }
  })

  const edges: Edge[] = pathEdges.map((e, i) => ({
    id: `edge-${e.source}-${e.target}-${i}`,
    source: e.source,
    target: e.target,
    label: e.label || undefined,
    animated: true,
    markerEnd: { type: MarkerType.ArrowClosed },
    style: { strokeWidth: 1.5 },
  }))

  return { nodes, edges }
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function AttackPathDetailPage() {
  const { findingId } = useParams<{ findingId: string }>()
  const toast = useToast()

  const { data, isLoading, error } = useGetAttackPathQuery(findingId!, {
    skip: !findingId,
  })
  const [dismissAttackPath, { isLoading: isDismissing }] = useDismissAttackPathMutation()
  const [reopenAttackPath, { isLoading: isReopening }] = useReopenAttackPathMutation()

  const graph = useMemo(() => {
    if (!data?.path?.nodes?.length) return { nodes: [], edges: [] }
    return layoutPath(data.path.nodes, data.path.edges || [], data.asset.id)
  }, [data])

  const handleDismiss = async () => {
    if (!findingId) return
    try {
      await dismissAttackPath(findingId).unwrap()
      toast.success('Attack path dismissed.')
    } catch (err) {
      toast.error(`Could not dismiss attack path. ${getApiErrorMessage(err)}`)
    }
  }

  const handleReopen = async () => {
    if (!findingId) return
    try {
      await reopenAttackPath(findingId).unwrap()
      toast.success('Attack path reopened.')
    } catch (err) {
      toast.error(`Could not reopen attack path. ${getApiErrorMessage(err)}`)
    }
  }

  if (error) {
    return (
      <div className="p-4">
        <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4 text-destructive">
          Failed to load attack path
        </div>
      </div>
    )
  }

  if (isLoading || !data) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  return (
    <div className="p-6">
      <Link
        to="/attack-paths"
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground transition-colors mb-4"
      >
        <ArrowLeft size={16} />
        Back to Attack Paths
      </Link>

      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 mb-6">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-3 mb-2">
            <h1 className="text-2xl font-bold text-foreground">{data.title}</h1>
            <SeverityBadge severity={data.severity} />
            <StatusBadge status={data.status} />
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted-foreground">
            <span className="px-2 py-0.5 rounded bg-muted font-mono text-xs">
              {data.rule_key}
            </span>
            <span>
              Asset:{' '}
              <Link
                to={`/assets/${data.asset.id}`}
                className="text-primary hover:text-primary/80"
              >
                {data.asset.name}
              </Link>{' '}
              · {assetTypeLabel(data.asset.asset_type)}
            </span>
            <span>First detected {formatRelativeTime(data.first_detected)}</span>
            <span>Last evaluated {formatRelativeTime(data.last_evaluated)}</span>
            {data.resolved_at && <span>Resolved {formatRelativeTime(data.resolved_at)}</span>}
            {data.incident_id && (
              <Link
                to={`/incidents/${data.incident_id}`}
                className="text-primary hover:text-primary/80"
              >
                View incident
              </Link>
            )}
          </div>
          {data.description && (
            <p className="text-sm text-muted-foreground mt-3 max-w-3xl">{data.description}</p>
          )}
        </div>

        <div className="flex items-center gap-4 shrink-0">
          <div className="text-center">
            <p className={cn('text-4xl font-bold', riskScoreColor(data.risk_score))}>
              {Math.round(data.risk_score)}
            </p>
            <p className="text-xs uppercase tracking-wider text-muted-foreground">
              risk score
            </p>
          </div>
          {data.status === 'open' ? (
            <button
              onClick={handleDismiss}
              disabled={isDismissing}
              className="px-4 py-2 border border-border rounded-lg text-foreground hover:bg-muted disabled:opacity-50 transition-colors"
            >
              {isDismissing ? 'Dismissing...' : 'Dismiss'}
            </button>
          ) : (
            <button
              onClick={handleReopen}
              disabled={isReopening}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50 transition-colors"
            >
              {isReopening ? 'Reopening...' : 'Reopen'}
            </button>
          )}
        </div>
      </div>

      {/* Attack path graph */}
      <section className="mb-8">
        <h2 className="text-lg font-semibold text-foreground mb-3">Attack Path</h2>
        <div className="bg-card border border-border rounded-lg overflow-hidden h-80">
          {graph.nodes.length === 0 ? (
            <div className="flex items-center justify-center h-full text-muted-foreground">
              No path data available
            </div>
          ) : (
            <ReactFlow
              nodes={graph.nodes}
              edges={graph.edges}
              nodeTypes={nodeTypes}
              fitView
              fitViewOptions={{ padding: 0.25 }}
              nodesDraggable={false}
              nodesConnectable={false}
              elementsSelectable={false}
              zoomOnScroll={false}
              preventScrolling={false}
            >
              <Controls showInteractive={false} />
              <Background gap={20} size={1} />
            </ReactFlow>
          )}
        </div>
      </section>

      {/* Evidence */}
      <section>
        <h2 className="text-lg font-semibold text-foreground mb-3">
          Evidence ({data.evidence.length})
        </h2>
        <div className="bg-card border border-border rounded-lg shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-border">
              <thead className="bg-muted/50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Source
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Title
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Severity
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Tags
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {data.evidence.map((alert) => (
                  <tr key={alert.id} className="hover:bg-muted/30 transition-colors">
                    <td className="px-6 py-4">
                      <SourceTypeBadge sourceType={alert.source_type} />
                    </td>
                    <td className="px-6 py-4">
                      <Link
                        to={`/alerts/${alert.id}`}
                        className="text-sm text-primary hover:text-primary/80"
                      >
                        {alert.title}
                      </Link>
                      {alert.rule_id && (
                        <p className="text-xs text-muted-foreground font-mono truncate max-w-xs">
                          {alert.rule_id}
                        </p>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="px-6 py-4">
                      <StatusBadge status={alert.status} />
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-wrap gap-1 max-w-xs">
                        {(alert.tags || []).slice(0, 4).map((tag) => (
                          <span
                            key={tag}
                            className="px-2 py-0.5 text-xs rounded bg-muted text-muted-foreground"
                          >
                            {tag}
                          </span>
                        ))}
                        {(alert.tags || []).length > 4 && (
                          <span className="text-xs text-muted-foreground">
                            +{alert.tags.length - 4}
                          </span>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
                {data.evidence.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-6 py-12 text-center text-muted-foreground">
                      No contributing alerts
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  )
}
