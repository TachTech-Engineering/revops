/**
 * Shared constants + helpers for the CNAPP pages
 * (Assets, Asset detail, Attack Paths, Attack Path detail).
 *
 * Kept separate from the badge components so files that export React
 * components only export components (react-refresh/only-export-components).
 */

export const severityConfig: Record<string, { color: string; label: string }> = {
  critical: { color: 'bg-red-500/20 text-red-400', label: 'Critical' },
  high: { color: 'bg-orange-500/20 text-orange-400', label: 'High' },
  medium: { color: 'bg-yellow-500/20 text-yellow-400', label: 'Medium' },
  low: { color: 'bg-blue-500/20 text-blue-400', label: 'Low' },
  info: { color: 'bg-gray-500/20 text-gray-400', label: 'Info' },
}

// For severity-sorting lists client-side (lower rank = more severe).
export const severityRank: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

export const assetTypeLabels: Record<string, string> = {
  host: 'Host',
  vm_instance: 'VM Instance',
  container: 'Container',
  container_image: 'Container Image',
  k8s_pod: 'K8s Pod',
  k8s_namespace: 'K8s Namespace',
  k8s_cluster: 'K8s Cluster',
  cloud_account: 'Cloud Account',
  storage_bucket: 'Storage Bucket',
  database: 'Database',
  iam_identity: 'IAM Identity',
  iam_role: 'IAM Role',
  network: 'Network',
  serverless_function: 'Serverless Function',
  load_balancer: 'Load Balancer',
  service: 'Service',
  other: 'Other',
}

export function assetTypeLabel(assetType: string): string {
  return assetTypeLabels[assetType] || assetType
}

// Risk score coloring (0-100): red-hot at the top, cooler as it drops.
export function riskScoreColor(score: number): string {
  if (score >= 75) return 'text-red-400'
  if (score >= 50) return 'text-orange-400'
  if (score >= 25) return 'text-yellow-400'
  return 'text-blue-400'
}
