import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDate(date: string | null): string {
  if (!date) return '-'
  return new Date(date).toLocaleString()
}

export function getSeverityColor(severity: string): string {
  const colors: Record<string, string> = {
    INFO: 'bg-blue-500/20 text-blue-400 border border-blue-500/30',
    LOW: 'bg-green-500/20 text-green-400 border border-green-500/30',
    MEDIUM: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
    HIGH: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
    CRITICAL: 'bg-red-500/20 text-red-400 border border-red-500/30',
  }
  return colors[severity] || 'bg-gray-500/20 text-gray-400 border border-gray-500/30'
}

export function getStatusColor(status: string): string {
  const colors: Record<string, string> = {
    OPEN: 'bg-red-500/20 text-red-400 border border-red-500/30',
    TRIAGED: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
    CLOSED: 'bg-gray-500/20 text-gray-400 border border-gray-500/30',
    RESOLVED: 'bg-green-500/20 text-green-400 border border-green-500/30',
  }
  return colors[status] || 'bg-gray-500/20 text-gray-400 border border-gray-500/30'
}

// Generate unique node ID for React Flow
export function generateNodeId(): string {
  return `node_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
}

// Generate unique edge ID for React Flow
export function generateEdgeId(source: string, target: string): string {
  return `edge_${source}_${target}_${Date.now()}`
}
