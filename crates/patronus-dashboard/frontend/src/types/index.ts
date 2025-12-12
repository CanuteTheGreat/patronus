export interface User {
  id: string
  email: string
  role: 'Admin' | 'Operator' | 'Viewer'
  active: boolean
  createdAt: string
  lastLogin?: string
}

export interface Site {
  id: string
  name: string
  location: string
  status: 'Active' | 'Degraded' | 'Down'
  endpointCount: number
  createdAt: string
  updatedAt: string
}

export interface Policy {
  id: string
  name: string
  description?: string
  priority: number
  matchRules: string
  action: string
  enabled: boolean
  packetsMatched: number
  bytesMatched: number
  createdAt: string
}

export interface Path {
  id: string
  sourceSiteId: string
  destinationSiteId: string
  latencyMs: number
  packetLoss: number
  bandwidthMbps: number
  qualityScore: number
  status: 'Active' | 'Degraded' | 'Down'
  lastUpdated: string
}

export interface Metrics {
  timestamp: string
  throughputMbps: number
  packetsPerSecond: number
  activeFlows: number
  avgLatencyMs: number
  avgPacketLoss: number
  cpuUsage: number
  memoryUsage: number
}

export interface AuditLog {
  id: string
  userId: string
  eventType: string
  description: string
  ipAddress: string
  timestamp: string
  metadata?: string
}

export interface SystemAlert {
  id: string
  severity: 'Critical' | 'Warning' | 'Info'
  title: string
  message: string
  timestamp: string
}

export interface HealthStatus {
  status: string
  version: string
  uptime: number
}

export interface VersionInfo {
  version: string
  buildDate: string
  gitCommit: string
}

export interface ApiKey {
  id: string
  name: string
  prefix: string
  key?: string // Only returned on creation
  createdAt: string
  lastUsed?: string
  expiresAt?: string
  revoked: boolean
}

export interface SystemInfo {
  version: string
  buildDate: string
  rustVersion: string
  uptime: number
  cpuUsage: number
  memoryUsage: number
  memoryTotal: number
  diskUsage: number
  diskTotal: number
  activeSessions: number
  totalSites: number
  totalPolicies: number
}

export interface CreateApiKeyInput {
  name: string
  expiresInDays: number
}

export interface UpdateProfileInput {
  email?: string
  displayName?: string
}

export interface SystemHealthCheck {
  status: string
  checks: {
    name: string
    status: string
    message?: string
  }[]
}

export interface LoginResponse {
  login: {
    accessToken: string
    refreshToken: string
    user: User
  }
}

export interface CreateSiteInput {
  name: string
  location: string
}

export interface UpdateSiteInput {
  name?: string
  location?: string
  status?: 'Active' | 'Degraded' | 'Down'
}

export interface CreatePolicyInput {
  name: string
  description?: string
  priority: number
  matchRules: string
  action: string
  enabled: boolean
}

export interface UpdatePolicyInput {
  name?: string
  description?: string
  priority?: number
  matchRules?: string
  action?: string
  enabled?: boolean
}

export interface CreateUserInput {
  email: string
  password: string
  role: 'Admin' | 'Operator' | 'Viewer'
  active: boolean
}

export interface UpdateUserInput {
  email?: string
  password?: string
  role?: 'Admin' | 'Operator' | 'Viewer'
  active?: boolean
}

export interface PaginationInput {
  page: number
  limit: number
}

export interface SiteFilter {
  status?: string
  search?: string
}

export interface PolicyFilter {
  enabled?: boolean
  action?: string
  search?: string
}

// Action types for policies
export const POLICY_ACTIONS = [
  { value: 'route_lowest_latency', label: 'Route - Lowest Latency' },
  { value: 'route_highest_bandwidth', label: 'Route - Highest Bandwidth' },
  { value: 'route_least_loss', label: 'Route - Least Packet Loss' },
  { value: 'route_round_robin', label: 'Route - Round Robin' },
  { value: 'route_weighted', label: 'Route - Weighted' },
  { value: 'drop', label: 'Drop' },
  { value: 'allow', label: 'Allow' },
  { value: 'reject', label: 'Reject' },
  { value: 'rate_limit', label: 'Rate Limit' },
  { value: 'redirect', label: 'Redirect' },
] as const

// Helper type for policy action values
export type PolicyAction = typeof POLICY_ACTIONS[number]['value']

// Event types for audit logs
export const AUDIT_EVENT_TYPES = [
  'login',
  'logout',
  'login_failed',
  'password_change',
  'site_created',
  'site_updated',
  'site_deleted',
  'policy_created',
  'policy_updated',
  'policy_deleted',
  'user_created',
  'user_updated',
  'user_deleted',
  'settings_changed',
  'cache_cleared',
] as const

export type AuditEventType = typeof AUDIT_EVENT_TYPES[number]

// Format bytes to human readable
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

// Format large numbers
export function formatNumber(num: number): string {
  if (num >= 1e9) return (num / 1e9).toFixed(2) + 'B'
  if (num >= 1e6) return (num / 1e6).toFixed(2) + 'M'
  if (num >= 1e3) return (num / 1e3).toFixed(2) + 'K'
  return num.toLocaleString()
}

// Get quality color class
export function getQualityColor(score: number): string {
  if (score >= 80) return 'text-green-600 dark:text-green-400'
  if (score >= 60) return 'text-blue-600 dark:text-blue-400'
  if (score >= 40) return 'text-yellow-600 dark:text-yellow-400'
  return 'text-red-600 dark:text-red-400'
}

// Get status color class
export function getStatusColor(status: string): string {
  switch (status) {
    case 'Active':
      return 'text-green-600 dark:text-green-400'
    case 'Degraded':
      return 'text-yellow-600 dark:text-yellow-400'
    case 'Down':
      return 'text-red-600 dark:text-red-400'
    default:
      return 'text-gray-600 dark:text-gray-400'
  }
}
