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
