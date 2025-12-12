import { gql } from '@apollo/client'

// Auth queries
export const LOGIN = gql`
  mutation Login($email: String!, $password: String!) {
    login(email: $email, password: $password) {
      accessToken
      refreshToken
      user {
        id
        email
        role
      }
    }
  }
`

export const REFRESH_TOKEN = gql`
  mutation RefreshToken($refreshToken: String!) {
    refreshToken(refreshToken: $refreshToken) {
      accessToken
      refreshToken
    }
  }
`

export const CHANGE_PASSWORD = gql`
  mutation ChangePassword($currentPassword: String!, $newPassword: String!) {
    changePassword(currentPassword: $currentPassword, newPassword: $newPassword)
  }
`

// Site queries
export const GET_SITES = gql`
  query GetSites($filter: SiteFilter, $pagination: PaginationInput) {
    sites(filter: $filter, pagination: $pagination) {
      id
      name
      location
      status
      endpointCount
      createdAt
      updatedAt
    }
  }
`

export const GET_SITE = gql`
  query GetSite($id: String!) {
    site(id: $id) {
      id
      name
      location
      status
      endpointCount
      createdAt
      updatedAt
    }
  }
`

export const GET_SITE_COUNT = gql`
  query GetSiteCount($filter: SiteFilter) {
    siteCount(filter: $filter)
  }
`

export const CREATE_SITE = gql`
  mutation CreateSite($input: CreateSiteInput!) {
    createSite(input: $input) {
      id
      name
      location
      status
    }
  }
`

export const UPDATE_SITE = gql`
  mutation UpdateSite($id: String!, $input: UpdateSiteInput!) {
    updateSite(id: $id, input: $input) {
      id
      name
      location
      status
    }
  }
`

export const DELETE_SITE = gql`
  mutation DeleteSite($id: String!) {
    deleteSite(id: $id)
  }
`

// Policy queries
export const GET_POLICIES = gql`
  query GetPolicies($filter: PolicyFilter, $pagination: PaginationInput) {
    policies(filter: $filter, pagination: $pagination) {
      id
      name
      description
      priority
      matchRules
      action
      enabled
      packetsMatched
      bytesMatched
      createdAt
    }
  }
`

export const GET_POLICY = gql`
  query GetPolicy($id: String!) {
    policy(id: $id) {
      id
      name
      description
      priority
      matchRules
      action
      enabled
      packetsMatched
      bytesMatched
      createdAt
    }
  }
`

export const CREATE_POLICY = gql`
  mutation CreatePolicy($input: CreatePolicyInput!) {
    createPolicy(input: $input) {
      id
      name
      description
      priority
      enabled
    }
  }
`

export const UPDATE_POLICY = gql`
  mutation UpdatePolicy($id: String!, $input: UpdatePolicyInput!) {
    updatePolicy(id: $id, input: $input) {
      id
      name
      priority
      enabled
    }
  }
`

export const DELETE_POLICY = gql`
  mutation DeletePolicy($id: String!) {
    deletePolicy(id: $id)
  }
`

export const TOGGLE_POLICY = gql`
  mutation TogglePolicy($id: String!, $enabled: Boolean!) {
    togglePolicy(id: $id, enabled: $enabled) {
      id
      enabled
    }
  }
`

// Path queries
export const GET_PATHS = gql`
  query GetPaths($sourceSiteId: String, $destinationSiteId: String, $pagination: PaginationInput) {
    paths(sourceSiteId: $sourceSiteId, destinationSiteId: $destinationSiteId, pagination: $pagination) {
      id
      sourceSiteId
      destinationSiteId
      latencyMs
      packetLoss
      bandwidthMbps
      qualityScore
      status
      lastUpdated
    }
  }
`

export const GET_PATH = gql`
  query GetPath($id: String!) {
    path(id: $id) {
      id
      sourceSiteId
      destinationSiteId
      latencyMs
      packetLoss
      bandwidthMbps
      qualityScore
      status
      lastUpdated
    }
  }
`

export const CHECK_PATH_HEALTH = gql`
  mutation CheckPathHealth($pathId: String!) {
    checkPathHealth(pathId: $pathId) {
      id
      status
      latencyMs
      packetLoss
      qualityScore
    }
  }
`

export const FAILOVER_PATH = gql`
  mutation FailoverPath($pathId: String!) {
    failoverPath(pathId: $pathId)
  }
`

// Metrics queries
export const GET_METRICS = gql`
  query GetMetrics {
    metrics {
      timestamp
      throughputMbps
      packetsPerSecond
      activeFlows
      avgLatencyMs
      avgPacketLoss
      cpuUsage
      memoryUsage
    }
  }
`

export const GET_METRICS_HISTORY = gql`
  query GetMetricsHistory($from: DateTime!, $to: DateTime!, $intervalSeconds: Int) {
    metricsHistory(from: $from, to: $to, intervalSeconds: $intervalSeconds) {
      timestamp
      throughputMbps
      packetsPerSecond
      activeFlows
      avgLatencyMs
      avgPacketLoss
      cpuUsage
      memoryUsage
    }
  }
`

// User queries
export const GET_USERS = gql`
  query GetUsers($pagination: PaginationInput) {
    users(pagination: $pagination) {
      id
      email
      role
      active
      createdAt
      lastLogin
    }
  }
`

export const GET_USER = gql`
  query GetUser($id: String!) {
    user(id: $id) {
      id
      email
      role
      active
      createdAt
      lastLogin
    }
  }
`

export const CREATE_USER = gql`
  mutation CreateUser($input: CreateUserInput!) {
    createUser(input: $input) {
      id
      email
      role
      active
    }
  }
`

export const UPDATE_USER = gql`
  mutation UpdateUser($id: String!, $input: UpdateUserInput!) {
    updateUser(id: $id, input: $input) {
      id
      email
      role
      active
    }
  }
`

export const UPDATE_USER_ROLE = gql`
  mutation UpdateUserRole($userId: String!, $role: UserRole!) {
    updateUserRole(userId: $userId, role: $role) {
      id
      role
    }
  }
`

export const DEACTIVATE_USER = gql`
  mutation DeactivateUser($userId: String!) {
    deactivateUser(userId: $userId) {
      id
      active
    }
  }
`

export const DELETE_USER = gql`
  mutation DeleteUser($id: String!) {
    deleteUser(id: $id)
  }
`

// Audit log queries
export const GET_AUDIT_LOGS = gql`
  query GetAuditLogs(
    $userId: String
    $eventType: String
    $severity: String
    $since: DateTime
    $until: DateTime
    $limit: Int
  ) {
    auditLogs(
      userId: $userId
      eventType: $eventType
      severity: $severity
      since: $since
      until: $until
      limit: $limit
    ) {
      id
      userId
      eventType
      description
      ipAddress
      timestamp
      metadata
    }
  }
`

export const GET_MUTATION_LOGS = gql`
  query GetMutationLogs($limit: Int) {
    mutationLogs(limit: $limit) {
      id
      userId
      eventType
      description
      ipAddress
      timestamp
      metadata
    }
  }
`

// System queries
export const GET_HEALTH = gql`
  query GetHealth {
    health {
      status
      version
      uptime
    }
  }
`

export const GET_VERSION = gql`
  query GetVersion {
    version {
      version
      buildDate
      gitCommit
    }
  }
`

export const CLEAR_CACHE = gql`
  mutation ClearCache {
    clearCache
  }
`

export const SYSTEM_HEALTH_CHECK = gql`
  mutation SystemHealthCheck {
    systemHealthCheck {
      status
      checks {
        name
        status
        message
      }
    }
  }
`

// Subscriptions
export const METRICS_SUBSCRIPTION = gql`
  subscription OnMetricsUpdate($intervalSeconds: Int) {
    metricsStream(intervalSeconds: $intervalSeconds) {
      timestamp
      throughputMbps
      packetsPerSecond
      activeFlows
      avgLatencyMs
      avgPacketLoss
      cpuUsage
      memoryUsage
    }
  }
`

export const SITE_STATUS_SUBSCRIPTION = gql`
  subscription OnSiteStatusChange {
    siteUpdates {
      id
      name
      status
    }
  }
`

export const PATH_UPDATES_SUBSCRIPTION = gql`
  subscription OnPathUpdates($siteId: String) {
    pathUpdates(siteId: $siteId) {
      id
      sourceSiteId
      destinationSiteId
      latencyMs
      packetLoss
      qualityScore
      status
    }
  }
`

export const POLICY_EVENTS_SUBSCRIPTION = gql`
  subscription OnPolicyEvents($policyId: String) {
    policyEvents(policyId: $policyId) {
      policyId
      matchCount
      timestamp
    }
  }
`

export const AUDIT_EVENTS_SUBSCRIPTION = gql`
  subscription OnAuditEvents {
    auditEvents {
      id
      userId
      eventType
      description
      timestamp
    }
  }
`

export const SYSTEM_ALERTS_SUBSCRIPTION = gql`
  subscription OnSystemAlerts($severity: AlertSeverity) {
    systemAlerts(severity: $severity) {
      id
      severity
      title
      message
      timestamp
    }
  }
`

// API Keys queries
export const GET_API_KEYS = gql`
  query GetApiKeys {
    apiKeys {
      id
      name
      prefix
      createdAt
      lastUsed
      expiresAt
      revoked
    }
  }
`

export const CREATE_API_KEY = gql`
  mutation CreateApiKey($input: CreateApiKeyInput!) {
    createApiKey(input: $input) {
      id
      name
      prefix
      key
      createdAt
      expiresAt
    }
  }
`

export const REVOKE_API_KEY = gql`
  mutation RevokeApiKey($id: String!) {
    revokeApiKey(id: $id) {
      id
      revoked
    }
  }
`

// System Info query
export const GET_SYSTEM_INFO = gql`
  query GetSystemInfo {
    systemInfo {
      version
      buildDate
      rustVersion
      uptime
      cpuUsage
      memoryUsage
      memoryTotal
      diskUsage
      diskTotal
      activeSessions
      totalSites
      totalPolicies
    }
  }
`

// User Profile Update
export const UPDATE_USER_PROFILE = gql`
  mutation UpdateUserProfile($input: UpdateProfileInput!) {
    updateProfile(input: $input) {
      id
      email
      displayName
    }
  }
`
