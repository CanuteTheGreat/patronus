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

// Site queries
export const GET_SITES = gql`
  query GetSites {
    sites {
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
  query GetPolicies {
    policies {
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

// Path queries
export const GET_PATHS = gql`
  query GetPaths {
    paths {
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
  query GetUsers {
    users {
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

// Subscriptions
export const METRICS_SUBSCRIPTION = gql`
  subscription OnMetricsUpdate {
    metricsUpdated {
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
    siteStatusChanged {
      id
      name
      status
    }
  }
`
