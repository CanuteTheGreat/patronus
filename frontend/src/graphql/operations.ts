// GraphQL documents, written against the dashboard's real schema
// (crates/patronus-dashboard/src/graphql/{queries,mutations,subscriptions}.rs).
// The previous UI queried fields that never existed (overview, recentAlerts,
// linkMetrics, slaPolicies, trafficStats, ...), so every page showed only
// "Unknown field" errors.
import { gql } from '@apollo/client'

export const DASHBOARD = gql`
  query Dashboard {
    health
    version
    siteCount
    sites { id name status }
    paths { id status qualityScore }
    policies { id enabled }
    metrics {
      timestamp throughputMbps packetsPerSecond activeFlows
      avgLatencyMs avgPacketLoss cpuUsage memoryUsage
    }
  }
`

export const METRICS_STREAM = gql`
  subscription MetricsStream {
    metricsStream(intervalSeconds: 5) {
      timestamp throughputMbps packetsPerSecond activeFlows
      avgLatencyMs avgPacketLoss cpuUsage memoryUsage
    }
  }
`

export const METRICS_HISTORY = gql`
  query MetricsHistory($from: DateTime!, $to: DateTime!) {
    metricsHistory(from: $from, to: $to) {
      timestamp throughputMbps packetsPerSecond activeFlows avgLatencyMs avgPacketLoss
    }
  }
`

export const SITES = gql`
  query Sites {
    sites { id name location endpointCount status createdAt updatedAt }
  }
`

export const CREATE_SITE = gql`
  mutation CreateSite($input: CreateSiteInput!) {
    createSite(input: $input) { id name location status }
  }
`

export const UPDATE_SITE = gql`
  mutation UpdateSite($input: UpdateSiteInput!) {
    updateSite(input: $input) { id name location status }
  }
`

export const DELETE_SITE = gql`
  mutation DeleteSite($id: String!) {
    deleteSite(id: $id)
  }
`

export const PATHS = gql`
  query Paths {
    sites { id name }
    paths {
      id sourceSiteId destinationSiteId latencyMs packetLoss
      bandwidthMbps qualityScore status lastUpdated
    }
  }
`

export const CHECK_PATH = gql`
  mutation CheckPathHealth($pathId: String!) {
    checkPathHealth(pathId: $pathId) { id status latencyMs packetLoss qualityScore lastUpdated }
  }
`

export const FAILOVER_PATH = gql`
  mutation FailoverPath($pathId: String!) {
    failoverPath(pathId: $pathId)
  }
`

export const POLICIES = gql`
  query Policies {
    policies {
      id name description priority matchRules action enabled
      packetsMatched bytesMatched createdAt
    }
  }
`

export const CREATE_POLICY = gql`
  mutation CreatePolicy($input: CreatePolicyInput!) {
    createPolicy(input: $input) { id name enabled }
  }
`

export const TOGGLE_POLICY = gql`
  mutation TogglePolicy($id: String!, $enabled: Boolean!) {
    togglePolicy(id: $id, enabled: $enabled) { id enabled }
  }
`

export const DELETE_POLICY = gql`
  mutation DeletePolicy($id: String!) {
    deletePolicy(id: $id)
  }
`

export const AUDIT_LOGS = gql`
  query AuditLogs($limit: Int) {
    auditLogs(limit: $limit) { id userId eventType description ipAddress timestamp metadata }
  }
`

export const USERS = gql`
  query Users {
    users { id email role active createdAt lastLogin }
  }
`

export const CREATE_USER = gql`
  mutation CreateUser($input: CreateUserInput!) {
    createUser(input: $input) { id email role active }
  }
`
