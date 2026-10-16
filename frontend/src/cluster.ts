// Data behind the Cluster view and the header leader badge: GET /ha/cluster
// returns the serving node's HA status plus every peer's /ha/status.

export interface HaStatus {
  node_id: string
  role: 'Leader' | 'Follower' | 'Candidate'
  term: number
  leader_id: string | null
  peers: string[]
  cluster_size: number
  log_index: number
  commit_index: number
  applied_index: number
}

export interface ClusterMember {
  addr: string
  reachable: boolean
  is_self: boolean
  status: HaStatus | null
}

export interface ClusterView {
  ha_enabled: boolean
  leader_id: string | null
  term: number
  members: ClusterMember[]
}

export async function fetchCluster(): Promise<ClusterView> {
  const res = await fetch('/ha/cluster')
  if (!res.ok) throw new Error(`/ha/cluster returned ${res.status}`)
  return (await res.json()) as ClusterView
}
