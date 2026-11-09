"""Mocked dashboard APIs shared by the render proofs (sites, GraphQL, HA cluster)."""
now = '2026-10-30T12:00:00Z'
sites = [dict(id=str(i), name=n, location=l, status=st, endpointCount=c, createdAt=now, updatedAt=now, __typename='Site') for i, (n, l, st, c) in enumerate([
    ('HQ Chicago', 'Chicago, US', 'active', 24), ('Branch Denver', 'Denver, US', 'degraded', 8), ('Branch Berlin', 'Berlin, DE', 'inactive', 3)])]
def gql(body):
    q = body.get('query', '')
    d = {}
    if 'overview' in q:
        d['overview'] = dict(totalSites=3, activeSites=2, totalLinks=4, healthyLinks=3, avgLatency=23.4, totalThroughput=420000000, packetLoss=0.004)
        d['recentAlerts'] = [dict(id='a1', severity='critical', message='Link Berlin-HQ down', timestamp=now, siteId='2'),
                             dict(id='a2', severity='warning', message='Latency above SLA on Denver', timestamp=now, siteId='1'),
                             dict(id='a3', severity='info', message='Policy updated', timestamp=now, siteId='0')]
        d['linkMetrics'] = [dict(timestamp=f'2026-10-30T12:{m:02d}:00Z', throughput=300e6+m*3e6, latency=20+m%7, packetLoss=0.001*(m%4)) for m in range(0, 40, 4)]
    if 'sites {' in q or 'sites{' in q:
        d['sites'] = [dict(x, status=x['status'].upper()) for x in sites] if 'endpointCount' in q else sites
    if 'links {' in q:
        d['links'] = [dict(id='l1', sourceId='0', targetId='1', status='degraded', latency=40, bandwidth=100, utilization=.7),
                      dict(id='l2', sourceId='0', targetId='2', status='down', latency=0, bandwidth=100, utilization=0)]
    if 'slaPolicies' in q:
        d['slaPolicies'] = [dict(id='s1', name='Voice', description='Realtime voice', targetLatency=50, targetPacketLoss=.01, targetAvailability=99.9, currentLatency=42, currentPacketLoss=.004, currentAvailability=99.95, compliance=98.2, violations=1),
                            dict(id='s2', name='Video', description='Conferencing', targetLatency=80, targetPacketLoss=.02, targetAvailability=99.5, currentLatency=120, currentPacketLoss=.03, currentAvailability=98.1, compliance=71.0, violations=14)]
    if 'trafficStats' in q:
        d['trafficStats'] = [dict(siteId='0', siteName='HQ Chicago', totalBytes=5e10, totalPackets=4e7, applications=[dict(name='HTTPS', bytes=3e10, packets=2e7, percentage=60), dict(name='VoIP', bytes=1e10, packets=1e7, percentage=20)])]
    if 'securityEvents' in q:
        d['securityEvents'] = [dict(id='e1', timestamp=now, severity='high', type='intrusion', source='203.0.113.9', destination='10.0.0.5', description='Port scan', blocked=True),
                               dict(id='e2', timestamp=now, severity='medium', type='malware', source='198.51.100.2', destination='10.0.0.9', description='Suspicious download', blocked=False)]
        d['threatStats'] = dict(total=120, blocked=100, allowed=20, byType=[dict(type='intrusion', count=70), dict(type='malware', count=50)])
    return dict(data=d)
CLUSTER = dict(ha_enabled=True, leader_id='n1', term=4, members=[
    dict(addr='10.0.0.1:8080', reachable=True, is_self=True, status=dict(node_id='n1', role='Leader', term=4, leader_id='n1', peers=['n2', 'n3'], cluster_size=3, log_index=120, commit_index=120, applied_index=120)),
    dict(addr='10.0.0.2:8080', reachable=True, is_self=False, status=dict(node_id='n2', role='Follower', term=4, leader_id='n1', peers=['n1', 'n3'], cluster_size=3, log_index=120, commit_index=120, applied_index=119)),
    dict(addr='10.0.0.3:8080', reachable=False, is_self=False, status=None)])
