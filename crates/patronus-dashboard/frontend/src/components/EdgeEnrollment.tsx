import { useCallback, useEffect, useState } from 'react'
import toast from 'react-hot-toast'

interface EdgeRow {
  site_id: string
  name: string
  status: string
  overlay_ip: string
  subnets: string[]
  last_heartbeat: number
}

function authHeaders(): Record<string, string> {
  const token = localStorage.getItem('access_token')
  return token
    ? { Authorization: `Bearer ${token}`, 'content-type': 'application/json' }
    : { 'content-type': 'application/json' }
}

/**
 * Patronus appliances join the overlay by themselves (SD-WAN edge agent):
 * this card creates their one-time enrollment tokens and lists the enrolled
 * edges (REST: /api/v1/edge/tokens, /edge/edges).
 */
export default function EdgeEnrollment() {
  const [edges, setEdges] = useState<EdgeRow[]>([])
  const [label, setLabel] = useState('')
  const [token, setToken] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    const r = await fetch('/api/v1/edge/edges', { headers: authHeaders() })
    if (r.ok) setEdges(await r.json())
  }, [])

  useEffect(() => {
    load()
    const t = setInterval(load, 15000)
    return () => clearInterval(t)
  }, [load])

  const createToken = async () => {
    setBusy(true)
    try {
      const r = await fetch('/api/v1/edge/tokens', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ label }),
      })
      const j = await r.json()
      if (!r.ok) {
        toast.error(j.error || 'Could not create a token')
        return
      }
      setToken(j.token)
      setLabel('')
    } finally {
      setBusy(false)
    }
  }

  const revoke = async (e: EdgeRow) => {
    if (!window.confirm(`Revoke ${e.name}? Its tunnels are removed from the other sites.`)) return
    const r = await fetch(`/api/v1/edge/edges/${e.site_id}`, {
      method: 'DELETE',
      headers: authHeaders(),
    })
    if (r.ok) {
      toast.success(`${e.name} revoked`)
      load()
    } else {
      toast.error((await r.json()).error || 'Could not revoke')
    }
  }

  return (
    <div className="card" data-testid="edge-enrollment">
      <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
        Patronus edges
      </h2>
      <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
        A Patronus firewall joins the overlay with the SD-WAN edge agent: create a
        one-time token here and paste it, with this dashboard's address, on the
        firewall's SD-WAN edge page.
      </p>
      <div className="mt-4 flex flex-col md:flex-row gap-2">
        <input
          className="input flex-1"
          placeholder="Label (for example the site name)"
          value={label}
          maxLength={64}
          onChange={(e) => setLabel(e.target.value)}
          aria-label="Token label"
        />
        <button className="btn btn-primary" onClick={createToken} disabled={busy}>
          Create enrollment token
        </button>
      </div>
      {token && (
        <div className="mt-3 p-3 rounded bg-yellow-50 dark:bg-yellow-900/20 text-sm">
          <div>Shown once. Use it within the edge's enrollment form:</div>
          <code className="block mt-1 break-all" data-testid="edge-token">
            {token}
          </code>
        </div>
      )}
      {edges.length > 0 && (
        <table className="mt-4 w-full text-sm">
          <thead>
            <tr className="text-left text-gray-500">
              <th className="py-1">Edge</th>
              <th>Status</th>
              <th>Overlay address</th>
              <th>Subnets</th>
              <th>Last heard</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {edges.map((e) => (
              <tr key={e.site_id} className="border-t border-gray-200 dark:border-gray-700">
                <td className="py-1">{e.name}</td>
                <td>{e.status}</td>
                <td>{e.overlay_ip}</td>
                <td>{e.subnets.join(', ') || '-'}</td>
                <td>
                  {e.last_heartbeat
                    ? new Date(e.last_heartbeat * 1000).toLocaleTimeString()
                    : '-'}
                </td>
                <td className="text-right">
                  <button className="text-red-600 hover:underline" onClick={() => revoke(e)}>
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
