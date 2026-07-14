import { createContext, useContext, useEffect, useRef, useState, useCallback } from 'react'
import { getJSON, postJSON, humanBytes, uptime, ago } from './api.js'

// Lets any panel open the per-host DNS drill-down without prop drilling.
const HostContext = createContext(() => {})
const useOpenHost = () => useContext(HostContext)

// A hostname/IP rendered as a button that opens its DNS detail modal.
function HostLink({ ip, name, children }) {
  const open = useOpenHost()
  if (!ip) return <>{children ?? name}</>
  return (
    <button className="host-link" title="DNS activity for this host"
      onClick={() => open({ ip, name: name || ip })}>
      {children ?? name}
    </button>
  )
}

function Login({ onSuccess, noPassword }) {
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    const res = await postJSON('/api/login', { password })
    setBusy(false)
    if (res.ok) onSuccess()
    else setError('Incorrect password')
  }

  return (
    <div className="login-wrap">
      <form className="login" onSubmit={submit}>
        <div className="brand center">
          <span className="logo" />
          <h1>Bardcastle Firewall</h1>
        </div>
        {noPassword ? (
          <p className="msg">
            No password is set yet. On the firewall run:
            <code>sudo bardcastle-fw webui set-password</code>
          </p>
        ) : (
          <>
            <input
              type="password"
              placeholder="Password"
              value={password}
              autoFocus
              onChange={(e) => setPassword(e.target.value)}
            />
            {error && <div className="msg err">{error}</div>}
            <button disabled={busy || !password}>{busy ? '...' : 'Sign in'}</button>
          </>
        )}
      </form>
    </div>
  )
}

// Poll an endpoint on an interval; expose data, error, and loading state.
function usePoll(path, intervalMs = 8000) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(() => {
    getJSON(path)
      .then((d) => { setData(d); setError(null) })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [path])

  useEffect(() => {
    refresh()
    const id = setInterval(refresh, intervalMs)
    return () => clearInterval(id)
  }, [refresh, intervalMs])

  return { data, error, loading }
}

function Panel({ title, error, loading, wide, children }) {
  return (
    <section className={wide ? 'panel wide' : 'panel'}>
      <h2>{title}</h2>
      {error ? (
        <div className="msg err">unavailable: {error}</div>
      ) : loading ? (
        <div className="msg">loading...</div>
      ) : (
        children
      )}
    </section>
  )
}

function SystemPanel() {
  const { data, error, loading } = usePoll('/api/status')
  const r = data?.resources || {}
  return (
    <Panel title="System" error={error} loading={loading}>
      <div className="kv">
        <span>Memory</span>
        <span>{r.mem_used_mb} / {r.mem_total_mb} MB ({r.mem_pct}%)</span>
        <span>Load</span>
        <span>{(r.load || []).join('  ')}</span>
        <span>Uptime</span>
        <span>{uptime(r.uptime_sec)}</span>
      </div>
      <div className="tscroll">
        <table>
          <thead><tr><th>Interface</th><th>State</th><th>Address</th></tr></thead>
          <tbody>
            {(data?.interfaces || []).map((i) => (
              <tr key={i.name}>
                <td>{i.name}</td>
                <td><span className={i.state === 'UP' ? 'dot up' : 'dot down'} />{i.state}</td>
                <td className="mono">{i.addresses.join(', ') || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  )
}

function FirewallPanel() {
  const { data, error, loading } = usePoll('/api/firewall')
  return (
    <Panel title="Firewall" error={error} loading={loading}>
      <div className="kv">
        <span>Blocklist</span>
        <span>{data?.blocklist_v4?.toLocaleString()} IPv4 / {data?.blocklist_v6} IPv6</span>
      </div>
      <div className="tscroll">
        <table>
          <thead><tr><th>Rule</th><th>Chain</th><th className="num">Packets</th><th className="num">Bytes</th></tr></thead>
          <tbody>
            {(data?.counters || []).map((c, idx) => (
              <tr key={idx}>
                <td>{c.label}</td>
                <td className="mono">{c.chain}</td>
                <td className="num">{c.packets.toLocaleString()}</td>
                <td className="num">{humanBytes(c.bytes)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  )
}

function LeasesPanel() {
  const { data, error, loading } = usePoll('/api/leases')
  const leases = data?.leases || []
  return (
    <Panel title={`DHCP Leases (${leases.length})`} error={error} loading={loading}>
      <div className="tscroll">
        <table>
          <thead><tr><th>Hostname</th><th>IP</th><th>MAC</th></tr></thead>
          <tbody>
            {leases.map((l) => (
              <tr key={l.mac}>
                <td>
                  <HostLink ip={l.ip} name={l.hostname || l.ip}>
                    {l.hostname || <span className="muted">(none)</span>}
                  </HostLink>
                </td>
                <td className="mono"><HostLink ip={l.ip} name={l.hostname || l.ip}>{l.ip}</HostLink></td>
                <td className="mono muted">{l.mac}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  )
}

function VpnPanel() {
  const { data, error, loading } = usePoll('/api/vpn')
  const clients = data?.clients || []
  return (
    <Panel title="VPN" error={error} loading={loading}>
      <div className="kv">
        <span>Online now</span>
        <span>{data?.active_peers} / {data?.total_peers} connected</span>
      </div>
      <div className="tscroll">
        <table>
          <thead><tr><th>Client</th><th>VPN IP</th><th>Last seen</th><th className="num">Transfer</th></tr></thead>
          <tbody>
            {clients.map((c) => (
              <tr key={c.ip}>
                <td>
                  <span className={c.online ? 'dot up' : 'dot down'} />
                  <HostLink ip={c.ip} name={c.name}>{c.name}</HostLink>
                </td>
                <td className="mono">{c.ip}</td>
                <td className="muted">{c.online ? 'online' : ago(c.handshake)}</td>
                <td className="num mono muted">
                  {c.handshake ? `${humanBytes(c.rx)} / ${humanBytes(c.tx)}` : '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  )
}

function BandwidthPanel() {
  const { data, error, loading } = usePoll('/api/bandwidth', 30000)
  const days = data?.days || []
  const max = Math.max(1, ...days.map((d) => d.rx + d.tx))
  const H = 90
  return (
    <Panel title="WAN Bandwidth (daily)" error={error} loading={loading} wide>
      {data?.available === false ? (
        <div className="msg muted">vnstat not available yet (collecting data)</div>
      ) : (
        <>
          <div className="kv">
            <span>Interface</span>
            <span className="mono">{data?.interface || '-'}</span>
          </div>
          <div className="bars" style={{ height: H + 22 }}>
            {days.map((d) => {
              const rxH = Math.round((d.rx / max) * H)
              const txH = Math.round((d.tx / max) * H)
              return (
                <div className="bar-col" key={d.date} title={`${d.date}\n down ${humanBytes(d.rx)} / up ${humanBytes(d.tx)}`}>
                  <div className="bar-stack" style={{ height: H }}>
                    <div className="bar rx" style={{ height: rxH }} />
                    <div className="bar tx" style={{ height: txH }} />
                  </div>
                  <span className="bar-label">{d.date.slice(5)}</span>
                </div>
              )
            })}
            {days.length === 0 && <div className="msg muted">no data yet</div>}
          </div>
          <div className="legend">
            <span><span className="swatch rx" /> download</span>
            <span><span className="swatch tx" /> upload</span>
          </div>
        </>
      )}
    </Panel>
  )
}

function DnsPanel() {
  const { data, error, loading } = usePoll('/api/dns', 15000)
  if (data?.available === false) {
    return (
      <Panel title="DNS Activity" error={error} loading={loading} wide>
        <div className="msg muted">query logging is off or the journal is unreadable</div>
      </Panel>
    )
  }
  const domains = data?.top_domains || []
  const clients = data?.top_clients || []
  return (
    <Panel title="DNS Activity (last 2h)" error={error} loading={loading} wide>
      <div className="two-col">
        <div>
          <h3>Top domains</h3>
          <table>
            <tbody>
              {domains.map((d) => (
                <tr key={d.name}><td className="mono ellipsis">{d.name}</td><td className="num">{d.count}</td></tr>
              ))}
              {domains.length === 0 && <tr><td className="muted">no queries</td></tr>}
            </tbody>
          </table>
        </div>
        <div>
          <h3>Top clients</h3>
          <table>
            <tbody>
              {clients.map((c) => (
                <tr key={c.ip}>
                  <td className="ellipsis"><HostLink ip={c.ip} name={c.name}>{c.name}</HostLink></td>
                  <td className="num">{c.count}</td>
                </tr>
              ))}
              {clients.length === 0 && <tr><td className="muted">no queries</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </Panel>
  )
}

function IdsPanel() {
  const { data, error, loading } = usePoll('/api/ids', 15000)
  if (data?.available === false) {
    return (
      <Panel title="Attacks / IDS" error={error} loading={loading} wide>
        <div className="msg muted">CrowdSec is not installed or not reachable</div>
      </Panel>
    )
  }
  const decisions = data?.decisions || []
  const alerts = data?.alerts || []
  const clean = decisions.length === 0 && alerts.length === 0
  return (
    <Panel title={`Attacks / IDS${data?.active_bans ? ` (${data.active_bans} active bans)` : ''}`} error={error} loading={loading} wide>
      {clean ? (
        <div className="msg ok">No attacks detected. No active bans.</div>
      ) : (
        <>
          {decisions.length > 0 && (
            <>
              <h3>Currently banned</h3>
              <div className="tscroll">
                <table>
                  <thead><tr><th>Source IP</th><th>Country</th><th>Reason</th><th>Expires</th></tr></thead>
                  <tbody>
                    {decisions.map((d, i) => (
                      <tr key={i}>
                        <td className="mono">{d.ip}</td>
                        <td>{d.country || '-'}</td>
                        <td className="ellipsis">{(d.scenario || '').split('/').pop()}</td>
                        <td className="muted">{d.expires}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
          {alerts.length > 0 && (
            <>
              <h3>Recent alerts</h3>
              <div className="tscroll">
                <table>
                  <thead><tr><th>Source IP</th><th>Country</th><th>Scenario</th><th className="num">Events</th><th>When</th></tr></thead>
                  <tbody>
                    {alerts.map((a) => (
                      <tr key={a.id}>
                        <td className="mono">{a.ip}</td>
                        <td>{a.country || '-'}</td>
                        <td className="ellipsis">{(a.scenario || '').split('/').pop()}</td>
                        <td className="num">{a.events}</td>
                        <td className="muted mono">{a.when}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </>
      )}
    </Panel>
  )
}

const EVENT_LABEL = {
  new_device: 'New device', blocked_ip: 'Blocked IP', vpn_connect: 'VPN connect',
  vpn_disconnect: 'VPN disconnect', ids_alert: 'IDS alert', dhcp_lease: 'DHCP lease',
  service_restart: 'Service restart', config_change: 'Config change',
  blocklist_update: 'Blocklist update', login_attempt: 'Login attempt',
}

const DHCP_ACTION = { add: 'New lease', old: 'Lease renewed', del: 'Lease released' }

// Turn a structured event into one readable sentence. Falls back to a compact
// key: value rendering (never raw JSON) for shapes we do not special-case.
function describeEvent(type, data) {
  const d = data || {}
  const host = d.hostname || d.client_name || d.mac
  const at = d.ip || d.client_ip
  const where = host && at ? `${host} (${at})` : (host || at || '')
  switch (type) {
    case 'dhcp_lease':
      return `${DHCP_ACTION[d.action] || 'Lease'}: ${where || d.mac || 'unknown device'}`
    case 'new_device':
      return `New device joined: ${where || 'unknown'}`
    case 'vpn_connect':
      return `VPN connected: ${where || 'client'}`
    case 'vpn_disconnect':
      return `VPN disconnected: ${where || 'client'}`
    case 'blocked_ip':
      return `Blocked ${d.ip || 'IP'}${d.reason ? ` (${d.reason})` : ''}`
    case 'ids_alert':
      return `IDS alert${d.scenario ? `: ${String(d.scenario).split('/').pop()}` : ''}` +
        `${d.source || d.ip ? ` from ${d.source || d.ip}` : ''}`
    case 'blocklist_update':
      return `Blocklist updated${d.count != null ? `: ${Number(d.count).toLocaleString()} entries` : ''}` +
        `${d.source ? ` (${d.source})` : ''}`
    case 'service_restart':
      return `Service restarted${d.service ? `: ${d.service}` : ''}`
    case 'login_attempt':
      return `Login ${d.success ? 'succeeded' : 'failed'}${d.user ? ` for ${d.user}` : ''}` +
        `${d.ip ? ` from ${d.ip}` : ''}`
    case 'config_change': {
      const mod = d.module || 'system'
      if (d.module === 'vpn' && d.action === 'set_admin')
        return `VPN client ${d.client} ${d.admin ? 'granted' : 'revoked'} dashboard access`
      if (d.action === 'apply') return `${mod} configuration applied`
      return `${mod} configuration changed${d.action ? ` (${d.action})` : ''}`
    }
    default: {
      const parts = Object.entries(d).map(([k, v]) => `${k}: ${v}`)
      return parts.join(', ') || '(no details)'
    }
  }
}

function EventRow({ e }) {
  return (
    <div className="event">
      <span className={`tag t-${e.type}`}>{EVENT_LABEL[e.type] || e.type}</span>
      <span className="etime mono muted">{(e.timestamp || '').slice(0, 19).replace('T', ' ')}</span>
      <span className="edata" title={JSON.stringify(e.data)}>{describeEvent(e.type, e.data)}</span>
    </div>
  )
}

// Live event feed: fetch the recent backlog once, then stream new events over
// SSE (falls back to nothing extra if the stream drops; the browser retries).
function EventsPanel() {
  const [events, setEvents] = useState([])
  const [error, setError] = useState(null)
  const [live, setLive] = useState(false)
  const [loading, setLoading] = useState(true)
  const seen = useRef(new Set())

  const add = useCallback((e) => {
    const key = `${e.timestamp}|${e.type}|${JSON.stringify(e.data)}`
    if (seen.current.has(key)) return
    seen.current.add(key)
    setEvents((prev) => [e, ...prev].slice(0, 100))
  }, [])

  useEffect(() => {
    let es
    getJSON('/api/events?limit=40')
      .then((d) => { (d.events || []).slice().reverse().forEach(add) })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))

    es = new EventSource('/api/events/stream')
    es.onopen = () => setLive(true)
    es.onmessage = (ev) => {
      try { add(JSON.parse(ev.data)) } catch { /* ignore malformed */ }
    }
    es.onerror = () => setLive(false) // browser auto-reconnects
    return () => es && es.close()
  }, [add])

  return (
    <Panel title={<>Live Events <span className={live ? 'dot up' : 'dot down'} title={live ? 'streaming' : 'reconnecting'} /></>} error={error} loading={loading} wide>
      <div className="feed">
        {events.map((e, idx) => <EventRow e={e} key={idx} />)}
        {events.length === 0 && <div className="msg muted">no events yet</div>}
      </div>
    </Panel>
  )
}

// Per-host DNS drill-down. Fetched once on open (with a manual refresh);
// closes on backdrop click or Escape.
function HostModal({ host, onClose }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    setLoading(true)
    getJSON(`/api/dns/host?ip=${encodeURIComponent(host.ip)}`)
      .then((d) => { setData(d); setError(null) })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [host.ip])

  useEffect(() => { load() }, [load])
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const domains = data?.top_domains || []
  const types = data?.types || []
  const recent = data?.recent || []

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <header className="modal-head">
          <div>
            <h2>{host.name}</h2>
            <span className="mono muted">{host.ip}</span>
          </div>
          <div className="modal-actions">
            <button className="ghost" onClick={load} title="Refresh">Refresh</button>
            <button className="ghost" onClick={onClose} title="Close">Close</button>
          </div>
        </header>

        {error ? (
          <div className="msg err">unavailable: {error}</div>
        ) : loading && !data ? (
          <div className="msg">loading...</div>
        ) : data?.available === false ? (
          <div className="msg muted">no query log available (logging off or unreadable)</div>
        ) : data?.total === 0 ? (
          <div className="msg muted">no DNS queries from this host in the last 6h</div>
        ) : (
          <>
            <div className="kv">
              <span>Total queries (6h)</span>
              <span>{data?.total?.toLocaleString()}</span>
              <span>Query types</span>
              <span className="chips">
                {types.map((t) => (
                  <span className="chip" key={t.name}>{t.name} {t.count}</span>
                ))}
              </span>
            </div>
            <div className="two-col">
              <div>
                <h3>Top domains</h3>
                <div className="tscroll">
                  <table>
                    <tbody>
                      {domains.map((d) => (
                        <tr key={d.name}>
                          <td className="mono ellipsis">{d.name}</td>
                          <td className="num">{d.count}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
              <div>
                <h3>Recent queries</h3>
                <div className="feed">
                  {recent.map((q, i) => (
                    <div className="event" key={i}>
                      <span className="etime mono muted">{q.time}</span>
                      <span className="tag">{q.type}</span>
                      <span className="edata mono">{q.name}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

export default function App() {
  const [now, setNow] = useState(new Date())
  const [auth, setAuth] = useState(null) // null=loading, {authenticated, password_set}
  const [host, setHost] = useState(null) // selected host for the DNS modal

  const checkAuth = useCallback(() => {
    getJSON('/api/authstate').then(setAuth).catch(() => setAuth({ authenticated: false }))
  }, [])

  useEffect(() => { checkAuth() }, [checkAuth])
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])

  async function logout() {
    await postJSON('/api/logout', {})
    setAuth({ authenticated: false, password_set: true })
  }

  if (auth === null) return <div className="login-wrap"><div className="msg">loading...</div></div>
  if (!auth.authenticated) {
    return <Login onSuccess={checkAuth} noPassword={auth.password_set === false} />
  }

  return (
    <HostContext.Provider value={setHost}>
      <div className="app">
        <header>
          <div className="brand">
            <span className="logo" />
            <h1>Bardcastle Firewall</h1>
          </div>
          <div className="header-right">
            <span className="clock mono">{now.toLocaleTimeString()}</span>
            <button className="logout" onClick={logout}>Sign out</button>
          </div>
        </header>
        <main>
          <BandwidthPanel />
          <IdsPanel />
          <SystemPanel />
          <FirewallPanel />
          <VpnPanel />
          <DnsPanel />
          <LeasesPanel />
          <EventsPanel />
        </main>
        <footer>
          Read-only dashboard (phase 1). Management stays in the CLI.
        </footer>
      </div>
      {host && <HostModal host={host} onClose={() => setHost(null)} />}
    </HostContext.Provider>
  )
}
