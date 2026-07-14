// Small fetch helper. Endpoints are same-origin (the SPA is served by the
// FastAPI process), so relative paths work in production. In dev, vite proxies
// /api to the backend.

export async function getJSON(path) {
  const res = await fetch(path, { headers: { Accept: 'application/json' } })
  if (res.status === 401) throw new Error('unauthorized')
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`)
  return res.json()
}

export async function postJSON(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  })
  return res
}

export function humanBytes(n) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let v = Number(n) || 0
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return i === 0 ? `${v} B` : `${v.toFixed(1)} ${units[i]}`
}

export function ago(unixSeconds) {
  if (!unixSeconds) return 'never'
  const d = Math.max(0, Math.floor(Date.now() / 1000) - unixSeconds)
  if (d < 60) return `${d}s ago`
  if (d < 3600) return `${Math.floor(d / 60)}m ago`
  if (d < 86400) return `${Math.floor(d / 3600)}h ago`
  return `${Math.floor(d / 86400)}d ago`
}

export function uptime(sec) {
  if (!sec) return '-'
  const d = Math.floor(sec / 86400)
  const h = Math.floor((sec % 86400) / 3600)
  const m = Math.floor((sec % 3600) / 60)
  return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : `${m}m`
}
