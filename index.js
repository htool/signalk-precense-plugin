const { execFile } = require('child_process')
const { promisify } = require('util')
const os = require('os')

const execFileAsync = promisify(execFile)
const PLUGIN_ID = 'signalk-precense-plugin'
const PATH_PREFIX = 'sensors.presence'

module.exports = function (app) {
  const plugin = {}
  plugin.id = PLUGIN_ID
  plugin.name = 'LAN Presence'
  plugin.description =
    'Detects devices on the boat LAN (ping + ARP/neigh). Publishes sensors.presence.<id> as boolean, plus lastSeen and ip.'

  let timer = null
  let discoverTimer = null
  let statusTimer = null
  const state = new Map()
  const discovered = new Map()

  plugin.schema = () => ({
    type: 'object',
    properties: {
      pingIntervalSeconds: {
        type: 'number',
        title: 'Ping interval (seconds)',
        description: 'How often to check tracked devices',
        default: 30,
        minimum: 5
      },
      missBeforeAbsent: {
        type: 'number',
        title: 'Misses before absent',
        description: 'Consecutive failures before absent (phones often ignore ICMP asleep)',
        default: 4,
        minimum: 1
      },
      discoverIntervalSeconds: {
        type: 'number',
        title: 'Discovery refresh (seconds)',
        default: 60,
        minimum: 15
      },
      networks: {
        type: 'array',
        title: 'Networks to scan (CIDR)',
        description: 'Empty = local interface subnets',
        items: { type: 'string' },
        default: []
      },
      devices: {
        type: 'array',
        title: 'Tracked devices',
        description: 'Name becomes path slug under sensors.presence',
        items: {
          type: 'object',
          properties: {
            enabled: { type: 'boolean', title: 'Track', default: true },
            name: { type: 'string', title: 'Name (path slug)' },
            ip: { type: 'string', title: 'IP address' },
            mac: { type: 'string', title: 'MAC (optional)' }
          }
        },
        default: []
      }
    }
  })

  plugin.uiSchema = () => ({
    devices: { items: { enabled: { 'ui:widget': 'checkbox' } } }
  })

  function slugify (name) {
    return String(name || '')
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'device'
  }

  function localCidrs () {
    const out = []
    const ifaces = os.networkInterfaces()
    for (const [name, addrs] of Object.entries(ifaces)) {
      if (!addrs) continue
      if (
        name === 'lo' ||
        name.startsWith('docker') ||
        name.startsWith('br-') ||
        name.startsWith('veth') ||
        name.startsWith('tailscale') ||
        name === 'tun0'
      ) continue
      for (const a of addrs) {
        if (a.family !== 'IPv4' || a.internal) continue
        const parts = a.address.split('.').map(Number)
        const mask = (a.netmask || '255.255.255.0').split('.').map(Number)
        const net = parts.map((p, i) => p & mask[i]).join('.')
        let prefix = 24
        if (a.netmask === '255.255.0.0') prefix = 16
        else if (a.netmask === '255.255.255.128') prefix = 25
        out.push(net + '/' + prefix)
      }
    }
    return out
  }

  async function run (cmd, args, timeoutMs) {
    timeoutMs = timeoutMs || 8000
    try {
      const r = await execFileAsync(cmd, args, { timeout: timeoutMs, maxBuffer: 2 * 1024 * 1024 })
      return r.stdout || ''
    } catch (e) {
      return (e && e.stdout) || ''
    }
  }

  async function pingOnce (ip) {
    const out = await run('ping', ['-c', '1', '-W', '1', ip], 3000)
    return /1 received|1 packets received|bytes from/i.test(out)
  }

  async function readNeigh () {
    const map = new Map()
    let text = await run('ip', ['neigh', 'show'])
    if (!text.trim()) {
      text = await run('cat', ['/proc/net/arp'])
      for (const line of text.split('\n').slice(1)) {
        const p = line.trim().split(/\s+/)
        if (p.length < 4) continue
        const ip = p[0]
        const mac = (p[3] || '').toLowerCase()
        if (!mac || mac === '00:00:00:00:00:00') continue
        map.set(ip, { ip: ip, mac: mac, state: 'REACHABLE' })
      }
      return map
    }
    for (const line of text.split('\n')) {
      const m = line.match(/^(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+(?:\s+lladdr\s+([0-9a-f:]+))?\s+(\S+)/i)
      if (!m) continue
      const ip = m[1]
      const mac = (m[2] || '').toLowerCase()
      const st = (m[3] || '').toUpperCase()
      if (!mac) continue
      if (st === 'FAILED' || st === 'INCOMPLETE') continue
      map.set(ip, { ip: ip, mac: mac, state: st })
    }
    return map
  }

  async function tryResolveHostname (ip) {
    try {
      const r = await execFileAsync('getent', ['hosts', ip], { timeout: 2000 })
      const parts = String(r.stdout || '').trim().split(/\s+/)
      return parts[1] || ''
    } catch (_) {
      return ''
    }
  }

  async function refreshDiscovery (options) {
    const cidrs = ((options.networks && options.networks.length) ? options.networks : localCidrs()).filter(Boolean)
    const neigh = await readNeigh()
    const now = Date.now()
    for (const entry of neigh.values()) {
      const hostname = await tryResolveHostname(entry.ip)
      const prev = discovered.get(entry.ip) || {}
      discovered.set(entry.ip, {
        ip: entry.ip,
        mac: entry.mac,
        hostname: hostname || prev.hostname || '',
        lastSeen: now
      })
    }
    for (const cidr of cidrs.slice(0, 4)) {
      const base = cidr.split('/')[0]
      const parts = base.split('.')
      if (parts.length === 4) {
        await pingOnce(parts[0] + '.' + parts[1] + '.' + parts[2] + '.254')
      }
    }
    const tracked = (options.devices || []).filter(function (d) { return d && d.enabled !== false }).length
    app.setPluginStatus('Discovery: ' + discovered.size + ' in ARP/neigh; tracking ' + tracked)
  }

  function devicePresentFromNeigh (device, neigh) {
    if (device.ip && neigh.has(device.ip)) return true
    if (device.mac) {
      const want = String(device.mac).toLowerCase()
      for (const n of neigh.values()) {
        if (n.mac === want) return true
      }
    }
    return false
  }

  function publishDevice (id, present, ip, lastSeenMs) {
    const base = PATH_PREFIX + '.' + id
    app.handleMessage(PLUGIN_ID, {
      updates: [{
        source: { label: PLUGIN_ID },
        timestamp: new Date().toISOString(),
        values: [
          { path: base, value: !!present, meta: { description: 'LAN presence for ' + id, displayName: id } },
          { path: base + '.lastSeen', value: lastSeenMs ? new Date(lastSeenMs).toISOString() : null },
          { path: base + '.ip', value: ip || null }
        ]
      }]
    })
  }

  async function checkTracked (options) {
    const devices = (options.devices || []).filter(function (d) {
      return d && d.enabled !== false && d.name && d.ip
    })
    const neigh = await readNeigh()
    const missNeed = Math.max(1, Number(options.missBeforeAbsent) || 4)

    for (const d of devices) {
      const id = slugify(d.name)
      let st = state.get(id)
      if (!st) {
        st = { present: false, lastSeen: null, ip: d.ip, missStreak: 0 }
        state.set(id, st)
      }

      const pingOk = await pingOnce(d.ip)
      const arpOk = devicePresentFromNeigh(d, neigh)
      const alive = pingOk || arpOk

      if (alive) {
        st.missStreak = 0
        st.lastSeen = Date.now()
        st.ip = d.ip
        if (d.mac) {
          const want = String(d.mac).toLowerCase()
          for (const n of neigh.values()) {
            if (n.mac === want) { st.ip = n.ip; break }
          }
        }
        if (!st.present) {
          st.present = true
          app.debug(id + ' present (' + (pingOk ? 'ping' : 'arp') + ')')
        }
        publishDevice(id, true, st.ip, st.lastSeen)
      } else {
        st.missStreak += 1
        if (st.present && st.missStreak >= missNeed) {
          st.present = false
          app.debug(id + ' absent after ' + st.missStreak + ' misses')
          publishDevice(id, false, st.ip, st.lastSeen)
        } else if (st.present) {
          publishDevice(id, true, st.ip, st.lastSeen)
        } else {
          publishDevice(id, false, st.ip, st.lastSeen)
        }
      }
    }
  }

  plugin.start = function (options) {
    plugin.stop()
    options = options || {}
    const pingMs = Math.max(5, Number(options.pingIntervalSeconds) || 30) * 1000
    const discMs = Math.max(15, Number(options.discoverIntervalSeconds) || 60) * 1000
    app.setPluginStatus('Starting LAN presence…')

    const tick = async function () {
      try { await checkTracked(options) } catch (e) {
        app.error(e)
        app.setPluginStatus('Error: ' + (e.message || e))
      }
    }
    const disc = async function () {
      try { await refreshDiscovery(options) } catch (e) { app.debug(e) }
    }

    disc()
    tick()
    timer = setInterval(tick, pingMs)
    discoverTimer = setInterval(disc, discMs)
    statusTimer = setInterval(function () {
      const tracked = (options.devices || []).filter(function (d) { return d && d.enabled !== false })
      const present = tracked.filter(function (d) {
        const st = state.get(slugify(d.name))
        return st && st.present
      }).length
      app.setPluginStatus('Tracking ' + tracked.length + ', present ' + present + ', discovered ' + discovered.size)
    }, 15000)
  }

  plugin.stop = function () {
    if (timer) clearInterval(timer)
    if (discoverTimer) clearInterval(discoverTimer)
    if (statusTimer) clearInterval(statusTimer)
    timer = discoverTimer = statusTimer = null
  }

  plugin._discovered = discovered
  return plugin
}
