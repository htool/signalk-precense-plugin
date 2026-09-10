const { execFile } = require('child_process')
const { promisify } = require('util')
const os = require('os')
const fs = require('fs')

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
  /** @type {Map<string, { host: string, ip: string, lastSeen: number }>} */
  const mdnsByName = new Map()
  let mdnsBrowsers = []


  plugin.schema = () => {
    const nets = listLocalNetworks()
    const enums = nets.map((n) => n.cidr)
    const enumNames = nets.map(networkLabel)
    return {
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
        title: 'Networks to scan',
        description: enums.length
          ? 'Kies welk LAN-netwerk(en) gescand worden. Leeg = alle hieronder.'
          : 'Geen bruikbare LAN-interfaces gevonden; laat leeg.',
        items: enums.length
          ? { type: 'string', enum: enums, enumNames: enumNames }
          : { type: 'string' },
        uniqueItems: true,
        default: []
      },
      devices: (() => {
        const list = listDiscoverableDevices()
        const enums = list.map((d) => d.key)
        const enumNames = list.map((d) => d.label)
        return {
          type: 'array',
          title: 'Tracked devices',
          description: enums.length
            ? 'Vink ontdekte LAN-devices aan. Pad: sensors.presence.<naam> (hostname of IP).'
            : 'Nog geen devices in ARP/neigh. Wacht even of open deze pagina opnieuw na discovery.',
          items: enums.length
            ? { type: 'string', enum: enums, enumNames: enumNames }
            : { type: 'string' },
          uniqueItems: true,
          default: []
        }
      })(),
      deviceNames: {
        type: 'object',
        title: 'Pad-namen (optioneel)',
        description: 'Overschrijf de Signal K path-slug per device-key (anders hostname of IP).',
        additionalProperties: { type: 'string' },
        default: {}
      },
      mdnsNames: {
        type: 'array',
        title: 'Track by mDNS name (iPhone-friendly)',
        description:
          'Announced names like Hans-iPhone or Hans-iPhone.local. Resolves via mDNS each check — no fixed MAC needed (Private Wi-Fi Address OK).',
        items: { type: 'string' },
        default: []
      }
    }
  }
  }

  plugin.uiSchema = () => ({
    networks: {
      'ui:widget': 'checkboxes',
      'ui:options': { inline: false }
    },
    devices: {
      'ui:widget': 'checkboxes',
      'ui:options': { inline: false }
    },
    deviceNames: {
      'ui:widget': 'hidden'
    }
  })

  function slugify (name) {
    return String(name || '')
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'device'
  }


  function normalizeMdnsName (name) {
    return String(name || '')
      .trim()
      .replace(/\.local$/i, '')
      .toLowerCase()
  }

  function deviceKey (entry) {
    const host = normalizeMdnsName(entry.hostname || entry.host || '')
    if (host) return 'name:' + host
    if (entry.mac) return 'mac:' + String(entry.mac).toLowerCase()
    return 'ip:' + entry.ip
  }

  function deviceLabel (entry) {
    const host = (entry.hostname || '').replace(/\.local$/i, '')
    const mac = entry.mac ? ' · mac ' + entry.mac : ''
    if (host) return host + '.local · ' + (entry.ip || '?') + mac + ' [mDNS name]'
    return (entry.ip || '?') + mac
  }

  function defaultPathName (entry) {
    const host = (entry.hostname || entry.mdnsName || '').replace(/\.local$/i, '')
    if (host) return slugify(host)
    return ''
  }

  function isUglyFactoryName (name) {
    const n = String(name || '')
    // Shelly factory ids, bare IPs, empty, generic fallback
    if (!n || n === 'device') return true
    if (/^\d+-\d+-\d+-\d+$/.test(n)) return true
    if (/^shelly/i.test(n) && /[0-9a-f]{8,}/i.test(n)) return true
    return false
  }

  function preferName (a, b) {
    // return the nicer of two path names
    if (!a) return b
    if (!b) return a
    const ua = isUglyFactoryName(a)
    const ub = isUglyFactoryName(b)
    if (ua && !ub) return b
    if (ub && !ua) return a
    return a.length <= b.length ? a : b
  }

  /** Saved selection keys may outlive ARP; keep them selectable. */
  let lastOptions = {}

  function watchedCidrs (options) {
    options = options || lastOptions || {}
    const listed = (options.networks && options.networks.length) ? options.networks : localCidrs()
    return listed.filter(Boolean)
  }

  function ipMatchesCidrs (ip, cidrs) {
    const parts = String(ip || '').split('.').map(Number)
    if (parts.length !== 4 || parts.some(function (p) { return !Number.isFinite(p) })) return false
    if (!cidrs || !cidrs.length) return true
    const ipn = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0
    for (const cidr of cidrs) {
      const bits = String(cidr).split('/')
      const net = bits[0].split('.').map(Number)
      if (net.length !== 4) continue
      const prefix = Number(bits[1] || 24)
      const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
      const netn = ((net[0] << 24) | (net[1] << 16) | (net[2] << 8) | net[3]) >>> 0
      if ((ipn & mask) === (netn & mask)) return true
    }
    return false
  }

  function ipInWatched (ip, options) {
    return ipMatchesCidrs(ip, watchedCidrs(options))
  }

  function pickWatchedIp (ips, options) {
    const list = (ips || []).filter(function (a) { return /^\d+\.\d+\.\d+\.\d+$/.test(a) })
    const cidrs = watchedCidrs(options)
    for (let i = 0; i < list.length; i++) {
      if (ipMatchesCidrs(list[i], cidrs)) return list[i]
    }
    return ''
  }

  function bestDiscoveredForKey (key) {
    let best = null
    for (const d of discovered.values()) {
      if (deviceKey(d) !== key) continue
      if (!ipInWatched(d.ip)) continue
      if (!best || (d.lastSeen || 0) >= (best.lastSeen || 0)) best = d
    }
    return best
  }

  function ipForMac (mac) {
    if (!mac) return ''
    const want = String(mac).toLowerCase()
    for (const d of discovered.values()) {
      if (String(d.mac || '').toLowerCase() === want && ipInWatched(d.ip)) return d.ip
    }
    return ''
  }

  function neighIpForMac (mac, neigh) {
    if (!mac || !neigh) return ''
    const want = String(mac).toLowerCase()
    let fallback = ''
    for (const n of neigh.values()) {
      if (n.mac !== want) continue
      if (!ipInWatched(n.ip)) continue
      if (n.state === 'REACHABLE' || n.state === 'DELAY' || n.state === 'PROBE') return n.ip
      if (!fallback) fallback = n.ip
    }
    return fallback
  }

  function seedDiscoveredFromArpSync () {
    if (discovered.size) return
    try {
      const text = fs.readFileSync('/proc/net/arp', 'utf8')
      for (const line of text.split('\n').slice(1)) {
        const p = line.trim().split(/\s+/)
        if (p.length < 4) continue
        const ip = p[0]
        const mac = (p[3] || '').toLowerCase()
        if (!mac || mac === '00:00:00:00:00:00') continue
        if (!ipInWatched(ip)) continue
        if (!discovered.has(ip)) {
          discovered.set(ip, { ip: ip, mac: mac, hostname: '', lastSeen: Date.now() })
        }
      }
    } catch (_) {}
  }

  function listDiscoverableDevices () {
    seedDiscoveredFromArpSync()
    const byKey = new Map()
    for (const entry of discovered.values()) {
      if (!entry || !entry.ip) continue
      const key = deviceKey(entry)
      const prev = byKey.get(key)
      if (!prev || (entry.lastSeen || 0) >= (prev.lastSeen || 0)) {
        byKey.set(key, {
          key: key,
          ip: entry.ip,
          mac: entry.mac || '',
          hostname: entry.hostname || '',
          lastSeen: entry.lastSeen || 0,
          label: deviceLabel(entry)
        })
      }
    }
    for (const [name, info] of mdnsByName.entries()) {
      const key = 'name:' + name
      const prev = byKey.get(key)
      if (!prev || (info.lastSeen || 0) >= (prev.lastSeen || 0)) {
        byKey.set(key, {
          key: key,
          ip: info.ip,
          mac: '',
          hostname: name,
          lastSeen: info.lastSeen || 0,
          label: deviceLabel({ hostname: name, ip: info.ip, mac: '' })
        })
      }
    }
    // Prefer name: keys: drop mac:/ip: duplicates that share hostname
    for (const [key, row] of Array.from(byKey.entries())) {
      if (key.indexOf('name:') === 0) continue
      if (row.hostname) {
        const nkey = 'name:' + normalizeMdnsName(row.hostname)
        if (byKey.has(nkey)) byKey.delete(key)
      }
    }
    // merge previously selected keys from lastOptions so offline devices stay listed
    const selected = normalizeSelectedKeys(lastOptions.devices).concat(
      (lastOptions.mdnsNames || []).map(function (n) { return 'name:' + normalizeMdnsName(n) })
    )
    for (const key of selected) {
      if (byKey.has(key)) continue
      const parsed = parseDeviceKey(key)
      if (!parsed) continue
      byKey.set(key, {
        key: key,
        ip: parsed.ip || '',
        mac: parsed.mac || '',
        hostname: '',
        lastSeen: 0,
        label: (parsed.mac ? parsed.ip + ' (' + parsed.mac + ') [offline]' : parsed.ip + ' [offline]')
      })
    }
    return Array.from(byKey.values()).sort((a, b) => a.label.localeCompare(b.label))
  }

  function parseDeviceKey (key) {
    if (!key || typeof key !== 'string') return null
    if (key.indexOf('name:') === 0) return { name: key.slice(5), ip: '', mac: '' }
    if (key.indexOf('mac:') === 0) return { mac: key.slice(4), ip: '', name: '' }
    if (key.indexOf('ip:') === 0) return { ip: key.slice(3), mac: '', name: '' }
    if (/^\d+\.\d+\.\d+\.\d+$/.test(key)) return { ip: key, mac: '', name: '' }
    // bare hostname
    if (key.indexOf('.') === -1 || /\.local$/i.test(key)) {
      return { name: normalizeMdnsName(key), ip: '', mac: '' }
    }
    return null
  }

  function rememberMdnsHost (host, ip) {
    const name = normalizeMdnsName(host)
    if (!name || !ip) return
    mdnsByName.set(name, { host: name, ip: ip, lastSeen: Date.now() })
    const prev = discovered.get(ip) || {}
    discovered.set(ip, {
      ip: ip,
      mac: prev.mac || '',
      hostname: name,
      lastSeen: Date.now()
    })
  }

  function loadMdnsJs () {
    try { return require('mdns-js') } catch (_) {}
    try { return require('/home/pi/.signalk/node_modules/mdns-js') } catch (_) {}
    return null
  }

  function startMdnsBrowse () {
    stopMdnsBrowse()
    const mdns = loadMdnsJs()
    if (!mdns) {
      app.debug('mdns-js not found; using avahi CLI only')
      return
    }
    const types = [
      mdns.createBrowser(),
      mdns.createBrowser(mdns.tcp('http')),
      mdns.createBrowser(mdns.tcp('apple-mobdev2')),
      mdns.createBrowser(mdns.tcp('companion-link')),
      mdns.createBrowser(mdns.tcp('airplay')),
      mdns.createBrowser(mdns.tcp('raop')),
      mdns.createBrowser(mdns.tcp('device-info'))
    ]
    for (const browser of types) {
      browser.on('ready', function () {
        try { browser.discover() } catch (_) {}
      })
      browser.on('update', function (data) {
        try {
          const host = data.host || ''
          const addrs = data.addresses || []
          const ip = addrs.find(function (a) { return /^\d+\.\d+\.\d+\.\d+$/.test(a) })
          if (host && ip) rememberMdnsHost(host, ip)
          else if (data.fullname && ip) {
            const short = String(data.fullname).split('.')[0]
            if (short) rememberMdnsHost(short, ip)
          }
        } catch (e) { app.debug(e) }
      })
      mdnsBrowsers.push(browser)
    }
  }

  function stopMdnsBrowse () {
    for (const b of mdnsBrowsers) {
      try { if (b && b.stop) b.stop() } catch (_) {}
    }
    mdnsBrowsers = []
  }

  async function refreshMdnsViaAvahi () {
    // Lightweight: resolve known mdnsNames + parse a short browse for host/address pairs
    const out = await run('timeout', ['6', 'avahi-browse', '-atrk'], 8000)
    let curHost = ''
    for (const line of String(out).split('\n')) {
      let m = line.match(/hostname = \[([^\]]+)\]/)
      if (m) { curHost = m[1]; continue }
      m = line.match(/address = \[(\d+\.\d+\.\d+\.\d+)\]/)
      if (m && curHost) {
        rememberMdnsHost(curHost, m[1])
        curHost = ''
      }
    }
  }

  async function resolveMdnsNameToIp (name) {
    const n = normalizeMdnsName(name)
    const cached = mdnsByName.get(n)
    if (cached && cached.ip && Date.now() - cached.lastSeen < 120000) return cached.ip
    const fqdn = n + '.local'
    let text = await run('avahi-resolve-host-name', ['-4', fqdn], 4000)
    let m = String(text).match(/(\d+\.\d+\.\d+\.\d+)/)
    if (m) {
      rememberMdnsHost(n, m[1])
      return m[1]
    }
    text = await run('getent', ['hosts', fqdn], 3000)
    m = String(text).match(/(\d+\.\d+\.\d+\.\d+)/)
    if (m) {
      rememberMdnsHost(n, m[1])
      return m[1]
    }
    return (cached && cached.ip) || ''
  }

  function normalizeSelectedKeys (devices) {
    if (!devices) return []
    if (!Array.isArray(devices)) return []
    if (!devices.length) return []
    if (typeof devices[0] === 'string') return devices.filter(Boolean)
    // legacy {enabled,name,ip,mac}
    return devices
      .filter(function (d) { return d && d.enabled !== false && d.ip })
      .map(function (d) {
        return d.mac ? 'mac:' + String(d.mac).toLowerCase() : 'ip:' + d.ip
      })
  }

  function resolveTrackedDevices (options) {
    const names = options.deviceNames || {}
    const selected = normalizeSelectedKeys(options.devices)
    const rows = []
    if (Array.isArray(options.devices) && options.devices.length && typeof options.devices[0] === 'object') {
      for (const d of options.devices) {
        if (!d || d.enabled === false || !d.ip) continue
        rows.push({
          name: d.name || defaultPathName(d),
          ip: d.ip,
          mac: d.mac || '',
          mdnsName: '',
          key: d.mac ? 'mac:' + String(d.mac).toLowerCase() : 'ip:' + d.ip
        })
      }
    } else {
      function pushDev (key, entry, parsed) {
        const mdnsName = (parsed && parsed.name) || normalizeMdnsName((entry && entry.hostname) || '')
        const mac = (entry && entry.mac) || (parsed && parsed.mac) || ''
        let useIp = (entry && entry.ip) || (parsed && parsed.ip) || ''
        if (!useIp && mac) {
          for (const d of discovered.values()) {
            if (String(d.mac).toLowerCase() === mac) { useIp = d.ip; break }
          }
        }
        if (!useIp && mdnsName) {
          const c = mdnsByName.get(mdnsName)
          if (c) useIp = c.ip
        }
        const base = entry || { ip: useIp, mac: mac, hostname: mdnsName }
        let name = names[key] || (mdnsName ? slugify(mdnsName) : defaultPathName(base))
        if (!name || name === 'device') return
        rows.push({ name: name, ip: useIp || '', mac: mac, key: key, mdnsName: mdnsName })
      }
      for (const key of selected) {
        let entry = null
        for (const d of discovered.values()) {
          if (deviceKey(d) === key) { entry = d; break }
        }
        pushDev(key, entry, parseDeviceKey(key))
      }
      for (const raw of options.mdnsNames || []) {
        const n = normalizeMdnsName(raw)
        if (!n) continue
        const key = 'name:' + n
        const c = mdnsByName.get(n)
        const entry = c
          ? { ip: c.ip, mac: '', hostname: n }
          : { ip: '', mac: '', hostname: n }
        pushDev(key, entry, { name: n, ip: '', mac: '' })
      }
    }
    // Dedupe by IP (and by mdnsName): keep friendliest path name
    const byIp = new Map()
    const noIp = []
    for (const row of rows) {
      if (!row.ip) { noIp.push(row); continue }
      const prev = byIp.get(row.ip)
      if (!prev) { byIp.set(row.ip, row); continue }
      const chosen = preferName(prev.name, row.name)
      const keep = chosen === row.name ? row : prev
      const other = keep === row ? prev : row
      keep.name = preferName(keep.name, other.name)
      if (!keep.mdnsName && other.mdnsName) keep.mdnsName = other.mdnsName
      if (!keep.mac && other.mac) keep.mac = other.mac
      byIp.set(row.ip, keep)
    }
    // also dedupe no-ip rows by mdnsName
    const byName = new Map()
    for (const row of noIp) {
      const k = row.mdnsName || row.name
      const prev = byName.get(k)
      if (!prev) byName.set(k, row)
      else {
        row.name = preferName(prev.name, row.name)
        byName.set(k, row)
      }
    }
    return Array.from(byIp.values()).concat(Array.from(byName.values()))
  }


  function prefixFromNetmask (netmask) {
    if (!netmask) return 24
    const parts = netmask.split('.').map(Number)
    let bits = 0
    for (const p of parts) {
      for (let i = 7; i >= 0; i--) {
        if (p & (1 << i)) bits++
        else return bits
      }
    }
    return bits
  }

  function listLocalNetworks () {
    const ifaces = os.networkInterfaces()
    const byCidr = new Map()
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
        const family = a.family === 'IPv4' || a.family === 4
        if (!family || a.internal) continue
        const parts = a.address.split('.').map(Number)
        const mask = (a.netmask || '255.255.255.0').split('.').map(Number)
        const net = parts.map((p, i) => p & mask[i]).join('.')
        const prefix = prefixFromNetmask(a.netmask)
        const cidr = net + '/' + prefix
        const prev = byCidr.get(cidr) || { cidr, iface: name, addresses: [] }
        if (!prev.addresses.includes(a.address)) prev.addresses.push(a.address)
        if (name && !prev.iface) prev.iface = name
        byCidr.set(cidr, prev)
      }
    }
    return Array.from(byCidr.values()).sort((a, b) => a.cidr.localeCompare(b.cidr))
  }

  function localCidrs () {
    return listLocalNetworks().map((n) => n.cidr)
  }

  function networkLabel (n) {
    const ips = n.addresses.slice(0, 3).join(', ')
    const more = n.addresses.length > 3 ? '…' : ''
    return n.iface + ' · ' + ips + more + ' (' + n.cidr + ')'
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
    function ipInSelected (ip) {
      if (!cidrs.length) return true
      const parts = ip.split('.').map(Number)
      if (parts.length !== 4) return false
      for (const cidr of cidrs) {
        const bits = cidr.split('/')
        const net = bits[0].split('.').map(Number)
        const prefix = Number(bits[1] || 24)
        const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
        const ipn = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0
        const netn = ((net[0] << 24) | (net[1] << 16) | (net[2] << 8) | net[3]) >>> 0
        if ((ipn & mask) === (netn & mask)) return true
      }
      return false
    }
    // drop stale entries not seen this pass (same network filter)
    for (const ip of Array.from(discovered.keys())) {
      if (!neigh.has(ip)) continue
    }
    for (const entry of neigh.values()) {
      if (!ipInSelected(entry.ip)) continue
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
    try { await refreshMdnsViaAvahi() } catch (e) { app.debug(e) }
    const tracked = resolveTrackedDevices(options).length
    app.setPluginStatus('Discovery: ' + discovered.size + ' hosts, mDNS ' + mdnsByName.size + '; tracking ' + tracked)
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
    const devices = resolveTrackedDevices(options)
    const neigh = await readNeigh()
    const missNeed = Math.max(1, Number(options.missBeforeAbsent) || 4)

    for (const d of devices) {
      const id = slugify(d.name)
      // never publish empty/fallback/IP-slug paths
      if (!id || id === 'device' || /^\d+-\d+-\d+-\d+$/.test(id)) continue
      let st = state.get(id)
      if (!st) {
        st = { present: false, lastSeen: null, ip: d.ip, missStreak: 0 }
        state.set(id, st)
      }

      let resolvedNow = ''
      if (d.mdnsName) {
        resolvedNow = await resolveMdnsNameToIp(d.mdnsName)
        if (resolvedNow) d.ip = resolvedNow
      }
      if (!d.ip) {
        st.missStreak += 1
        if (st.present && st.missStreak >= missNeed) {
          st.present = false
          publishDevice(id, false, st.ip, st.lastSeen)
        } else if (st.present) {
          publishDevice(id, true, st.ip, st.lastSeen)
        } else {
          publishDevice(id, false, st.ip, st.lastSeen)
        }
        continue
      }

      const pingOk = await pingOnce(d.ip)
      const arpOk = devicePresentFromNeigh(d, neigh)
      // mDNS resolve success = announced on LAN (good for sleeping iPhones that ignore ICMP)
      const alive = pingOk || arpOk || !!resolvedNow

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
    lastOptions = options
    const pingMs = Math.max(5, Number(options.pingIntervalSeconds) || 30) * 1000
    const discMs = Math.max(15, Number(options.discoverIntervalSeconds) || 60) * 1000
    app.setPluginStatus('Starting LAN presence…')
    startMdnsBrowse()

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
      const tracked = resolveTrackedDevices(options)
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
    stopMdnsBrowse()
  }

  plugin._discovered = discovered
  return plugin
}
