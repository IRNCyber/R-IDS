import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'

type Severity = 'Critical' | 'High' | 'Medium' | 'Low'
type Alert = {
  id: string; title: string; severity: Severity; source: string; destination: string
  port: string; rule: string; time: string; age: number; status: 'New' | 'Acknowledged'
  description: string; protocol: string; count: number
}

type Overview = {
  totalAlerts: number; newAlerts: number; criticalAndHigh: number
  critical: number; high: number; medium: number; low: number
  packetsAnalyzed: number; packetsPerSecond: number
  sensorsOnline: number; sensorsTotal: number
}
type CaptureStatus = { state: 'idle' | 'starting' | 'capturing' | 'error'; interface: string | null; error: string | null }
type Health = { status: string; capture: CaptureStatus }

const nav = [
  { label: 'Overview', icon: 'grid' }, { label: 'Alerts', icon: 'bell' },
  { label: 'Detections', icon: 'target' }, { label: 'Network', icon: 'nodes' },
]
const management = [{ label: 'Rules', icon: 'sliders' }, { label: 'Data sources', icon: 'layers' }]

function Icon({ name, size = 18 }: { name: string; size?: number }) {
  const common = { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.7, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const }
  const paths: Record<string, ReactNode> = {
    grid: <><rect x="3.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.5"/></>,
    bell: <><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"/><path d="M10 21h4"/></>,
    target: <><circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="4.5"/><path d="m12 12 6-6"/></>,
    nodes: <><circle cx="5" cy="7" r="2"/><circle cx="19" cy="6" r="2"/><circle cx="12" cy="18" r="2"/><path d="m7 8 4 8m6-9-4 9m-6-9 10-1"/></>,
    sliders: <><path d="M4 7h9m4 0h3M4 17h3m4 0h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/></>,
    layers: <><path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 12 9 5 9-5M3 16l9 5 9-5"/></>,
    search: <><circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 4.5 4.5"/></>,
    chevron: <path d="m9 18 6-6-6-6"/>,
    down: <path d="m7 10 5 5 5-5"/>,
    arrow: <><path d="M7 17 17 7M7 7h10v10"/></>,
    check: <path d="m5 12 4 4L19 6"/>,
    close: <path d="m6 6 12 12M18 6 6 18"/>,
    more: <><circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/></>,
    clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
    shield: <><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z"/><path d="m9 12 2 2 4-4"/></>,
    bolt: <path d="m13 2-3 8h7l-6 12 1-9H5l8-11Z"/>,
    menu: <><path d="M4 6h16M4 12h16M4 18h16"/></>,
    external: <><path d="M14 4h6v6m0-6-9 9"/><path d="M18 13v5a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h5"/></>,
  }
  return <svg {...common} aria-hidden="true">{paths[name] ?? paths.grid}</svg>
}

function App() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [selectedId, setSelectedId] = useState('')
  const [overview, setOverview] = useState<Overview | null>(null)
  const [captureStatus, setCaptureStatus] = useState<CaptureStatus>({ state: 'idle', interface: null, error: null })
  const [apiState, setApiState] = useState<'loading' | 'online' | 'offline'>('loading')
  const [severity, setSeverity] = useState('All severities')
  const [query, setQuery] = useState('')
  const [activeNav, setActiveNav] = useState('Overview')
  const [toast, setToast] = useState('')
  const [mobileMenu, setMobileMenu] = useState(false)

  useEffect(() => {
    let cancelled = false
    async function loadDashboard() {
      try {
        const [alertsResponse, overviewResponse, healthResponse] = await Promise.all([
          fetch('/api/v1/alerts'),
          fetch('/api/v1/stats/overview'),
          fetch('/api/v1/health'),
        ])
        if (!alertsResponse.ok || !overviewResponse.ok || !healthResponse.ok) throw new Error('Dashboard API returned an error')
        const [nextAlerts, nextOverview, health] = await Promise.all([
          alertsResponse.json() as Promise<Alert[]>,
          overviewResponse.json() as Promise<Overview>,
          healthResponse.json() as Promise<Health>,
        ])
        if (cancelled) return
        setAlerts(nextAlerts)
        setOverview(nextOverview)
        setCaptureStatus(health.capture)
        setSelectedId(current => current || nextAlerts[0]?.id || '')
        setApiState('online')
      } catch {
        if (!cancelled) setApiState('offline')
      }
    }
    void loadDashboard()
    const refresh = window.setInterval(() => { void loadDashboard() }, 2000)
    return () => { cancelled = true; window.clearInterval(refresh) }
  }, [])

  const filteredAlerts = useMemo(() => alerts.filter(alert => {
    const matchesSeverity = severity === 'All severities' || alert.severity === severity
    const searchable = `${alert.title} ${alert.source} ${alert.destination} ${alert.id} ${alert.rule}`.toLowerCase()
    return matchesSeverity && searchable.includes(query.toLowerCase())
  }), [alerts, severity, query])
  const selected = alerts.find(alert => alert.id === selectedId)
  const newCount = alerts.filter(alert => alert.status === 'New').length
  const severityTotal = overview?.totalAlerts ?? 0
  const severityStats = overview ? [
    { label: 'Critical', count: overview.critical, className: 'critical-dot' },
    { label: 'High', count: overview.high, className: 'high-dot' },
    { label: 'Medium', count: overview.medium, className: 'medium-dot' },
    { label: 'Low', count: overview.low, className: 'low-dot' },
  ] : []
  const severityColors = ['#df6863', '#e9a056', '#e7c668', '#54af91']
  let severityOffset = 0
  const severityGradient = severityTotal === 0 ? '#e9edef' : `conic-gradient(${severityStats.map((item, index) => {
    const start = severityOffset / severityTotal * 100
    severityOffset += item.count
    return `${severityColors[index]} ${start}% ${severityOffset / severityTotal * 100}%`
  }).join(', ')})`

  async function acknowledge(id: string) {
    try {
      const response = await fetch(`/api/v1/alerts/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'Acknowledged' }),
      })
      if (!response.ok) throw new Error('Could not update alert')
      const updated = await response.json() as Alert
      setAlerts(current => current.map(alert => alert.id === id ? updated : alert))
      setOverview(current => current ? { ...current, newAlerts: Math.max(0, current.newAlerts - 1) } : current)
      setToast(`${id} acknowledged`)
      window.setTimeout(() => setToast(''), 2400)
    } catch {
      setToast('Could not acknowledge alert. Check the API connection.')
      window.setTimeout(() => setToast(''), 3000)
    }
  }

  function exportAlerts() {
    const rows = [['ID', 'Title', 'Severity', 'Source', 'Destination', 'Time', 'Status'], ...filteredAlerts.map(a => [a.id, a.title, a.severity, a.source, a.destination, a.time, a.status])]
    const csv = rows.map(row => row.map(cell => `"${cell.replaceAll('"', '""')}"`).join(',')).join('\n')
    const link = document.createElement('a')
    link.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
    link.download = 'rustguard-alerts.csv'
    link.click()
    URL.revokeObjectURL(link.href)
  }

  return <div className="app-shell">
    <aside className={`sidebar ${mobileMenu ? 'sidebar-open' : ''}`}>
      <div className="brand"><div className="brand-mark"><Icon name="shield" size={20}/></div><span>rustguard<span className="brand-period">.</span></span><button className="mobile-close icon-button" aria-label="Close menu" onClick={() => setMobileMenu(false)}><Icon name="close"/></button></div>
      <div className="workspace-switch"><div className="workspace-avatar">R</div><div className="workspace-copy"><strong>RustGuard Local</strong><span>Workspace</span></div><Icon name="down" size={15}/></div>
      <div className="nav-caption">MONITOR</div>
      <nav aria-label="Main navigation">{nav.map(item => <button key={item.label} className={`nav-item ${activeNav === item.label ? 'nav-active' : ''}`} onClick={() => { setActiveNav(item.label); setMobileMenu(false) }}><Icon name={item.icon}/><span>{item.label}</span></button>)}</nav>
      <div className="nav-caption management-caption">MANAGE</div>
      <nav aria-label="Management">{management.map(item => <button key={item.label} className={`nav-item ${activeNav === item.label ? 'nav-active' : ''}`} onClick={() => { setActiveNav(item.label); setMobileMenu(false) }}><Icon name={item.icon}/><span>{item.label}</span></button>)}</nav>
      <div className="sidebar-bottom">
        <div className="sensor-card"><div className="sensor-title"><span className={`pulse-dot ${apiState === 'offline' || captureStatus.state === 'error' ? 'offline-dot' : ''}`}/>{apiState === 'loading' ? 'Connecting to API' : apiState === 'offline' ? 'API unavailable' : captureStatus.state === 'capturing' ? 'Live capture active' : captureStatus.state === 'error' ? 'Capture error' : 'API connected · capture idle'}</div><div className="sensor-meta">{captureStatus.interface ? `Interface ${captureStatus.interface}` : apiState === 'online' ? 'No network interface selected' : 'Start rustguard serve-api'}</div><div className="sensor-health"><i style={{ width: captureStatus.state === 'capturing' ? '100%' : '0%' }}/></div></div>
        <button className="profile"><div className="profile-avatar">AR</div><span className="profile-copy"><strong>Alex Rivera</strong><small>Administrator</small></span><Icon name="more" size={17}/></button>
      </div>
    </aside>

    {mobileMenu && <button aria-label="Close navigation overlay" className="mobile-backdrop" onClick={() => setMobileMenu(false)}/>}
    <main className="main-area">
      <header className="topbar"><button className="mobile-menu icon-button" aria-label="Open menu" onClick={() => setMobileMenu(true)}><Icon name="menu"/></button><div className="breadcrumbs"><span>Workspace</span><Icon name="chevron" size={14}/><strong>{activeNav}</strong></div><div className="topbar-right"><div className={`live-status ${apiState === 'offline' || captureStatus.state === 'error' ? 'offline-status' : ''}`}><span className={`pulse-dot ${apiState === 'offline' || captureStatus.state === 'error' ? 'offline-dot' : ''}`}/>{apiState === 'loading' ? 'Connecting' : apiState === 'offline' ? 'API offline' : captureStatus.state === 'capturing' ? `Capturing ${captureStatus.interface}` : 'API connected'}</div><button className="top-icon icon-button" aria-label="Search"><Icon name="search"/></button><button className="top-icon notification-button icon-button" aria-label="Notifications"><Icon name="bell"/><i/></button><div className="top-avatar">AR</div></div></header>
      <div className="page-content">
        <div className="page-heading"><div><div className="eyebrow"><span className="pulse-dot"/>{new Intl.DateTimeFormat('en-US', { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' }).format(new Date()).toUpperCase()}</div><h1>Security overview</h1><p className="page-subtitle">Here’s what’s happening across your monitored network.</p></div><div className="heading-actions"><button className="button button-secondary" onClick={exportAlerts} disabled={!alerts.length}><span className="download-icon">↓</span> Export report</button><button className="button button-primary" onClick={() => { setActiveNav('Alerts'); document.querySelector('.alerts-panel')?.scrollIntoView({ behavior: 'smooth', block: 'center' }) }}><Icon name="bolt" size={16}/> Investigate alerts <span className="button-badge">{newCount}</span></button></div></div>
        {apiState === 'online' && captureStatus.state === 'capturing' && <div className="api-notice"><Icon name="shield" size={15}/><span><strong>Passive capture active on {captureStatus.interface}.</strong> RustGuard is observing TCP SYN traffic and raising alerts when a source crosses the configured scan thresholds.</span></div>}
        {apiState === 'online' && captureStatus.state === 'idle' && <div className="api-notice"><Icon name="shield" size={15}/><span><strong>API connected; packet capture is idle.</strong> Choose an authorized interface with <code>rustguard list-interfaces</code>, then start <code>cargo run -p ids-cli --features ids-cli/live-capture -- serve-api --interface &lt;name&gt;</code>.</span></div>}
        {apiState === 'online' && captureStatus.state === 'starting' && <div className="api-notice"><Icon name="clock" size={15}/><span><strong>Opening capture on {captureStatus.interface}…</strong> The alert feed will update when SYN traffic is observed.</span></div>}
        {apiState === 'online' && captureStatus.state === 'error' && <div className="api-notice api-error"><Icon name="bolt" size={15}/><span><strong>Capture could not start.</strong> {captureStatus.error ?? 'Check the selected interface and capture permissions.'}</span></div>}
        {apiState === 'offline' && <div className="api-notice api-error"><Icon name="bolt" size={15}/><span><strong>Backend not reachable.</strong> Start the API with <code>cargo run -p ids-cli --features ids-cli/live-capture -- serve-api --interface &lt;name&gt;</code>, then refresh this page.</span></div>}

        <section className="metric-grid" aria-label="Security metrics">
          <article className="metric-card"><div className="metric-top"><span className="metric-label">Total alerts</span><span className="metric-icon metric-icon-green"><Icon name="bell" size={17}/></span></div><div className="metric-value">{overview?.totalAlerts ?? '—'} <span className="metric-change positive"><Icon name="arrow" size={13}/> {overview ? `${overview.newAlerts} new` : '—'}</span></div><div className="metric-foot">Current alert feed</div></article>
          <article className="metric-card"><div className="metric-top"><span className="metric-label">Critical &amp; high</span><span className="metric-icon metric-icon-red"><Icon name="target" size={17}/></span></div><div className="metric-value">{overview?.criticalAndHigh ?? '—'}</div><div className="metric-foot">{overview ? `${overview.critical} critical · ${overview.high} high severity` : 'Waiting for API'}</div></article>
          <article className="metric-card"><div className="metric-top"><span className="metric-label">TCP SYNs observed</span><span className="metric-icon metric-icon-blue"><Icon name="layers" size={17}/></span></div><div className="metric-value">{(overview?.packetsAnalyzed ?? 0).toLocaleString()}</div><div className="metric-foot">{(overview?.packetsPerSecond ?? 0).toLocaleString()} SYNs / sec</div></article>
          <article className="metric-card"><div className="metric-top"><span className="metric-label">Sensors online</span><span className="metric-icon metric-icon-purple"><Icon name="shield" size={17}/></span></div><div className="metric-value">{overview?.sensorsOnline ?? 0} <span className="metric-total">/ {overview?.sensorsTotal ?? 0}</span><span className="online-tag">{overview?.sensorsTotal ? `${overview.sensorsOnline} online` : 'None configured'}</span></div><div className="metric-foot">Sensor integration is not configured</div></article>
        </section>

        <section className="analytics-grid">
          <article className="panel trend-panel"><div className="panel-heading"><div><h2>Alert activity</h2><p>Current API feed</p></div></div><div className="chart-summary"><strong>{overview?.totalAlerts ?? '—'}</strong><span>alerts in feed</span><span className="chart-comparison">Timeline aggregation will be available with event storage.</span></div><div className="chart-placeholder"><Icon name="clock" size={20}/><span>Alert history chart needs timestamped stored events</span></div></article>
          <article className="panel severity-panel"><div className="panel-heading"><div><h2>Severity breakdown</h2><p>Alerts by priority</p></div><button className="icon-button subtle-button" aria-label="More severity options"><Icon name="more"/></button></div><div className="severity-content"><div className="donut-wrap"><div className="donut" style={{ background: severityGradient }}><div className="donut-center"><strong>{severityTotal}</strong><span>Total</span></div></div></div><div className="severity-legend">{severityStats.map(item => <div key={item.label}><i className={`sev-dot ${item.className}`}/><span>{item.label}</span><b>{item.count}</b><small>{severityTotal ? `${(item.count / severityTotal * 100).toFixed(0)}%` : '0%'}</small></div>)}</div></div><div className="severity-foot"><span className="pulse-dot"/>Counts from current API feed</div></article>
        </section>

        <section className="lower-grid">
          <article className="panel alerts-panel"><div className="panel-heading alerts-heading"><div><div className="heading-title-row"><h2>Recent alerts</h2><span className="new-pill">{newCount} new</span></div><p>Latest detections from your network</p></div><button className="text-link" onClick={() => setActiveNav('Alerts')}>View all alerts <Icon name="chevron" size={15}/></button></div>
            <div className="alert-controls"><label className="search-box"><Icon name="search" size={16}/><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search alerts, IPs, rules…" aria-label="Search alerts"/><kbd>/</kbd></label><label className="select-wrap severity-select"><select value={severity} onChange={e => setSeverity(e.target.value)} aria-label="Filter by severity"><option>All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select><Icon name="down" size={14}/></label><button className="filter-button" onClick={() => { setSeverity('All severities'); setQuery('') }}>Reset</button></div>
            <div className="alert-table-wrap">{apiState === 'loading' ? <div className="empty-state"><strong>Loading alerts…</strong><span>Connecting to the RustGuard API.</span></div> : apiState === 'offline' ? <div className="empty-state"><span className="empty-icon"><Icon name="bolt" size={20}/></span><strong>Alert feed unavailable</strong><span>Start the backend to load alert records.</span></div> : <><table className="alert-table"><thead><tr><th>DETECTION</th><th>SOURCE → DESTINATION</th><th>SEVERITY</th><th>TIME</th><th><span className="sr-only">Open</span></th></tr></thead><tbody>{filteredAlerts.map(alert => <tr key={alert.id} className={selectedId === alert.id ? 'selected-row' : ''} onClick={() => setSelectedId(alert.id)} tabIndex={0} onKeyDown={e => e.key === 'Enter' && setSelectedId(alert.id)}><td><div className="detection-cell"><span className={`severity-rail rail-${alert.severity.toLowerCase()}`}/><span><strong>{alert.title}</strong><small>{alert.id} <i>·</i> {alert.rule}</small></span></div></td><td><div className="ip-cell"><span>{alert.source}</span><Icon name="chevron" size={13}/><span>{alert.destination}</span></div><small className="port-label">Port {alert.port}</small></td><td><span className={`severity-badge badge-${alert.severity.toLowerCase()}`}><i/>{alert.severity}</span></td><td><span className="time-cell">{alert.time}</span><small className="ago-cell">{alert.age} min ago</small></td><td><button className="row-open" aria-label={`View ${alert.title}`} onClick={e => { e.stopPropagation(); setSelectedId(alert.id) }}><Icon name="chevron" size={16}/></button></td></tr>)}</tbody></table>{filteredAlerts.length === 0 && <div className="empty-state"><span className="empty-icon"><Icon name="search" size={20}/></span><strong>{alerts.length ? 'No alerts match your search' : 'No alerts in the feed yet'}</strong><span>{alerts.length ? 'Try a different keyword or severity.' : 'New detections will appear here when sources are connected.'}</span>{alerts.length > 0 && <button onClick={() => { setQuery(''); setSeverity('All severities') }}>Clear filters</button>}</div>}</>}</div>
            <div className="table-footer"><span>Showing <strong>{filteredAlerts.length ? 1 : 0}–{filteredAlerts.length}</strong> of <strong>{overview?.totalAlerts ?? 0}</strong> alerts</span><div><button disabled aria-label="Previous page">‹</button><button className="page-number">1</button><button disabled aria-label="Next page">›</button></div></div>
          </article>

          <aside className="right-column"><article className="panel activity-panel"><div className="panel-heading"><div><h2>Network activity</h2><p>Packet capture metrics</p></div><span className={`live-small ${captureStatus.state === 'capturing' ? '' : 'not-live'}`}><i/>{captureStatus.state === 'capturing' ? 'LIVE' : 'IDLE'}</span></div><div className="activity-number">{(overview?.packetsPerSecond ?? 0).toLocaleString()} <span>packets / sec</span></div><div className="chart-placeholder compact-placeholder"><Icon name="layers" size={19}/><span>{captureStatus.state === 'capturing' ? 'Traffic history will appear after storage is enabled.' : 'Start capture to observe live network traffic.'}</span></div></article>
          <article className="panel sensor-panel"><div className="panel-heading"><div><h2>Sensor health</h2><p>Collection points reported by API</p></div><button className="text-link" onClick={() => setActiveNav('Data sources')}>Manage <Icon name="chevron" size={14}/></button></div>{overview?.sensorsTotal ? <div className="sensor-row"><span className="sensor-type sensor-type-green"><Icon name="nodes" size={15}/></span><div><strong>{overview.sensorsOnline} sensors online</strong><small>{overview.sensorsTotal} configured collection points</small></div><span className="status-dot"/></div> : <div className="sensor-empty"><Icon name="shield" size={19}/><strong>No sensors registered</strong><span>Connect packet or log sources to report health here.</span></div>}</article></aside>
        </section>
        <footer className="page-footer"><span>RustGuard IDS <i>·</i> Local dashboard</span><span><span className="pulse-dot"/> {captureStatus.state === 'capturing' ? `Passive capture · ${captureStatus.interface}` : 'No packet capture active'}</span></footer>
      </div>
    </main>

    <aside className="detail-panel"><div className="detail-top"><span className="detail-kicker">ALERT DETAILS</span><button className="icon-button detail-more" aria-label="More alert actions"><Icon name="more"/></button></div>{selected ? <><div className={`detail-severity severity-${selected.severity.toLowerCase()}`}><span className="severity-icon"><Icon name="target" size={17}/></span>{selected.severity} severity</div><h2 className="detail-title">{selected.title}</h2><div className="detail-id">{selected.id}<span>·</span>{selected.rule}</div><p className="detail-description">{selected.description}</p><div className="detail-actions"><button className={`button ${selected.status === 'Acknowledged' ? 'button-acknowledged' : 'button-primary'}`} onClick={() => selected.status === 'New' && acknowledge(selected.id)}>{selected.status === 'Acknowledged' ? <><Icon name="check" size={16}/> Acknowledged</> : <><Icon name="check" size={16}/> Acknowledge</>}</button><button className="button button-secondary" onClick={() => setToast('Case management is not available yet')}><Icon name="external" size={15}/> Create case</button></div><div className="detail-section"><h3>CONNECTION</h3><div className="connection-flow"><div><small>SOURCE</small><strong>{selected.source}</strong><span>Source address</span></div><div className="connection-arrow"><Icon name="arrow" size={15}/></div><div><small>DESTINATION</small><strong>{selected.destination}</strong><span>Port {selected.port} · {selected.protocol}</span></div></div></div><div className="detail-section"><h3>DETECTION CONTEXT</h3><div className="context-row"><span>Observed activity</span><strong>{selected.count} events</strong></div><div className="context-row"><span>Detection window</span><strong>{selected.age < 5 ? '60 seconds' : '5 minutes'}</strong></div><div className="context-row"><span>First seen</span><strong>Today, {selected.time}</strong></div><div className="context-row"><span>Sensor</span><strong>Not assigned</strong></div></div><div className="detail-section rule-section"><div className="rule-heading"><h3>TRIGGERED RULE</h3><button onClick={() => setActiveNav('Rules')}>View rule <Icon name="chevron" size={13}/></button></div><div className="rule-code"><span>alert</span> tcp any any <span>→</span> $HOME_NET {selected.port}<br/><span className="rule-indent">(msg: <em>"{selected.title}"</em>; sid: {selected.rule.replace('SID ', '')};)</span></div></div><div className="detail-bottom"><div className="detail-status"><span className={selected.status === 'New' ? 'status-dot status-orange' : 'status-dot'}/><span>{selected.status}</span><span>·</span><span>{selected.age} minutes ago</span></div><button className="detail-text-button" onClick={() => setToast('Alert history will be available after storage is connected')}>View activity history <Icon name="chevron" size={13}/></button></div></> : <div className="detail-empty"><span className="empty-icon"><Icon name="target" size={20}/></span><strong>{apiState === 'loading' ? 'Loading alert details' : 'Select an alert'}</strong><span>{apiState === 'offline' ? 'Start the backend to load investigations.' : 'Choose a detection to inspect its details.'}</span></div>}</aside>
    {toast && <div className="toast" role="status"><span className="toast-check"><Icon name="check" size={14}/></span>{toast}</div>}
  </div>
}

export default App
