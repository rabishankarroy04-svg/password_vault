import React, { useEffect, useState } from 'react';

import { getActivities } from './adminApi';

export function DeviceContext({ context = {} }) {
 context = context || {};
 const label = (value, fallback) => value && value !== 'Unknown' ? value : fallback;
 const recorded = ['category', 'os', 'browser', 'deviceStatus'].some(key => key in context);
 const reason = context.userAgentStatus === 'MISSING' ? 'User-Agent not supplied; device details unavailable.'
  : context.userAgentStatus === 'NON_BROWSER' ? 'Non-browser API client reported; physical device and OS are not inferred.'
  : context.userAgentStatus === 'UNRECOGNIZED' ? 'User-Agent format not recognized; only identifiable labels are shown.'
  : !recorded ? 'Request metadata not recorded (legacy or uninstrumented event).'
  : null;
 return <small className="threat-context">{label(context.category, recorded ? 'Device unavailable' : 'Device not recorded')} · {label(context.os, recorded ? 'OS unavailable' : 'OS not recorded')} · {label(context.browser, recorded ? 'Browser unavailable' : 'Browser not recorded')} · {label(context.deviceStatus, recorded ? 'Recognition not evaluated' : 'Recognition not recorded')}
 {reason && <span>{reason}</span>}

 <span>{context.locationAvailable ? `${context.country}${context.region ? ' / '+context.region : ''} (approximate, ${context.locationSource || 'configured provider'})` : 'Location unavailable'}</span>

 {context.deviceId && <span>Device reference: {context.deviceId}</span>}</small>;

}

export function RuleContext({ context = {} }) {

 if (!Object.keys(context).length) return <p className="threat-footnote">Legacy alert: original threshold, time window and evidence snapshot were not stored. Historical configuration is unavailable; no current values are substituted.</p>;

 return <section><h3>Detection context at the time of the alert</h3><p>Factors: {(context.riskFactors || []).join(', ') || 'Unavailable'}</p><p>Relevant events: {context.eventCount ?? 'Unavailable'} · Threshold: {context.threshold ?? 'Unavailable'} · Window: {context.windowMinutes ?? 'Unavailable'} minutes</p>{context.severityReason && <p>{context.severityReason}</p>}<p>{context.suggestedAction || 'Review supporting evidence and confirm legitimate activity with the account owner.'}</p></section>;

}

const TYPES=['ALL','LOGIN','LOGIN_FAILURE','LOGIN_MFA_CHALLENGE','LOGIN_MFA_FAILURE','NEW_DEVICE_LOGIN','NEW_IP_LOGIN','UNUSUAL_LOGIN_TIME','ACCESS_DENIED','USER_ROLE_CHANGED','VAULT_ACCESS_DENIED','CREDENTIAL_SHARED','SHARING_PERMISSION_CHANGED'];

function AuditRow({ item }) {
 const metadata = item.metadata || {};
 const time = item.time ? new Date(item.time) : null;
 const validTime = time && !Number.isNaN(time.getTime());
 return <tr>
  <td><strong className="audit-event-name">{item.action}</strong><span className="audit-secondary">{item.name || 'Unknown account'}</span><span className="audit-record-label">Audit activity</span></td>
  <td><dl className="audit-device-fields"><div><dt>Device</dt><dd>{metadata.category || 'Unknown'}</dd></div><div><dt>OS</dt><dd>{metadata.os || 'Unknown'}</dd></div><div><dt>Browser</dt><dd>{metadata.browser || 'Unknown'}</dd></div></dl></td>
  <td><span className="audit-source">{item.device || 'Unknown source'}</span>{validTime ? <time className="audit-secondary" dateTime={time.toISOString()}>{time.toLocaleString()}</time> : <span className="audit-secondary">Unknown timestamp</span>}</td>
  <td><span className={`audit-result ${item.status === 'Success' ? 'success' : 'review'}`}>{item.status || 'Unknown result'}</span><span className="audit-risk">Risk: {metadata.riskLevel || 'Not classified'}</span>
   <details className="audit-row-details"><summary>Details<span className="visually-hidden"> for {item.action} — {item.name || 'Unknown account'}</span></summary><div>
    <p><strong>Audit details</strong><br/>{item.details || 'No additional details recorded.'}</p>
    <p><strong>Risk explanation</strong><br/>{metadata.riskReason || 'No risk explanation recorded. An audit event is not automatically a security alert.'}</p>
    <p><strong>Device recognition</strong><br/>{metadata.deviceStatus || 'Unknown'}</p>
    <p><strong>Location</strong><br/>{metadata.locationAvailable ? `${metadata.country}${metadata.region ? ' / ' + metadata.region : ''} (approximate)` : 'Location unavailable'}</p>
    {metadata.deviceId && <p><strong>Device reference</strong><br/>{metadata.deviceId}</p>}
    {['credentialRef','shareRef','recipientRef','permission'].filter(key=>metadata[key]).map(key=><p key={key}><strong>{key}</strong><br/>{String(metadata[key])}</p>)}
   </div></details>
  </td>
 </tr>;
}

export function AuditBrowser({ from, to }) {
 const [search,setSearch]=useState(''),[type,setType]=useState('ALL'),[sort,setSort]=useState('NEWEST'),[page,setPage]=useState(0);
 const [data,setData]=useState(null),[error,setError]=useState(''),[loading,setLoading]=useState(false);
 useEffect(()=>{setPage(0);},[from,to]);
 useEffect(()=>{let current=true;setLoading(true);setError('');
  getActivities({search,type,sort,page,size:10,from,to}).then(value=>{if(current)setData(value);}).catch(()=>{if(current){setData(null);setError('Security audit unavailable. Missing monitoring data is not zero activity.');}}).finally(()=>{if(current)setLoading(false);});return()=>{current=false;};
 },[search,type,sort,page,from,to]);
 const size = data?.size || 10;
 const totalPages = Math.max(1, Math.ceil((data?.total || 0) / size));
 return <section className="panel authentication-audit" aria-busy={loading}><div className="panel-heading"><div><span className="panel-eyebrow">AUTHENTICATION AND SECURITY AUDIT</span><h2>Security activity evidence</h2><p>Actual audit events for {from} through {to}. Audit activity is not automatically a threat.</p></div></div>
 <div className="security-alert-filters"><label className="audit-search-label">Search audit<span className="table-search audit-search-control"><i className="fa-solid fa-magnifying-glass" aria-hidden="true"/><input aria-label="Search security audit" placeholder="Search account or event" value={search} onChange={e=>{setSearch(e.target.value);setPage(0);}} maxLength={120}/></span></label><label>Event type<select aria-label="Audit event type" value={type} onChange={e=>{setType(e.target.value);setPage(0);}}>{TYPES.map(v=><option key={v}>{v}</option>)}</select></label><label>Audit order<select value={sort} onChange={e=>{setSort(e.target.value);setPage(0);}}><option value="NEWEST">Newest first</option><option value="OLDEST">Oldest first</option></select></label></div>
 {error && <p role="alert">{error}</p>}{loading && <p role="status">Loading security audit…</p>}
 <div className="audit-table-wrap" tabIndex="0" role="region" aria-label="Scrollable authentication audit"><table className="data-table"><caption className="visually-hidden">Authentication and security audit records, separate from security alert investigations</caption><thead><tr><th scope="col">Event / account</th><th scope="col">Device</th><th scope="col">Source / time</th><th scope="col">Result / risk</th></tr></thead><tbody>{data?.items?.map(item=><AuditRow key={item.id} item={item}/>)}</tbody></table></div>
 {!loading&&data?.items?.length===0&&<p>No audit events match these filters.</p>}
 {data&&<nav className="threat-audit-pagination" aria-label="Authentication audit pagination"><button type="button" aria-label="Previous audit page" disabled={loading||page===0} onClick={()=>setPage(p=>p-1)}>← Previous</button><div className="audit-page-summary" role="status" aria-live="polite"><strong>{loading ? 'Loading audit page…' : `Page ${page+1} of ${totalPages}`}</strong><span>{data.total} matching events</span></div><button type="button" aria-label="Next audit page" disabled={loading||(page+1)*size>=data.total} onClick={()=>setPage(p=>p+1)}>Next →</button></nav>}
 </section>;
}

export function RangeBreakdown({ metrics }) {
 if(!metrics) return <p>Selected-range breakdown unavailable.</p>;
 const chart=(title,rows,statusChart=false)=>{
  const entries=Object.entries(rows || {}),max=Math.max(1,...entries.map(([,value])=>value));
  return <article className={`range-pattern-chart${statusChart ? ' investigation-status-breakdown' : ''}`}><h3>{title}</h3>
   {entries.length ? entries.map(([key,value])=><div key={key} className="threat-breakdown-row" data-status={statusChart && ['OPEN','INVESTIGATING','RESOLVED','FALSE_POSITIVE'].includes(key) ? key : undefined}>
    <span>{key.replaceAll('_',' ')}</span><meter min="0" max={max} value={value} aria-label={key} aria-valuetext={statusChart ? `${value} investigations` : `${value} alerts`}/><strong>{value}</strong>
   </div>) : <p>No matching recorded alerts.</p>}
  </article>;
 };
 const statistics=[
  ['Successful logins',metrics.successfulLogins,'fa-right-to-bracket','green'],
  ['Failed logins',metrics.failedLogins,'fa-triangle-exclamation','amber'],
  ['New-device signals',metrics.newDeviceActivity,'fa-laptop','violet'],
  ['Denied requests',metrics.deniedRequests,'fa-shield-halved','cyan'],
 ];
 return <section className="panel range-patterns">
  <div className="panel-heading"><div><span className="panel-eyebrow">SELECTED DATE RANGE</span><h2>Selected-range activity and investigation patterns</h2><p>Recorded activity and alert counts within the selected date range.</p></div></div>
  <div className="threat-metric-grid range-pattern-metrics">{statistics.map(([label,value,icon,color])=><article key={label}><span className={`mini-stat-icon ${color}`}><i className={`fa-solid ${icon}`} aria-hidden="true"/></span><div><small>{label}</small><strong>{value ?? '—'}</strong></div></article>)}</div>
  <div className="range-pattern-charts">{chart('Alerts by threat type',metrics.byThreatType)}{chart('Investigation status',metrics.byStatus,true)}</div>
 </section>;
}
