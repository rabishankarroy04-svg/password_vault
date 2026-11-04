import React,{useEffect,useState} from 'react';
import {getSharingMonitor} from './adminApi';
export default function SharingMonitor(){
 const [page,setPage]=useState(0),[status,setStatus]=useState('ALL'),[data,setData]=useState(null),[error,setError]=useState('');
 useEffect(()=>{let active=true;setData(null);setError('');getSharingMonitor({page,size:20,status}).then(d=>{if(active)setData(d);}).catch(()=>{if(active)setError('Sharing monitoring unavailable.');});return()=>{active=false;};},[page,status]);
 return <section className="panel sharing-monitor"><div className="panel-heading"><div><h2>Sharing activity</h2><p>Account and access metadata only. Failed attempts and permission changes remain in the security audit below.</p></div></div>
 <label>Share status<select value={status} onChange={e=>{setStatus(e.target.value);setPage(0);}}>{['ALL','ACTIVE','EXPIRED','REVOKED'].map(s=><option key={s}>{s}</option>)}</select></label>
 {error&&<p role="alert">{error}</p>}<div className="audit-table-wrap"><table className="data-table"><thead><tr><th>Sender</th><th>Recipient</th><th>Permission / status</th><th>Created / expiry</th></tr></thead><tbody>{data?.items.map(s=><tr key={s.id}><td>{s.sender}</td><td>{s.recipient}</td><td>{s.permission} · {s.status}</td><td>{new Date(s.createdAt).toLocaleString()} / {s.expiresAt?new Date(s.expiresAt).toLocaleString():'No expiry'}</td></tr>)}</tbody></table></div>
 {data?.total===0&&<p>No matching shares recorded.</p>}<button disabled={!data||page===0} onClick={()=>setPage(page-1)}>Previous shares</button><button disabled={!data||(page+1)*20>=data.total} onClick={()=>setPage(page+1)}>Next shares</button>
 </section>;
}
