import React,{useEffect,useRef,useState} from 'react';
import {getStoredAuth} from '../services/api';
export default function AdminWorkspace({onSignedOut}){
 const frame=useRef(null),[error,setError]=useState('');
 const origin=`${window.location.protocol}//${window.location.hostname}:3001`;
 useEffect(()=>{
  const timer=setTimeout(()=>setError('Admin Console connection is taking longer than expected. Check that its Vite server is running on port 3001.'),12000);
  function receive(event){
   if(event.origin!==origin||event.source!==frame.current?.contentWindow)return;
   if(event.data?.type==='securevault:ready'&&typeof event.data.nonce==='string'){
    const token=getStoredAuth()?.token;if(token)event.source.postMessage({type:'securevault:session',nonce:event.data.nonce,token},origin);
   }
   if(event.data?.type==='securevault:verified'){clearTimeout(timer);setError('');}
   if(event.data?.type==='securevault:signed-out')onSignedOut();
   if(event.data?.type==='securevault:rejected'){clearTimeout(timer);setError('The backend could not verify administrator access. Refresh your workspace identity.');}
  }
  window.addEventListener('message',receive);return()=>{clearTimeout(timer);window.removeEventListener('message',receive);};
 },[origin,onSignedOut]);
 return <section className="admin-workspace-frame">{error&&<p role="alert" className="workspace-alert">{error}</p>}<iframe ref={frame} src={`${origin}/?workspace=embedded`} title="SecureVault Admin Console" referrerPolicy="origin"/></section>;
}
