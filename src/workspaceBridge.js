// Separate applications keep their React/CSS runtimes. Tokens are never placed in URLs or localStorage.
export const trustedWorkspaceMessage=(event,parent,origin,nonce)=>event.source===parent&&event.origin===origin&&event.data?.type==='securevault:session'&&event.data.nonce===nonce;
export function installWorkspaceBridge(verify,accept,reject){
 if(window.parent===window)return()=>{};
 let parentOrigin;
 try{parentOrigin=new URL(document.referrer).origin;}catch{return()=>{};}
 const allowed=new Set(['http://127.0.0.1:3000','http://localhost:3000']);
 if(!allowed.has(parentOrigin))return()=>{};
 const nonce=crypto.randomUUID();let busy=false,active=true;
 const receive=async event=>{
  if(!trustedWorkspaceMessage(event,window.parent,parentOrigin,nonce)||busy)return;
  if(typeof event.data.token!=='string'||event.data.token.length>4096)return;
  busy=true;
  try{const identity=await verify(event.data.token);if(active){accept(identity);window.parent.postMessage({type:'securevault:verified'},parentOrigin);}}
  catch{if(active){reject();window.parent.postMessage({type:'securevault:rejected'},parentOrigin);}}
 };
 window.addEventListener('message',receive);window.parent.postMessage({type:'securevault:ready',nonce},parentOrigin);
 return()=>{active=false;window.removeEventListener('message',receive);};
}
export function notifyWorkspaceSignOut(){
 if(window.parent===window)return;
 try{const origin=new URL(document.referrer).origin;if(['http://127.0.0.1:3000','http://localhost:3000'].includes(origin))window.parent.postMessage({type:'securevault:signed-out'},origin);}catch{}
}
