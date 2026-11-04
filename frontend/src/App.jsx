import {SESSION_INVALID} from './services/session';
import React, {useCallback,useEffect,useState} from 'react';
import Navbar from './components/Navbar';
import Login from './components/Login';
import Register from './components/Register';
import UserDashboard from './components/UserDashboard';
import AdminWorkspace from './components/AdminWorkspace';
import {getStoredAuth,logoutUser} from './services/api';
import {vaultRequest} from './services/vaultApi';
import './App.css';
import './Workspace.css';
import './ReferenceStyle.css';

export default function App(){
 const [currentUser,setCurrentUser]=useState(null),[activeView,setActiveView]=useState('login');
 const [identity,setIdentity]=useState(null),[error,setError]=useState(''),[checking,setChecking]=useState(false);
 const handleLogout=useCallback(()=>{logoutUser();setCurrentUser(null);setIdentity(null);setActiveView('login');setError('');},[]);
 const verify=useCallback(async(preferred)=>{
  setChecking(true);setError('');setIdentity(null);
  try{const me=await vaultRequest('/me');setIdentity(me);setCurrentUser(me);
   const user=me.roles.includes('ROLE_USER'),admin=me.roles.includes('ROLE_ADMIN');
   if(preferred==='vault'&&user)setActiveView('vault');else if(admin)setActiveView('admin');else if(user)setActiveView('vault');else setError('No supported workspace role is assigned. Contact your project administrator.');
  }catch(e){setError(e.message);}finally{setChecking(false);}
 },[]);
 useEffect(()=>{window.addEventListener(SESSION_INVALID,handleLogout);return()=>window.removeEventListener(SESSION_INVALID,handleLogout);},[handleLogout]);
 useEffect(()=>{const auth=getStoredAuth();if(auth?.user){setCurrentUser(auth.user);setActiveView('verify');verify();}},[verify]);
 const signedIn=user=>{setCurrentUser(user);setActiveView('verify');verify();};
 const dual=identity?.roles?.includes('ROLE_USER')&&identity.roles.includes('ROLE_ADMIN');
 return <div className={`app-container ${currentUser?'workspace-app':''}`}>
  {!currentUser&&<Navbar activeView={activeView} setActiveView={setActiveView} currentUser={null} onLogout={handleLogout}/>}
  {currentUser&&<header className="workspace-global-header"><div className="workspace-global-actions">{dual&&<button onClick={()=>verify(activeView==='admin'?'vault':'admin')} disabled={checking}>Switch Workspace · {activeView==='admin'?'User':'Admin'}</button>}<span>{identity?.username||currentUser.username}</span><button onClick={handleLogout}>Sign out</button></div></header>}
  <main className="main-content">
   {!currentUser&&activeView==='register'?<Register onRegisterSuccess={()=>setActiveView('login')} onNavigateLogin={()=>setActiveView('login')}/>:!currentUser?<Login onLoginSuccess={signedIn} onNavigateRegister={()=>setActiveView('register')}/>:<>
    {checking?<section className="workspace-state" role="status"><h2>Verifying your workspace</h2><p>Checking your active session and current roles with SecureVault.</p></section>:error?<section className="workspace-state"><h2>Workspace verification unavailable</h2><p role="alert">{error}</p><p>No permissions have been inferred from saved browser information.</p><button onClick={()=>verify()}>Retry verification</button></section>:identity&&activeView==='admin'?<AdminWorkspace onSignedOut={handleLogout}/>:identity&&activeView==='vault'?<UserDashboard currentUser={identity} onLogout={handleLogout}/>:null}
   </>}
  </main>
 </div>;
}
