import React from 'react';
import {afterEach,expect,test,vi} from 'vitest';
import {render,screen,cleanup,act} from '@testing-library/react';
import App from '../frontend/src/App';
import {vaultRequest} from '../frontend/src/services/vaultApi';
import {invalidateSession} from '../frontend/src/services/session';
vi.mock('../frontend/src/components/UserDashboard',()=>({default:()=> <div>Authenticated workspace</div>}));
vi.mock('../frontend/src/components/AdminWorkspace',()=>({default:()=> <div>Admin workspace</div>}));
vi.mock('../frontend/src/components/Login',()=>({default:()=> <div>Existing login flow</div>}));
vi.mock('../frontend/src/components/Register',()=>({default:()=>null}));
afterEach(()=>{cleanup();sessionStorage.clear();localStorage.clear();vi.unstubAllGlobals();});
function auth(){sessionStorage.setItem('securevault_jwt','fixture-session');sessionStorage.setItem('securevault_user',JSON.stringify({username:'fixture'}));}
function response(status,code){vi.stubGlobal('fetch',vi.fn().mockResolvedValue({ok:status===200,status,json:async()=>status===200?{username:'fixture',roles:['ROLE_USER']}:{code}}));}
test.each(['UNAUTHENTICATED','SESSION_REVOKED'])('explicit %s removes only matching auth state and returns to login',async code=>{
 auth();localStorage.setItem('securevault_vault_theme','light');sessionStorage.setItem('other-setting','preserved');response(200);render(<App/>);
 expect(await screen.findByText('Authenticated workspace')).toBeInTheDocument();response(401,code);
 await act(async()=>{await vaultRequest('/notifications/unread').catch(()=>{});});
 expect(screen.getByText('Existing login flow')).toBeInTheDocument();expect(screen.queryByText('Authenticated workspace')).not.toBeInTheDocument();
 expect(sessionStorage.getItem('securevault_jwt')).toBeNull();expect(sessionStorage.getItem('other-setting')).toBe('preserved');expect(localStorage.getItem('securevault_vault_theme')).toBe('light');
});
test.each([[503,undefined],[403,undefined],[401,undefined],[401,'VERIFICATION_FAILED']])('HTTP %s without session-invalid code preserves login',async(status,code)=>{
 auth();response(status,code);await vaultRequest('/notifications/unread').catch(()=>{});expect(sessionStorage.getItem('securevault_jwt')).toBe('fixture-session');
});
test('network failure preserves login',async()=>{auth();vi.stubGlobal('fetch',vi.fn().mockRejectedValue(new TypeError('Network unavailable')));await vaultRequest('/notifications/unread').catch(()=>{});expect(sessionStorage.getItem('securevault_jwt')).toBe('fixture-session');});
test('late response cannot clear a newer session',()=>{auth();invalidateSession('previous-fixture-session');expect(sessionStorage.getItem('securevault_jwt')).toBe('fixture-session');});
test('expired identity verification returns to existing login',async()=>{auth();response(401,'UNAUTHENTICATED');render(<App/>);expect(await screen.findByText('Existing login flow')).toBeInTheDocument();expect(screen.queryByText('Authenticated workspace')).not.toBeInTheDocument();});
