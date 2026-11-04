import {afterEach,expect,test,vi} from 'vitest';
import {trustedWorkspaceMessage} from './workspaceBridge';
import {acceptWorkspaceSession} from './adminApi';
afterEach(()=>{vi.unstubAllGlobals();sessionStorage.clear();});
test('session handoff requires the expected window, exact origin and fresh nonce',()=>{
 const parent={},origin='http://127.0.0.1:3000',nonce='fixture-nonce',event={source:parent,origin,data:{type:'securevault:session',nonce}};
 expect(trustedWorkspaceMessage(event,parent,origin,nonce)).toBe(true);
 expect(trustedWorkspaceMessage({...event,origin:'http://untrusted.invalid'},parent,origin,nonce)).toBe(false);
 expect(trustedWorkspaceMessage({...event,source:{}},parent,origin,nonce)).toBe(false);
 expect(trustedWorkspaceMessage(event,parent,origin,'different-nonce')).toBe(false);
});
test('admin bridge stores a session only after backend administrator verification',async()=>{
 vi.stubGlobal('fetch',vi.fn().mockResolvedValue({ok:true,status:200,json:async()=>({username:'fixture',role:'ROLE_USER'})}));
 await expect(acceptWorkspaceSession('synthetic-fixture-token')).rejects.toThrow(/Administrator/);expect(sessionStorage.getItem('securevault_admin_jwt')).toBeNull();
 fetch.mockResolvedValue({ok:true,status:200,json:async()=>({username:'fixture',role:'ROLE_ADMIN'})});
 await acceptWorkspaceSession('synthetic-fixture-token');expect(sessionStorage.getItem('securevault_admin_jwt')==='synthetic-fixture-token').toBe(true);
});
