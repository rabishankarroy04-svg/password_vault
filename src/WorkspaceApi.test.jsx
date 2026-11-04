import {afterEach,expect,test,vi} from 'vitest';
import {vaultRequest} from '../frontend/src/services/vaultApi';
vi.mock('../frontend/src/services/api',()=>({getStoredAuth:()=>({token:'fixture-only'})}));
afterEach(()=>vi.unstubAllGlobals());
test.each([[404,/activation/],[401,/Verification/],[500,/schema/],[503,/encryption/]])('API HTTP %s returns useful safe diagnostics',async(status,message)=>{
 vi.stubGlobal('fetch',vi.fn().mockResolvedValue({ok:false,status,json:async()=>({error:'synthetic-private-error-value'})}));
 await expect(vaultRequest('/vault/overview')).rejects.toThrow(message);
 try{await vaultRequest('/vault/overview');}catch(e){expect(e.status).toBe(status);expect(e.message).not.toContain('synthetic-private-error-value');}
});
