import React from 'react';
import {afterEach,expect,test,vi} from 'vitest';
import {render,screen,fireEvent,cleanup} from '@testing-library/react';
import App from '../frontend/src/App';
import {vaultRequest} from '../frontend/src/services/vaultApi';
vi.mock('../frontend/src/services/api',()=>({getStoredAuth:()=>({token:'fixture-only',user:{username:'saved-user',roles:['ROLE_ADMIN']}}),logoutUser:vi.fn()}));
vi.mock('../frontend/src/services/vaultApi',()=>({vaultRequest:vi.fn()}));
vi.mock('../frontend/src/components/UserDashboard',()=>({default:()=> <div>Verified user workspace</div>}));
vi.mock('../frontend/src/components/AdminWorkspace',()=>({default:()=> <div>Verified admin workspace</div>}));
vi.mock('../frontend/src/components/Login',()=>({default:()=>null}));
vi.mock('../frontend/src/components/Register',()=>({default:()=>null}));
afterEach(()=>{cleanup();vi.clearAllMocks();});
test('saved frontend admin claims cannot grant an admin workspace',async()=>{
 vaultRequest.mockResolvedValue({username:'verified-user',roles:['ROLE_USER']});render(<App/>);
 expect(await screen.findByText('Verified user workspace')).toBeInTheDocument();expect(screen.queryByText('Verified admin workspace')).not.toBeInTheDocument();expect(screen.queryByRole('button',{name:/Switch Workspace/})).not.toBeInTheDocument();
});
test('dual-role accounts can switch only after rechecking backend identity',async()=>{
 vaultRequest.mockResolvedValue({username:'verified-admin',roles:['ROLE_USER','ROLE_ADMIN']});render(<App/>);
 expect(await screen.findByText('Verified admin workspace')).toBeInTheDocument();fireEvent.click(screen.getByRole('button',{name:/Switch Workspace/}));
 expect(await screen.findByText('Verified user workspace')).toBeInTheDocument();expect(vaultRequest).toHaveBeenCalledTimes(2);
});
test('unavailable role verification fails closed without rendering a privileged workspace',async()=>{
 vaultRequest.mockRejectedValue(new Error('Backend activation required.'));render(<App/>);
 expect(await screen.findByRole('heading',{name:'Workspace verification unavailable'})).toBeInTheDocument();expect(screen.queryByText('Verified admin workspace')).not.toBeInTheDocument();
});
