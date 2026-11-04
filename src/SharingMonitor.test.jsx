import React from 'react';
import {afterEach,expect,test,vi} from 'vitest';
import {render,screen,cleanup} from '@testing-library/react';
import SharingMonitor from './SharingMonitor';
import {getSharingMonitor} from './adminApi';
vi.mock('./adminApi',()=>({getSharingMonitor:vi.fn()}));
afterEach(()=>{cleanup();vi.clearAllMocks();});
test('admin sharing monitor renders actual sender, recipient and permission metadata',async()=>{
 getSharingMonitor.mockResolvedValue({items:[{id:'fixture',sender:'fixture-owner',recipient:'fixture-recipient',permission:'VIEW',status:'ACTIVE',createdAt:'2026-11-03T00:00:00Z'}],total:1});
 render(<SharingMonitor/>);expect(await screen.findByText('fixture-recipient')).toBeInTheDocument();expect(screen.getByText('VIEW · ACTIVE')).toBeInTheDocument();expect(screen.getByRole('button',{name:'Next shares'})).toBeDisabled();
});
