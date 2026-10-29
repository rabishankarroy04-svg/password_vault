import React from 'react';
import { beforeEach, afterEach, expect, test, vi } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import { DeviceContext, RuleContext, AuditBrowser, RangeBreakdown } from './ThreatContext';
import { getActivities } from './adminApi';
vi.mock('./adminApi', () => ({ getActivities: vi.fn() }));
beforeEach(()=>{vi.clearAllMocks();getActivities.mockResolvedValue({items:[],page:0,size:10,total:0});});
afterEach(cleanup);
test('device metadata is coarse and missing location is explicitly unavailable',()=>{
 render(<DeviceContext context={{category:'Mobile',os:'Android',browser:'Chrome',deviceStatus:'New'}}/>);
 expect(screen.getByText(/Mobile.*Android.*Chrome/)).toBeInTheDocument();expect(screen.getByText('Location unavailable')).toBeInTheDocument();
});
test('reliable configured location is approximate and no exact physical device is invented',()=>{
 render(<DeviceContext context={{locationAvailable:true,country:'US',region:'TestRegion',locationSource:'Isolated fixture'}}/>);
 expect(screen.getByText(/approximate, Isolated fixture/)).toBeInTheDocument();expect(screen.queryByText(/physical model|owner:/)).not.toBeInTheDocument();
});
test('legacy explanation does not substitute current settings for historical thresholds',()=>{
 render(<RuleContext/>);expect(screen.getByText(/Historical configuration is unavailable/)).toBeInTheDocument();expect(screen.queryByText(/Threshold: 4/)).not.toBeInTheDocument();
});
test('stored thresholds, factors and escalation explanation are shown',()=>{
 render(<RuleContext context={{riskFactors:['NEW_DEVICE_LOGIN','NEW_IP_LOGIN'],eventCount:1,threshold:25,windowMinutes:15,severityReason:'HIGH due to combined signals',suggestedAction:'Verify owner activity'}}/>);
 expect(screen.getByText(/NEW_DEVICE_LOGIN, NEW_IP_LOGIN/)).toBeInTheDocument();expect(screen.getByText(/Threshold: 25/)).toBeInTheDocument();expect(screen.getByText('HIGH due to combined signals')).toBeInTheDocument();
});
test('audit query uses selected dates, exact type, sort and bounded pagination',async()=>{
 getActivities.mockResolvedValue({items:[],page:0,size:10,total:21});render(<AuditBrowser from="2026-10-01" to="2026-10-30"/>);
 await waitFor(()=>expect(getActivities).toHaveBeenCalledWith(expect.objectContaining({from:'2026-10-01',to:'2026-10-30',page:0,size:10})));
 fireEvent.change(screen.getByLabelText('Audit event type'),{target:{value:'LOGIN_FAILURE'}});
 await waitFor(()=>expect(getActivities).toHaveBeenLastCalledWith(expect.objectContaining({type:'LOGIN_FAILURE',page:0})));
 fireEvent.change(screen.getByLabelText('Audit order'),{target:{value:'OLDEST'}});
 await waitFor(()=>expect(getActivities).toHaveBeenLastCalledWith(expect.objectContaining({sort:'OLDEST'})));
 await waitFor(()=>expect(screen.getByRole('button',{name:'Next audit page'})).not.toBeDisabled());fireEvent.click(screen.getByRole('button',{name:'Next audit page'}));
 await waitFor(()=>expect(getActivities).toHaveBeenLastCalledWith(expect.objectContaining({page:1})));
 fireEvent.change(screen.getByLabelText('Search security audit'),{target:{value:'alice'}});
 await waitFor(()=>expect(getActivities).toHaveBeenLastCalledWith(expect.objectContaining({search:'alice',page:0})));
});
test('unavailable audit data is an error rather than a claim of zero incidents',async()=>{
 getActivities.mockRejectedValue(new Error('offline'));render(<AuditBrowser from="2026-10-01" to="2026-10-30"/>);
 expect(await screen.findByRole('alert')).toHaveTextContent('Missing monitoring data is not zero activity');expect(screen.queryByText('No audit events match these filters.')).not.toBeInTheDocument();
});
test('audit results display failure, device and source without treating all activity as threats',async()=>{
 getActivities.mockResolvedValue({items:[{id:'fixture-id',action:'Login failure',name:'Fixture user',device:'IP 172.21.0.1',time:'2026-10-30T00:00:00Z',status:'Review',metadata:{os:'Linux',browser:'Firefox'}}],total:1});
 render(<AuditBrowser from="2026-10-01" to="2026-10-30"/>);expect(await screen.findByText('Fixture user')).toBeInTheDocument();expect(screen.getByText(/Audit activity is not automatically a threat/)).toBeInTheDocument();expect(screen.getByText('IP 172.21.0.1')).toBeInTheDocument();
});
test('range breakdown uses backend totals and missing metrics remain unavailable',()=>{
 const {rerender}=render(<RangeBreakdown/>);expect(screen.getByText(/breakdown unavailable/)).toBeInTheDocument();
 rerender(<RangeBreakdown metrics={{successfulLogins:8,failedLogins:4,newDeviceActivity:1,deniedRequests:5,byThreatType:{COMBINED_LOGIN_RISK:1},byStatus:{OPEN:1}}}/>);
 expect(screen.getByText('Successful logins').closest('article')).toHaveTextContent('8');expect(screen.getByRole('meter',{name:'COMBINED_LOGIN_RISK'})).toHaveAttribute('value','1');
});

test('audit pagination shows page totals and accessible boundary states', async () => {
 getActivities.mockResolvedValue({items:[],size:10,total:21});
 render(<AuditBrowser from="2026-10-01" to="2026-10-30"/>);
 expect(await screen.findByText('Page 1 of 3')).toBeInTheDocument();
 expect(screen.getByText('21 matching events')).toBeInTheDocument();
 const previous=screen.getByRole('button',{name:'Previous audit page'});
 const next=screen.getByRole('button',{name:'Next audit page'});
 expect(previous).toBeDisabled();expect(next).toBeEnabled();
 fireEvent.click(next);expect(await screen.findByText('Page 2 of 3')).toBeInTheDocument();
 expect(previous).toBeEnabled();fireEvent.click(next);
 expect(await screen.findByText('Page 3 of 3')).toBeInTheDocument();expect(next).toBeDisabled();
 fireEvent.click(previous);expect(await screen.findByText('Page 2 of 3')).toBeInTheDocument();
 expect(screen.getByRole('navigation',{name:'Authentication audit pagination'})).toBeInTheDocument();
});
test('empty audit has a stable single-page summary and disabled navigation',async()=>{
 render(<AuditBrowser from="2026-10-01" to="2026-10-30"/>);
 expect(await screen.findByText('Page 1 of 1')).toBeInTheDocument();
 expect(screen.getByText('0 matching events')).toBeInTheDocument();
 expect(screen.getByRole('button',{name:'Previous audit page'})).toBeDisabled();
 expect(screen.getByRole('button',{name:'Next audit page'})).toBeDisabled();
});
test('long explanations are collapsed details and historical metadata stays Unknown',async()=>{
 const explanation='Long stored explanation: investigate this signal with the owner before drawing conclusions.';
 getActivities.mockResolvedValue({items:[{id:'historical-fixture',action:'Login',name:'Historical user',device:'IP 172.21.0.1',time:'2026-10-30T00:00:00Z',status:'Success',details:'Historical audit record',metadata:{riskLevel:'LOW',riskReason:explanation}}],size:10,total:1});
 render(<AuditBrowser from="2026-10-01" to="2026-10-30"/>);
 expect(await screen.findByText('Historical user')).toBeInTheDocument();
 const summary=screen.getByText('Details');const details=summary.closest('details');
 expect(details).not.toHaveAttribute('open');
 expect(screen.getByText(explanation).closest('details')).toBe(details);
 fireEvent.click(summary);expect(details).toHaveAttribute('open');
 expect(screen.getAllByText('Unknown').length).toBeGreaterThanOrEqual(3);
 expect(screen.getByText('Risk: LOW')).toBeInTheDocument();
 expect(screen.getByText('Audit activity')).toBeInTheDocument();
 expect(screen.getByText('IP 172.21.0.1').closest('td').querySelector('time')).toHaveAttribute('datetime','2026-10-30T00:00:00.000Z');
});

test('investigation meters retain actual counts and status hooks without changing other breakdowns',()=>{
 render(<RangeBreakdown metrics={{successfulLogins:2,failedLogins:1,newDeviceActivity:0,deniedRequests:0,byThreatType:{NEW_DEVICE_LOGIN:2},byStatus:{OPEN:4,INVESTIGATING:2,RESOLVED:1,FALSE_POSITIVE:0}}}/>);
 for(const [status,count] of Object.entries({OPEN:4,INVESTIGATING:2,RESOLVED:1,FALSE_POSITIVE:0})) {
  const meter=screen.getByRole('meter',{name:status});
  expect(meter).toHaveAttribute('value',String(count));
  expect(meter).toHaveAttribute('aria-valuetext',`${count} investigations`);
  expect(meter.closest('.threat-breakdown-row')).toHaveAttribute('data-status',status);
 }
 expect(screen.getByRole('meter',{name:'NEW_DEVICE_LOGIN'}).closest('article')).not.toHaveClass('investigation-status-breakdown');
});

test('selected-range section reuses compact dashboard headings and metric cards with unchanged totals',()=>{
 render(<RangeBreakdown metrics={{successfulLogins:25,failedLogins:1,newDeviceActivity:0,deniedRequests:0,byThreatType:{ACCESS_DENIED:29},byStatus:{OPEN:34}}}/>);
 const heading=screen.getByRole('heading',{name:'Selected-range activity and investigation patterns'});
 expect(heading.closest('.panel-heading')).not.toBeNull();
 expect(heading.closest('section')).toHaveClass('range-patterns');
 expect(screen.getByText('Successful logins').closest('article')).toHaveTextContent('25');
 expect(screen.getByRole('meter',{name:'ACCESS_DENIED'})).toHaveAttribute('value','29');
 expect(screen.getByRole('meter',{name:'OPEN'})).toHaveAttribute('value','34');
});
test('audit search uses the shared dashboard search control and keeps its existing request behavior',async()=>{
 render(<AuditBrowser from="2026-10-01" to="2026-10-30"/>);
 const input=screen.getByLabelText('Search security audit');
 expect(input.closest('.table-search')).toHaveClass('audit-search-control');
 fireEvent.change(input,{target:{value:'Login'}});
 await waitFor(()=>expect(getActivities).toHaveBeenLastCalledWith(expect.objectContaining({search:'Login',page:0})));
});
