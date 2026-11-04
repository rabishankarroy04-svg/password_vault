import {invalidateSession,isInvalidSession} from './session';
import { getStoredAuth } from './api';

export class WorkspaceApiError extends Error {
  constructor(status,code){
    const messages={401:isInvalidSession(status,code)?'Your session has expired or was revoked. Sign in again.':'Verification was not accepted. Check your details and try again.',403:'The server denied access to this operation.',404:'This workspace API is unavailable or the record is no longer accessible. The local backend may need activation.',500:'The backend could not complete this request. The operator should check its schema and server logs.',503:'This feature is not ready. Ask the operator to check vault encryption configuration and backend availability.'};
    super(messages[status]||`The request failed (HTTP ${status}). Retry or contact your project administrator.`);
    this.name='WorkspaceApiError';this.status=status;this.code=code;
  }
}

export async function vaultRequest(path, options = {}) {
  const token = getStoredAuth()?.token;
  if (!token) { window.dispatchEvent(new Event('securevault:session-invalid')); throw new WorkspaceApiError(401,'UNAUTHENTICATED'); }
  const response = await fetch(`/api/account${path}`, {
    ...options, cache: 'no-store',
    headers: { Authorization: `Bearer ${token}`, ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers },
  });
  const data = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) {
    if(isInvalidSession(response.status,data?.code)) invalidateSession(token);
    const error=new WorkspaceApiError(response.status,data?.code);
    // Only expected, operator-authored validation messages are shown; never echo arbitrary server error fields.
    if([400,409,429].includes(response.status)&&typeof data?.message==='string'&&data.message.length<250)error.message=data.message;
    throw error;
  }
  return data;
}
export const vaultApi = {
  overview: () => vaultRequest('/vault/overview'),
  assess: (password, excludedId) => vaultRequest('/vault/password-health', { method:'POST',body:JSON.stringify({password,excludedId}) }),
  categories: () => vaultRequest('/vault/categories'),
  category: (name) => vaultRequest('/vault/categories', { method: 'POST', body: JSON.stringify({ name }) }),
  list: ({ search = '', category = '', sort = 'NEWEST', favorites = false } = {}) =>
    vaultRequest(`/vault/credentials?${new URLSearchParams({ search, category, sort, favorites })}`),
  read: id => vaultRequest(`/vault/credentials/${encodeURIComponent(id)}`),
  save: (id, data) => vaultRequest(`/vault/credentials${id ? `/${encodeURIComponent(id)}` : ''}`, { method: id ? 'PUT' : 'POST', body: JSON.stringify(data) }),
  remove: id => vaultRequest(`/vault/credentials/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  favorite: (id, favorite) => vaultRequest(`/vault/credentials/${encodeURIComponent(id)}/favorite`, { method: 'PATCH', body: JSON.stringify({ favorite }) }),
};
