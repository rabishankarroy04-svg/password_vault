export const SESSION_INVALID = 'securevault:session-invalid';
// Ignore late responses belonging to a previous login. Never clear preferences or vault data.
export function invalidateSession(token) {
  if (!token || sessionStorage.getItem('securevault_jwt') !== token) return;
  sessionStorage.removeItem('securevault_jwt');
  sessionStorage.removeItem('securevault_user');
  window.dispatchEvent(new Event(SESSION_INVALID));
}
export function isInvalidSession(status, code) {
  return status === 401 && ['UNAUTHENTICATED', 'SESSION_REVOKED'].includes(code);
}
