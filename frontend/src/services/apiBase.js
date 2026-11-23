export function getApiBase() {
  let raw = (import.meta.env.VITE_API_BASE_URL || '').trim();
  if (!raw) return '';
  // If the host is an internal unqualified hostname (e.g. from Render fromService without a dot), append .onrender.com
  if (!raw.includes('.')) {
    raw = `${raw}.onrender.com`;
  }
  return (raw.startsWith('http://') || raw.startsWith('https://') ? raw : `https://${raw}`).replace(/\/+$/, '');
}

export function buildApiUrl(path) {
  if (path.startsWith('http://') || path.startsWith('https://')) return path;
  const base = getApiBase();
  const normalized = path.startsWith('/') ? path : `/${path}`;
  return base ? `${base}${normalized}` : normalized;
}
