export function getApiBase() {
  const raw = import.meta.env.VITE_API_BASE_URL || '';
  if (!raw) return '';
  return (raw.startsWith('http') ? raw : `https://${raw}`).replace(/\/+$/, '');
}

export function buildApiUrl(path) {
  if (path.startsWith('http://') || path.startsWith('https://')) return path;
  const base = getApiBase();
  const normalized = path.startsWith('/') ? path : `/${path}`;
  return base ? `${base}${normalized}` : normalized;
}
