const groups = { lowercase: 'abcdefghijklmnopqrstuvwxyz', uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', numbers: '0123456789', symbols: '!@#$%^&*()_+-=[]{}:,.?' };
function randomIndex(size) {
  const cutoff = 256 - (256 % size), bytes = new Uint8Array(1);
  do { globalThis.crypto.getRandomValues(bytes); } while (bytes[0] >= cutoff);
  return bytes[0] % size;
}
export function generatePassword(length = 20, options = { lowercase: true, uppercase: true, numbers: true, symbols: true }) {
  if (!Number.isInteger(length) || length < 12 || length > 128) throw new Error('Choose a length from 12 to 128.');
  const selected = Object.entries(groups).filter(([key]) => options[key]).map(([, value]) => value);
  if (!selected.length) throw new Error('Select at least one character group.');
  const alphabet = selected.join('');
  const result = selected.map(group => group[randomIndex(group.length)]);
  while (result.length < length) result.push(alphabet[randomIndex(alphabet.length)]);
  for (let i = result.length - 1; i > 0; i--) { const j = randomIndex(i + 1); [result[i], result[j]] = [result[j], result[i]]; }
  return result.join('');
}
export function assessPassword(value = '') {
  const count = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter(pattern => pattern.test(value)).length;
  const guessed = !value || /^(.)\1{3,}$/.test(value) || ['password', '123456', 'qwerty', 'letmein', 'iloveyou', 'welcome', 'admin'].some(word => value.toLowerCase().includes(word));
  const score = guessed ? Math.min(15, value.length) : Math.min(100, Math.min(60, value.length * 3) + count * 10);
  const suggestions = [];
  if (value.length < 16) suggestions.push('Use at least 16 characters; longer unique passwords are preferable.');
  if (guessed) suggestions.push('Avoid common passwords, sequences and repeated characters.');
  if (count < 3) suggestions.push('Consider a longer random password or varied character groups.');
  suggestions.push('Use a unique password for each account. This is not a breach check.');
  return { score, strength: score < 20 ? 'Very Weak' : score < 40 ? 'Weak' : score < 70 ? 'Moderate' : score < 90 ? 'Strong' : 'Very Strong', suggestions };
}
