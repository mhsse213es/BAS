import { doLogout } from '../features/shell.js';


export function apicall(path, opts) {
  opts = opts || {};
  return fetch(path, Object.assign({ credentials: 'same-origin' }, opts, {
    headers: Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {})
  }))
  .then(function(r) {
    if (r.status === 401) { doLogout(); throw new Error('Session expired'); }
    return r.json();
  });
}