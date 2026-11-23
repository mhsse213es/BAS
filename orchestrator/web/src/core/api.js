import { doLogout } from '../features/shell.js';


export function apicall(path, opts) {
  opts = opts || {};
  return fetch(path, Object.assign({ credentials: 'same-origin' }, opts, {
    headers: Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {})
  }))
  .then(function(r) {
    if (r.status === 401) { doLogout(); throw new Error('Session expired'); }
    return r.json().then(function(body) {
      // Tag failures so callers can tell "failed" from "empty" without changing what they receive.
      if (r.status >= 400 && body && typeof body === 'object' && !Array.isArray(body)) {
        Object.defineProperty(body, 'httpStatus', { value: r.status });
      }
      return body;
    });
  });
}

// apicallOk: apicall hands a server error back as a plain { error } body instead of throwing, which makes a failed
// load read as an empty page and a refused action read as a success. This raises it instead.
export function apicallOk(path, opts) {
  return apicall(path, opts).then(function(r) {
    if (r && !Array.isArray(r) && typeof r === 'object' && typeof r.error === 'string' && r.error) throw new Error(r.error);
    return r;
  });
}
