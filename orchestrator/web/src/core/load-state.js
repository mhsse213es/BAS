// Failed / forbidden / empty are three different things and must never look alike.
//
// apicall() resolves with the parsed body whatever the HTTP status, so a 500 or 403 arrives as
// `{ error: '...' }` where pages expect an array. Pages that did `list || []` then either crashed
// (`.filter is not a function`) or drew "No X yet" for a request that actually failed. apicall now tags
// non-2xx bodies with a non-enumerable `httpStatus`; failureOf() reads it.
import { x } from './escape.js';
import { on } from './actions.js';

// null when the response is usable; otherwise { kind: 'forbidden' | 'error', status }.
export function failureOf(res) {
  if (!res || typeof res !== 'object' || Array.isArray(res)) return null;
  var s = res.httpStatus;
  if (typeof s !== 'number' || s < 400) return null;
  return { kind: s === 403 ? 'forbidden' : 'error', status: s };
}

// The array inside a list response ([] / { items: [] }), or null when the shape is wrong.
export function listOf(res) {
  if (Array.isArray(res)) return res;
  if (res && Array.isArray(res.items)) return res.items;
  return null;
}

// what: lower-case noun phrase ("findings"). retryAction: a registered ACTIONS name, optional.
export function failureHtml(what, f, retryAction) {
  var forbidden = f && f.kind === 'forbidden';
  var title = forbidden ? 'You do not have permission to view ' + what : 'Could not load ' + what;
  var sub = forbidden
    ? 'Your role does not include access to this data. Ask an administrator if you need it.'
    : 'The server returned an error' + (f && f.status ? ' (HTTP ' + f.status + ')' : '') + '. This is a failed request, not an empty result. Try again.';
  return '<div class="rk-empty rk-failed ' + (forbidden ? 'is-forbidden' : 'is-error') + '" role="alert"><b>' + x(title) + '</b><div>' + x(sub) + '</div>' +
    (retryAction ? '<button type="button" class="btn btn-outline btn-sm"' + on('click', retryAction) + '>Retry</button>' : '') + '</div>';
}
