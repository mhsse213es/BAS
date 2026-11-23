import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { showToast } from '../core/util.js';
import { pill } from '../core/kit.js';
import { describeRotation } from './ca-rotation-model.js';

// CA rotation card (audit F-09), read-only. It shows where a planned CA rotation stands and which agents are
// holding it up; the steps themselves (start, promote, retire) stay on the server's command line because each
// one changes how the whole fleet is trusted. The numbers are the server's; nothing is computed here.

export function renderCARotation(d) {
  var el = document.getElementById('ca-rotation-body');
  if (!el) return;
  var html = '<p class="conn-cfg-hint">' + x(d.headline) + '</p>';
  if (d.progress) {
    var tone = d.ready ? 'ok' : 'warn';
    html += '<div class="conn-cfg-row"><span class="conn-cfg-label">' + x(d.progress.done + ' of ' + d.progress.total + ' agents ' + d.progress.label) + '</span> ' +
      pill(d.ready ? 'Ready to ' + d.step : 'Not ready to ' + d.step, tone) + '</div>';
    if (d.pending.length) {
      html += '<div class="conn-cfg-row"><span class="conn-cfg-label">Still pending</span><span class="conn-cfg-val">' +
        d.pending.map(function(id) { return '<code>' + x(id) + '</code>'; }).join(', ') + '</span></div>';
    }
  }
  if (d.next) html += '<p class="conn-cfg-hint">' + x(d.next) + '</p>';
  el.innerHTML = html;
}

export function loadCARotation() {
  var el = document.getElementById('ca-rotation-body');
  if (!el) return Promise.resolve(false);
  return apicall('/api/ca-rotation/status').then(function(r) {
    var d = describeRotation(r);
    renderCARotation(d);
    return d.state !== 'unavailable';
  }).catch(function() {
    renderCARotation(describeRotation(null));
    return false;
  });
}

export function refreshCARotation() {
  var btn = document.getElementById('ca-rotation-refresh');
  if (btn) btn.disabled = true;
  loadCARotation().then(function(ok) {
    showToast(ok ? 'CA rotation status refreshed' : 'CA rotation status is not available', ok ? 'ok' : 'warn');
  }).then(function() { if (btn) btn.disabled = false; });
}
