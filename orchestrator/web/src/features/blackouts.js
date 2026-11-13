// Change-freeze (blackout) windows panel on the Scheduled Assessments page. Lists GET /api/scheduled-blackouts,
// adds POST /api/scheduled-blackouts, removes DELETE /api/scheduled-blackouts/{id}. A scheduled assessment whose
// time falls inside a window is skipped, not run late. The form is checked by blackout-model.js before it is sent;
// the server checks it again and stays the authority.
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { showToast } from '../core/util.js';
import { ROLE } from './shell.js';
import { blackoutFormToPayload, describeBlackout } from './blackout-model.js';

var BLK = { list: [], error: '' };

// Only the roles the server lets create and remove windows (CanExecuteRemediation) see the form.
function canManage() {
  return ROLE === 'admin' || ROLE === 'analyst';
}

export function loadBlackouts() {
  apicall('/api/scheduled-blackouts').then(function(d) {
    if (d && d.error) {
      BLK.error = d.error;
    } else {
      BLK.list = (d && d.blackouts) || [];
      BLK.error = '';
    }
    renderBlackouts();
  }).catch(function(e) {
    BLK.error = e.message;
    renderBlackouts();
  });
}

function renderBlackouts() {
  var body = document.getElementById('blk-body');
  var form = document.getElementById('blk-form');
  if (form) form.hidden = !canManage();
  if (!body) return;
  if (BLK.error) {
    body.innerHTML = '<p class="sub2">Could not load change-freeze windows: ' + x(BLK.error) + '</p>';
    return;
  }
  if (!BLK.list.length) {
    body.innerHTML = '<p class="sub2">No change-freeze windows. Scheduled assessments run as they are set.</p>';
    return;
  }
  body.innerHTML = '<div class="tbl-wrap"><table><thead><tr><th>Name</th><th>When</th><th>Created by</th><th></th></tr></thead><tbody>' +
    BLK.list.map(function(b) {
      var action = canManage()
        ? '<button type="button" class="btn btn-outline btn-sm"' + on('click', 'blackoutDelete', b.ID) + '>Remove</button>'
        : '';
      return '<tr><td>' + x(b.Name) + '</td><td>' + x(describeBlackout(b)) + '</td><td>' +
        x(b.CreatedBy || '') + '</td><td>' + action + '</td></tr>';
    }).join('') + '</tbody></table></div>';
}

function fieldValue(id) {
  var el = document.getElementById(id);
  return el ? el.value : '';
}

function readForm() {
  return {
    name: fieldValue('blk-name'), kind: fieldValue('blk-kind'),
    startsAt: fieldValue('blk-starts'), endsAt: fieldValue('blk-ends'),
    timeFrom: fieldValue('blk-from'), timeTo: fieldValue('blk-to'), timezone: fieldValue('blk-tz'),
    validFrom: fieldValue('blk-vfrom'), validTo: fieldValue('blk-vto')
  };
}

// Shows the fields for the chosen kind. Called by the kind <select> on change.
export function blackoutKindChange(el) {
  var daily = el && el.value === 'daily';
  var once = document.getElementById('blk-once-fields');
  var dailyFields = document.getElementById('blk-daily-fields');
  if (once) once.hidden = daily;
  if (dailyFields) dailyFields.hidden = !daily;
}

export function blackoutCreate() {
  var err = document.getElementById('blk-err');
  var checked = blackoutFormToPayload(readForm());
  if (!checked.payload) {
    if (err) err.textContent = checked.error;
    return;
  }
  if (err) err.textContent = '';
  apicall('/api/scheduled-blackouts', { method: 'POST', body: JSON.stringify(checked.payload) }).then(function(d) {
    if (d && d.error) {
      if (err) err.textContent = d.error;
      return;
    }
    var name = document.getElementById('blk-name');
    if (name) name.value = '';
    showToast('Change-freeze window added', 'ok');
    loadBlackouts();
  }).catch(function(e) {
    if (err) err.textContent = e.message;
  });
}

export function blackoutDelete(id) {
  if (!confirm('Remove this change-freeze window? Scheduled assessments will start inside its time again.')) return;
  apicall('/api/scheduled-blackouts/' + encodeURIComponent(id), { method: 'DELETE' }).then(function(res) {
    if (res && res.error) {
      showToast(res.error, 'err');
      return;
    }
    showToast('Change-freeze window removed', 'ok');
    loadBlackouts();
  }).catch(function(e) { showToast(e.message, 'err'); });
}
