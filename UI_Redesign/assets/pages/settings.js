/* Settings — users/roles, SSO, audit log, licence, content, backup, appearance, notifications. */
(function () {
  'use strict';
  var D = window.AUD, h = UI.h, icon = UI.icon, $ = UI.$;
  var C = $('#content');
  C.append(UI.banner(), UI.pageHeader({ title: 'Settings', sub: 'Administration for this installation. Seven sections instead of ten; appearance and dashboard preferences merged.' }));

  var SECTIONS = [
    ['users', 'users', 'Users & roles'], ['sso', 'lock', 'SSO & authentication'], ['audit', 'list', 'Audit log'],
    ['licence', 'badge', 'Licence'], ['content', 'book', 'Content & updates'], ['backup', 'database', 'Backup & recovery'],
    ['appearance', 'sliders', 'Appearance'], ['notifications', 'bell', 'Notifications']
  ];
  var layout = h('div', { class: 'settings-layout' });
  var nav = h('nav', { class: 'subnav', 'aria-label': 'Settings sections' }, SECTIONS.map(function (s) {
    return h('a', { href: '#' + s[0], 'data-sec': s[0] }, icon(s[1]), s[2]);
  }));
  var pane = h('div'); layout.append(nav, pane); C.appendChild(layout);

  function sec(title, kids) { return [h('h2', { class: 'card-title', style: 'font-size:16px;margin-bottom:14px' }, title)].concat(kids); }
  var RC = { Admin: 'critical', Analyst: 'accent', Auditor: 'info', Viewer: '' };
  var VIEWS = {
    users: function () {
      return sec('Users & roles', [UI.card({ flush: true, actions: UI.btn('Invite user', { sm: true, icon: 'plus' }), title: D.users.length + ' users',
        body: h('div', { class: 'table-wrap' }, UI.table([
          { h: 'User', cls: 'cell-main', render: function (u) { return h('div', { class: 'row gap-3' }, h('span', { class: 'avatar', style: 'width:28px;height:28px;font-size:11px' }, u.name.split(' ').map(function (w) { return w[0]; }).slice(0, 2).join('')), h('div', null, h('div', { class: 't-title' }, u.name), h('div', { class: 't-sub' }, u.email))); } },
          { h: 'Role', render: function (u) { return UI.pill(RC[u.role], u.role); } },
          { h: 'MFA', render: function (u) { return u.mfa ? UI.pill('good', 'On', 'checkCircle') : UI.pill('warning', 'Off', 'alert'); } },
          { h: 'Last active', cls: 'r', render: function (u) { return h('span', { class: 'soft small nowrap' }, u.last); } }
        ], D.users)) }),
        h('p', { class: 'small muted mt-3' }, 'Roles map to the backend RBAC permission set. Admin, Analyst, Auditor and Viewer are shown; custom roles are supported.')]);
    },
    sso: function () {
      return sec('SSO & authentication', [UI.card({ title: 'Single sign-on', body: [
        h('div', { class: 'row wrap mb-4' }, UI.pill('good', 'SAML enabled', 'checkCircle'), h('span', { class: 'small soft' }, 'Azure AD · SCIM provisioning on')),
        h('div', { class: 'form-grid' },
          field('Provider', 'Azure AD (SAML 2.0)'), field('Entity ID', 'audspect-contoso'),
          field('Default role for new users', 'Viewer'), field('Session timeout', '8 hours')),
        h('hr', { class: 'sep' }),
        h('div', { class: 'row' }, h('div', null, h('div', { class: 'strong' }, 'Require MFA for local accounts'), h('div', { class: 'small muted' }, 'Applies to break-glass admins only')), h('span', { class: 'spacer' }), h('span', { class: 'toggle on' }))] })]);
    },
    audit: function () {
      return sec('Audit log', [h('div', { class: 'filter-bar' }, UI.searchBox('Search by user or action'), UI.chip('Action', 'Any'), UI.chip('User', 'Any'), h('span', { class: 'spacer' }), UI.btn('Export', { sm: true, icon: 'download' })),
        UI.card({ flush: true, body: h('div', { class: 'table-wrap' }, UI.table([
          { h: 'When', cls: 'nowrap', render: function (r) { return h('span', { class: 'soft small' }, r.t); } },
          { h: 'User', render: function (r) { return h('span', { class: 'mono small' }, r.who); } },
          { h: 'Action', render: function (r) { return h('span', { class: 'strong' }, r.action); } },
          { h: 'Detail', render: function (r) { return h('span', { class: 'soft' }, r.detail); } }
        ], D.auditLog)) }),
        h('p', { class: 'small muted mt-3' }, 'The audit log is append-only and included in the signed audit evidence pack.')]);
    },
    licence: function () {
      return sec('Licence', [h('div', { class: 'grid' },
        UI.card({ cls: 'c-7 lg-12', title: 'On-prem licence', body: [
          UI.kv([['Edition', 'Enterprise · on-prem / air-gapped'], ['Endpoint seats', '214 of 250 used'], ['Valid until', '31 March 2027'], ['Add-ons', 'Kubernetes (not enabled)'], ['Signature', UI.pill('good', 'Valid', 'badge')]]),
          h('div', { class: 'mt-3' }, UI.meter(86, '', 'sm')), h('div', { class: 'xs muted mt-1' }, '214 of 250 seats')] }),
        UI.card({ cls: 'c-5 lg-12', title: 'Update licence', sub: 'Offline — no phone-home', body: [
          h('div', { class: 'dropzone' }, icon('upload'), h('div', { class: 'mt-2' }, h('b', null, 'Drop a signed licence file')), h('div', { class: 'small muted' }, 'Verified locally against the vendor key')),
          h('p', { class: 'small muted mt-3' }, 'The console never contacts a licence server; renewals are applied as signed files.')] }))]);
    },
    content: function () {
      return sec('Content & updates', [UI.card({ title: 'Offline content bundles', sub: 'Threat library, ATT&CK and KEV arrive as signed bundles', flush: true,
        body: h('div', { class: 'card-b' }, h('div', { class: 'list' }, D.ops.content.map(function (c) {
          return UI.listRow({ icon: 'book', title: h('span', { class: 'row gap-1' }, c.name, h('span', { class: 'tag mono' }, c.v)), sub: c.when, right: UI.pill('good', 'Verified', 'badge') }); }))) }),
        h('div', { class: 'callout info mt-4' }, icon('info'), h('div', { class: 'small' }, 'Bundles are signature-verified before import. Nothing leaves your network; there is no automatic download.'))]);
    },
    backup: function () {
      return sec('Backup & recovery', [UI.card({ title: 'Backups', body: [
        h('div', { class: 'row wrap mb-4' }, UI.pill('good', 'Last backup healthy', 'checkCircle'), h('span', { class: 'small soft' }, 'Today 02:00 · 1.4 GB · encrypted')),
        h('div', { class: 'form-grid' }, field('Schedule', 'Daily · 02:00 IST'), field('Retention', '30 days'), field('Location', 'On-prem NAS (encrypted)'), field('Last restore test', '14 Oct · passed')),
        h('div', { class: 'row mt-4' }, UI.btn('Back up now', { icon: 'database' }), UI.btn('Restore…', { ghost: true }))] })]);
    },
    appearance: function () {
      return sec('Appearance', [UI.card({ title: 'Theme', body: [
        h('div', { class: 'row wrap' }, themeCard('dark', 'Dark', 'Default · matches the logo'), themeCard('light', 'Light', 'For executives and print')),
        h('hr', { class: 'sep' }),
        row('Compact density', 'Tighter spacing for dense screens', true),
        row('Reduce motion', 'Minimise animations', false),
        row('Default dashboard view by role', 'Executives → Executive, analysts → Operations', true)] })]);
    },
    notifications: function () {
      return sec('Notifications', [UI.card({ title: 'What triggers a notification', body: [
        row('New critical finding', 'In-app and email to the owner', true),
        row('Finding past SLA', 'Daily digest to owners and managers', true),
        row('Assessment completed', 'In-app only', true),
        row('Posture score drop > 3 pts', 'Email to CISO', true),
        row('Integration unhealthy', 'In-app and email to admins', true),
        row('Report delivered', 'In-app only', false)] }),
        UI.card({ title: 'Delivery', sub: 'Email is sent from inside your network', body: h('div', { class: 'form-grid' }, field('SMTP server', 'smtp.contoso.example:587'), field('From address', 'audspect@contoso.example')) })]);
    }
  };
  function field(label, val) { return h('div', { class: 'field' }, h('label', null, label), h('div', { class: 'input', style: 'display:flex;align-items:center;color:var(--text-1)' }, val)); }
  function row(title, sub, on) { return h('div', { class: 'row', style: 'padding:10px 0;border-top:1px solid var(--border)' }, h('div', null, h('div', { class: 'strong' }, title), h('div', { class: 'small muted' }, sub)), h('span', { class: 'spacer' }), h('span', { class: 'toggle' + (on ? ' on' : '') })); }
  function themeCard(id, name, sub) {
    var cur = UI.theme() === id;
    var el = h('button', { class: 'tpl' + (cur ? ' on' : ''), type: 'button', style: 'width:200px' }, h('h4', null, icon(id === 'dark' ? 'moon' : 'sun'), name, cur ? UI.pill('accent', 'Active') : null), h('p', null, sub));
    el.addEventListener('click', function () { UI.setTheme(id); render(current); });
    return el;
  }

  var current = 'users';
  function render(id) {
    current = id;
    $('[data-sec]', nav); document.querySelectorAll('[data-sec]').forEach(function (a) { a.classList.toggle('on', a.getAttribute('data-sec') === id); });
    var view = (VIEWS[id] || VIEWS.users)();
    pane.replaceChildren.apply(pane, view);
    UI.hydrateIcons(pane);
  }
  nav.querySelectorAll('[data-sec]').forEach(function (a) {
    a.addEventListener('click', function (e) { e.preventDefault(); var id = a.getAttribute('data-sec'); try { history.replaceState(null, '', '#' + id); } catch (err) {} render(id); });
  });
  var want = (location.hash || '').replace('#', '');
  UI.boot('settings');
  render(VIEWS[want] ? want : 'users');
  UI.notes([
    { n: 1, sel: '.subnav', title: 'Ten sections become seven', body: 'Theme and Dashboard Preferences merge into Appearance; connectors move to Integrations. Audit log and Licence stay but are also reachable from where they matter.', today: 'Settings has a 10-item left nav mixing connectors, appearance and governance.' },
    { n: 2, sel: '.settings-layout', title: 'Air-gap-honest administration', body: 'Licensing and content are offline and signed; SSO/SCIM, append-only audit log and encrypted backups are first-class.' }
  ]);
})();
