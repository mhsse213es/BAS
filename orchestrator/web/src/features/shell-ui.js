import { x } from '../core/escape.js';

// Shared pieces of the redesigned shell: the breadcrumb row under the header and the page-header
// ("hero") banner every page opens with. Nothing here talks to the server -- the banner's stat
// chips are filled by each page's own loader from data it already fetched.

// Sidebar group of every tab, in the same grouping index.html uses for the nav.
var TAB_GROUP = {
  dashboard: 'Operations', scenarios: 'Operations', runs: 'Operations', 'k8s-scenarios': 'Operations',
  'scheduled-assessments': 'Operations', initiatives: 'Operations', campaigns: 'Operations',
  'factory-health': 'Operations', coverage: 'Operations', variants: 'Operations', 'ad-coverage': 'Operations',
  email: 'Operations', em: 'Operations',
  findings: 'Visibility', iocs: 'Visibility', remediation: 'Visibility', reports: 'Visibility',
  verification: 'Visibility', attackpath: 'Visibility', exposure: 'Visibility', recommendations: 'Visibility',
  exercises: 'Visibility', 'attack-coverage': 'Visibility', 'threat-priority': 'Visibility',
  compliance: 'Visibility', 'sla-report': 'Visibility',
  agents: 'Infrastructure', integrations: 'Infrastructure',
  settings: 'Administration', users: 'Administration', profile: 'Administration',
};

// Pages reached from another page rather than from the sidebar.
var TAB_PARENT = { compliance: 'reports', 'sla-report': 'reports' };
var PARENT_LABEL = { reports: 'Reports' };

// breadcrumbFor returns the trail for a tab: [group, (parent page,) current page].
export function breadcrumbFor(tab, title) {
  var trail = [];
  var group = TAB_GROUP[tab];
  if (group) trail.push({ label: group });
  var parent = TAB_PARENT[tab];
  if (parent) trail.push({ label: PARENT_LABEL[parent], tab: parent });
  trail.push({ label: title, current: true });
  return trail;
}

export function formatClock(d) {
  function p(n) { return (n < 10 ? '0' : '') + n; }
  return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}

// renderBreadcrumb paints the trail and the "Updated hh:mm:ss" stamp (the time this page was
// opened -- the only refresh time the console really knows).
export function renderBreadcrumb(tab, title) {
  var trail = document.getElementById('crumb-trail');
  if (trail) {
    trail.innerHTML = breadcrumbFor(tab, title).map(function(c, i) {
      var sep = i ? '<span class="crumb-sep" aria-hidden="true">&rsaquo;</span>' : '';
      if (c.current) return sep + '<span class="crumb-cur" aria-current="page">' + x(c.label) + '</span>';
      if (c.tab) {
        return sep + '<button type="button" class="crumb-link" data-on-click="showTab" data-args="' + x(JSON.stringify([c.tab])) + '">' + x(c.label) + '</button>';
      }
      return sep + '<span class="crumb-group">' + x(c.label) + '</span>';
    }).join('');
  }
  var upd = document.getElementById('crumb-updated');
  if (upd) upd.textContent = 'Updated ' + formatClock(new Date());
}

// pageHeroHtml builds the banner at the top of a page. `icon` and `actions` are trusted markup
// supplied by the caller (inline SVG, buttons wired with data-on-click); title, sub and every stat
// value/label are escaped here.
export function pageHeroHtml(o) {
  var stats = (o.stats || []).map(function(s) {
    var tone = /^(ok|warn|bad|info|muted)$/.test(s.tone) ? ' tone-' + s.tone : '';
    return '<div class="hero-stat">' + (s.icon ? '<span class="hero-stat-ico' + tone + '">' + s.icon + '</span>' : '') +
      '<div><b' + (s.id ? ' id="' + x(s.id) + '"' : '') + '>' + x(s.value) + '</b><span>' + x(s.label) + '</span></div></div>';
  }).join('');
  return '<section class="page-hero">' +
    '<div class="hero-main">' +
      (o.icon ? '<div class="hero-ico" aria-hidden="true">' + o.icon + '</div>' : '') +
      '<div class="hero-text"><h1>' + x(o.title) + '</h1>' + (o.sub ? '<p class="hero-sub">' + x(o.sub) + '</p>' : '') + '</div>' +
      (o.actions ? '<div class="hero-actions">' + o.actions + '</div>' : '') +
    '</div>' +
    (stats ? '<div class="hero-stats">' + stats + '</div>' : '') +
  '</section>';
}

// setHeroStat updates one stat chip by id; a page that is not on screen simply has no such id.
export function setHeroStat(id, value) {
  var el = document.getElementById(id);
  if (el) el.textContent = String(value);
}

// mountHero renders a banner into <div id="..."> (a page without that placeholder is skipped).
export function mountHero(id, cfg) {
  var el = document.getElementById(id);
  if (el) el.innerHTML = pageHeroHtml(cfg);
}
