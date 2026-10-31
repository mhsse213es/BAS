/* Shared top bar for document-style pages (proposal index, design system). */
(function () {
  'use strict';
  var h = UI.h;
  var here = document.body.getAttribute('data-doc');
  var links = [
    ['index.html', 'Proposal', 'index'], ['01-design-system.html', 'Design system', 'ds'], ['02-dashboard.html', 'Dashboard'],
    ['03-assessments.html', 'Assessments'], ['04-findings.html', 'Findings'], ['05-coverage.html', 'Coverage'],
    ['06-compliance.html', 'Compliance'], ['07-endpoints.html', 'Endpoints'], ['08-reports.html', 'Reports']
  ];
  var themeBtn = h('button', { class: 'icon-btn', id: 'theme-btn', type: 'button', title: 'Toggle theme (T)' });
  document.getElementById('doc-top').append(
    h('a', { class: 'brand', href: 'index.html', 'aria-label': 'Proposal home' }, h('img', { src: 'assets/img/logo_ondark.png', alt: '' }), h('span', { class: 'wordmark' }, 'Aud', h('b', null, 'spect'))),
    h('span', { class: 'pill outline' }, 'Console redesign · v0.3'),
    h('span', { class: 'spacer' }),
    h('nav', { 'aria-label': 'Proposal pages' }, links.map(function (l) { return h('a', { href: l[0], class: l[2] && l[2] === here ? 'on' : null }, l[1]); })),
    themeBtn);
  themeBtn.addEventListener('click', function () { UI.setTheme(UI.theme() === 'dark' ? 'light' : 'dark'); });
  UI.boot('none');
})();
