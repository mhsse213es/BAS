/* Sign-in screen. */
(function () {
  'use strict';
  var h = UI.h, icon = UI.icon, $ = UI.$;
  UI.setTheme(UI.theme());
  $('#login').append(
    h('div', { class: 'login-aside' },
      h('a', { class: 'brand', href: 'index.html' }, h('img', { src: 'assets/img/logo_ondark.png', alt: '', style: 'width:34px;height:34px' }), h('span', { class: 'wordmark', style: 'font-size:20px' }, 'Aud', h('b', null, 'spect'))),
      h('div', { class: 'login-pitch' },
        h('h1', null, 'Know how secure you are, continuously.'),
        h('p', null, 'Breach-and-attack simulation for regulated banking — on-prem, air-gapped, and mapped to RBI, SEBI, CERT-In and IRDAI.'),
        h('ul', { class: 'check-list', style: 'margin-top:20px' }, ['Runs entirely inside your network', 'Signed, tamper-evident evidence for auditors', 'Threat profile tuned for Indian BFSI'].map(function (t) { return h('li', null, icon('checkCircle', 'sm'), t); }))),
      h('div', { class: 'login-foot' }, icon('lock', 'sm'), 'On-prem · air-gapped · v3.0')),
    h('div', { class: 'login-main' },
      h('form', { class: 'login-card', onsubmit: 'return false' },
        h('h2', null, 'Sign in'),
        h('p', { class: 'small muted mb-4' }, 'Use your organisation account, or a local admin for break-glass access.'),
        UI.btn('Continue with Azure AD', { primary: true, icon: 'lock', cls: 'full-btn' }),
        h('div', { class: 'login-or' }, h('span', null, 'or')),
        h('div', { class: 'field' }, h('label', null, 'Email'), h('input', { class: 'input', type: 'email', placeholder: 'you@contoso.example', value: 'ciso@contoso.example' })),
        h('div', { class: 'field mt-3' }, h('label', null, 'Password'), h('input', { class: 'input', type: 'password', value: '••••••••••' })),
        h('div', { class: 'row mt-4' }, h('span', { class: 'row gap-1 small' }, h('span', { class: 'checkbox on' }, icon('check', 'sm')), 'Remember this device'), h('span', { class: 'spacer' }), h('a', { href: '#', class: 'small' }, 'Forgot password?')),
        h('a', { class: 'btn full-btn mt-4', href: '02-dashboard.html' }, 'Sign in'),
        h('p', { class: 'small muted mt-4', style: 'text-align:center' }, 'Protected by MFA · sessions expire after 8 hours')),
      h('a', { class: 'login-back', href: 'index.html' }, icon('arrowRight', 'sm'), 'Back to the proposal')));
  UI.hydrateIcons(document);
})();
