# G1e reveal inventory (Task 5)

Generated from the codemod dry run (`tools/g1e-js-codemod.mjs`) over `src/**/*.js` at `ac7c121f`. Sites are the inline-style reads, writes and clears that Task 5 routes through `src/core/inline-style.js`. File:line numbers refer to `ac7c121f`. Status is `pending` until the rewrite commit marks it `converted`.

## Summary

| kind | count | meaning |
|---|---|---|
| display-reveal | 82 | `el.style.display = ''` -> `setDisplay(el, '')`: removes `is-hidden`/`g1-display-*` and inline display. |
| display-hide | 104 | `el.style.display = 'none'` -> `setDisplay(el, 'none')`. |
| display-set | 34 | `el.style.display = <other literal>` -> `setDisplay(el, <literal>)`. |
| display-expr | 85 | `el.style.display = <expression>` -> `setDisplay(el, <expression>)`. |
| display-read | 16 | `el.style.display` read -> `displayOf(el)` (inline value, else the value the class stands for). |
| class-write | 8 | `el.className = v` -> `replaceClasses(el, v)` (keeps generated classes, as inline styles survived). |
| csstext-write | 5 | `el.style.cssText = v` -> `setCssText(el, v)` (drops generated classes, as the inline style was replaced). |
| style-remove | 1 | `el.removeAttribute('style')` -> `clearInlineStyle(el)` (drops generated classes too). |
| **total** | **335** | 18 modules |

Counts differ from the plan's estimates by a few sites (reveal 82 = 82; hide+set 138 ~ 136; expr 85 ~ 89; read 16 ~ 15; class-write 8 ~ 9). The table below is the actual count.

## Sites

### display-reveal (82)

| site (file:line at ac7c121f) | before | after | status |
|---|---|---|---|
| features/adversaries.js:527 | `document.getElementById('adv-drawer-overlay').style.display = ''` | `setDisplay(document.getElementById('adv-drawer-overlay'), '')` | pending |
| features/adversaries.js:528 | `document.getElementById('adv-drawer').style.display = ''` | `setDisplay(document.getElementById('adv-drawer'), '')` | pending |
| features/adversaries.js:596 | `warn.style.display = ''` | `setDisplay(warn, '')` | pending |
| features/adversaries.js:602 | `warn.style.display = ''` | `setDisplay(warn, '')` | pending |
| features/agent-drawer.js:622 | `document.getElementById('cmp-placeholder').style.display = ''` | `setDisplay(document.getElementById('cmp-placeholder'), '')` | pending |
| features/agent-drawer.js:634 | `document.getElementById('cmp-report').style.display = ''` | `setDisplay(document.getElementById('cmp-report'), '')` | pending |
| features/agent-drawer.js:636 | `document.getElementById(id).style.display = ''` | `setDisplay(document.getElementById(id), '')` | pending |
| features/attack-path.js:39 | `panel.style.display = ''` | `setDisplay(panel, '')` | pending |
| features/attack-path.js:41 | `document.getElementById('ap-progress').style.display = ''` | `setDisplay(document.getElementById('ap-progress'), '')` | pending |
| features/attack-path.js:320 | `empty.style.display = ''` | `setDisplay(empty, '')` | pending |
| features/attack-path.js:343 | `document.getElementById('tp-list-view').style.display = ''` | `setDisplay(document.getElementById('tp-list-view'), '')` | pending |
| features/attack-path.js:368 | `empty.style.display = ''` | `setDisplay(empty, '')` | pending |
| features/attack-path.js:389 | `document.getElementById('tp-detail-view').style.display = ''` | `setDisplay(document.getElementById('tp-detail-view'), '')` | pending |
| features/attack-path.js:481 | `evidenceCard.style.display = ''` | `setDisplay(evidenceCard, '')` | pending |
| features/attack-path.js:679 | `document.getElementById('ap-form').style.display = ''` | `setDisplay(document.getElementById('ap-form'), '')` | pending |
| features/attack-path.js:691 | `document.getElementById('ap-form').style.display = ''` | `setDisplay(document.getElementById('ap-form'), '')` | pending |
| features/attack-path.js:703 | `ctxEl.style.display = ''` | `setDisplay(ctxEl, '')` | pending |
| features/attack-path.js:712 | `panel.style.display = ''` | `setDisplay(panel, '')` | pending |
| features/attack-path.js:781 | `document.getElementById('ap-progress').style.display = ''` | `setDisplay(document.getElementById('ap-progress'), '')` | pending |
| features/attack-path.js:944 | `document.getElementById('ap-progress').style.display = ''` | `setDisplay(document.getElementById('ap-progress'), '')` | pending |
| features/attack-path.js:1034 | `document.getElementById('ap-assets').style.display = ''` | `setDisplay(document.getElementById('ap-assets'), '')` | pending |
| features/attack-path.js:1094 | `document.getElementById('ap-about-backdrop').style.display = ''` | `setDisplay(document.getElementById('ap-about-backdrop'), '')` | pending |
| features/attack-path.js:1095 | `document.getElementById('ap-about-modal').style.display = ''` | `setDisplay(document.getElementById('ap-about-modal'), '')` | pending |
| features/attack-path.js:1105 | `panel.style.display = ''` | `setDisplay(panel, '')` | pending |
| features/attack-path.js:1632 | `w.style.display = ''` | `setDisplay(w, '')` | pending |
| features/attack-path.js:1658 | `wrap.style.display = ''` | `setDisplay(wrap, '')` | pending |
| features/attack-path.js:2045 | `document.getElementById('sc-filter-source').style.display = ''` | `setDisplay(document.getElementById('sc-filter-source'), '')` | pending |
| features/attack-path.js:2048 | `document.getElementById('sc-filter-os').style.display = ''` | `setDisplay(document.getElementById('sc-filter-os'), '')` | pending |
| features/campaigns.js:78 | `document.getElementById('campaigns-list').style.display = ''` | `setDisplay(document.getElementById('campaigns-list'), '')` | pending |
| features/campaigns.js:165 | `document.getElementById('campaigns-detail').style.display = ''` | `setDisplay(document.getElementById('campaigns-detail'), '')` | pending |
| features/campaigns.js:409 | `preview.style.display = ''` | `setDisplay(preview, '')` | pending |
| features/campaigns.js:420 | `preview.style.display = ''` | `setDisplay(preview, '')` | pending |
| features/campaigns.js:426 | `preview.style.display = ''` | `setDisplay(preview, '')` | pending |
| features/campaigns.js:460 | `el.style.display = ''` | `setDisplay(el, '')` | pending |
| features/campaigns.js:525 | `document.getElementById('dash-ti-section').style.display = ''` | `setDisplay(document.getElementById('dash-ti-section'), '')` | pending |
| features/campaigns.js:568 | `document.getElementById('dash-endpoint-section').style.display = ''` | `setDisplay(document.getElementById('dash-endpoint-section'), '')` | pending |
| features/campaigns.js:607 | `sec.style.display = ''` | `setDisplay(sec, '')` | pending |
| features/compliance.js:170 | `document.getElementById('cpw-cancel-btn').style.display = ''` | `setDisplay(document.getElementById('cpw-cancel-btn'), '')` | pending |
| features/compliance.js:206 | `wrap.style.display = ''` | `setDisplay(wrap, '')` | pending |
| features/compliance.js:238 | `errEl.style.display = ''` | `setDisplay(errEl, '')` | pending |
| features/compliance.js:244 | `errEl.style.display = ''` | `setDisplay(errEl, '')` | pending |
| features/compliance.js:274 | `errEl.style.display = ''` | `setDisplay(errEl, '')` | pending |
| features/endpoint-mastery.js:162 | `document.getElementById('em-sweep-individual-wrap').style.display = ''` | `setDisplay(document.getElementById('em-sweep-individual-wrap'), '')` | pending |
| features/evidence.js:895 | `hint.style.display = ''` | `setDisplay(hint, '')` | pending |
| features/evidence.js:1360 | `openLink.style.display = ''` | `setDisplay(openLink, '')` | pending |
| features/findings.js:24 | `empty.style.display = ''` | `setDisplay(empty, '')` | pending |
| features/findings.js:29 | `body.style.display = ''` | `setDisplay(body, '')` | pending |
| features/findings.js:462 | `sec.style.display = ''` | `setDisplay(sec, '')` | pending |
| features/integrations.js:20 | `wrap.style.display = ''` | `setDisplay(wrap, '')` | pending |
| features/integrations.js:107 | `document.getElementById('connector-form-wrap').style.display = ''` | `setDisplay(document.getElementById('connector-form-wrap'), '')` | pending |
| features/integrations.js:125 | `document.getElementById('connector-form-wrap').style.display = ''` | `setDisplay(document.getElementById('connector-form-wrap'), '')` | pending |
| features/integrations.js:339 | `res.style.display = ''` | `setDisplay(res, '')` | pending |
| features/integrations.js:417 | `document.getElementById('response-connector-form-wrap').style.display = ''` | `setDisplay(document.getElementById('response-connector-form-wrap'), '')` | pending |
| features/integrations.js:435 | `document.getElementById('response-connector-form-wrap').style.display = ''` | `setDisplay(document.getElementById('response-connector-form-wrap'), '')` | pending |
| features/integrations.js:535 | `wrap.style.display = ''` | `setDisplay(wrap, '')` | pending |
| features/integrations.js:539 | `wrap.style.display = ''` | `setDisplay(wrap, '')` | pending |
| features/iocs.js:292 | `errEl.style.display = ''` | `setDisplay(errEl, '')` | pending |
| features/iocs.js:299 | `errEl.style.display = ''` | `setDisplay(errEl, '')` | pending |
| features/iocs.js:314 | `errEl.style.display = ''` | `setDisplay(errEl, '')` | pending |
| features/openaev.js:69 | `errEl.style.display = ''` | `setDisplay(errEl, '')` | pending |
| features/openaev.js:586 | `bar.style.display = ''` | `setDisplay(bar, '')` | pending |
| features/openaev.js:592 | `p.style.display = ''` | `setDisplay(p, '')` | pending |
| features/ransomware.js:78 | `tierEl.style.display = ''` | `setDisplay(tierEl, '')` | pending |
| features/reports.js:118 | `fwWrap.style.display = ''` | `setDisplay(fwWrap, '')` | pending |
| features/reports.js:131 | `filterWrap.style.display = ''` | `setDisplay(filterWrap, '')` | pending |
| features/reports.js:840 | `p2.style.display = ''` | `setDisplay(p2, '')` | pending |
| features/reports.js:842 | `p1.style.display = ''` | `setDisplay(p1, '')` | pending |
| features/reports.js:1085 | `selAllWrap.style.display = ''` | `setDisplay(selAllWrap, '')` | pending |
| features/reports.js:1087 | `applyBtn.style.display = ''` | `setDisplay(applyBtn, '')` | pending |
| features/reports.js:1537 | `filtersEl.style.display = ''` | `setDisplay(filtersEl, '')` | pending |
| features/reports.js:1766 | `box.style.display = ''` | `setDisplay(box, '')` | pending |
| features/reports.js:1804 | `search.style.display = ''` | `setDisplay(search, '')` | pending |
| features/reports.js:2672 | `document.getElementById('run-kpi-strip').style.display = ''` | `setDisplay(document.getElementById('run-kpi-strip'), '')` | pending |
| features/reports.js:2673 | `document.getElementById('run-tabbar').style.display = ''` | `setDisplay(document.getElementById('run-tabbar'), '')` | pending |
| features/reports.js:2674 | `document.getElementById('run-tab-content').style.display = ''` | `setDisplay(document.getElementById('run-tab-content'), '')` | pending |
| features/shell.js:262 | `document.getElementById('nav-settings').style.display = ''` | `setDisplay(document.getElementById('nav-settings'), '')` | pending |
| features/shell.js:272 | `el.style.display = ''` | `setDisplay(el, '')` | pending |
| features/shell.js:274 | `document.getElementById('sim-cov-card').style.display = ''` | `setDisplay(document.getElementById('sim-cov-card'), '')` | pending |
| features/threat-intel.js:278 | `wrap.style.display = ''` | `setDisplay(wrap, '')` | pending |
| features/threat-intel.js:292 | `errEl.style.display = ''` | `setDisplay(errEl, '')` | pending |
| features/threat-intel.js:318 | `wrap.style.display = ''` | `setDisplay(wrap, '')` | pending |
| features/threat-intel.js:355 | `missingRow.style.display = ''` | `setDisplay(missingRow, '')` | pending |

### display-hide (104)

| site (file:line at ac7c121f) | before | after | status |
|---|---|---|---|
| features/adversaries.js:159 | `overlay.style.display = 'none'` | `setDisplay(overlay, 'none')` | pending |
| features/adversaries.js:561 | `document.getElementById('adv-drawer-overlay').style.display = 'none'` | `setDisplay(document.getElementById('adv-drawer-overlay'), 'none')` | pending |
| features/adversaries.js:562 | `document.getElementById('adv-drawer').style.display = 'none'` | `setDisplay(document.getElementById('adv-drawer'), 'none')` | pending |
| features/adversaries.js:587 | `overlay.style.display = 'none'` | `setDisplay(overlay, 'none')` | pending |
| features/adversaries.js:608 | `warn.style.display = 'none'` | `setDisplay(warn, 'none')` | pending |
| features/agent-drawer.js:623 | `document.getElementById('cmp-report').style.display = 'none'` | `setDisplay(document.getElementById('cmp-report'), 'none')` | pending |
| features/agent-drawer.js:625 | `document.getElementById(id).style.display = 'none'` | `setDisplay(document.getElementById(id), 'none')` | pending |
| features/agent-drawer.js:633 | `document.getElementById('cmp-placeholder').style.display = 'none'` | `setDisplay(document.getElementById('cmp-placeholder'), 'none')` | pending |
| features/attack-path.js:40 | `document.getElementById('ap-form').style.display = 'none'` | `setDisplay(document.getElementById('ap-form'), 'none')` | pending |
| features/attack-path.js:323 | `empty.style.display = 'none'` | `setDisplay(empty, 'none')` | pending |
| features/attack-path.js:344 | `document.getElementById('tp-detail-view').style.display = 'none'` | `setDisplay(document.getElementById('tp-detail-view'), 'none')` | pending |
| features/attack-path.js:371 | `empty.style.display = 'none'` | `setDisplay(empty, 'none')` | pending |
| features/attack-path.js:388 | `document.getElementById('tp-list-view').style.display = 'none'` | `setDisplay(document.getElementById('tp-list-view'), 'none')` | pending |
| features/attack-path.js:491 | `evidenceCard.style.display = 'none'` | `setDisplay(evidenceCard, 'none')` | pending |
| features/attack-path.js:674 | `document.getElementById('ap-collect').style.display = 'none'` | `setDisplay(document.getElementById('ap-collect'), 'none')` | pending |
| features/attack-path.js:680 | `document.getElementById('ap-progress').style.display = 'none'` | `setDisplay(document.getElementById('ap-progress'), 'none')` | pending |
| features/attack-path.js:681 | `document.getElementById('ap-done-actions').style.display = 'none'` | `setDisplay(document.getElementById('ap-done-actions'), 'none')` | pending |
| features/attack-path.js:684 | `document.getElementById('ap-assets').style.display = 'none'` | `setDisplay(document.getElementById('ap-assets'), 'none')` | pending |
| features/attack-path.js:685 | `document.getElementById('ap-schedule').style.display = 'none'` | `setDisplay(document.getElementById('ap-schedule'), 'none')` | pending |
| features/attack-path.js:692 | `document.getElementById('ap-progress').style.display = 'none'` | `setDisplay(document.getElementById('ap-progress'), 'none')` | pending |
| features/attack-path.js:693 | `document.getElementById('ap-done-actions').style.display = 'none'` | `setDisplay(document.getElementById('ap-done-actions'), 'none')` | pending |
| features/attack-path.js:705 | `ctxEl.style.display = 'none'` | `setDisplay(ctxEl, 'none')` | pending |
| features/attack-path.js:780 | `document.getElementById('ap-form').style.display = 'none'` | `setDisplay(document.getElementById('ap-form'), 'none')` | pending |
| features/attack-path.js:899 | `cancelEl.style.display = 'none'` | `setDisplay(cancelEl, 'none')` | pending |
| features/attack-path.js:943 | `document.getElementById('ap-form').style.display = 'none'` | `setDisplay(document.getElementById('ap-form'), 'none')` | pending |
| features/attack-path.js:951 | `rb.style.display = 'none'` | `setDisplay(rb, 'none')` | pending |
| features/attack-path.js:999 | `rb.style.display = 'none'` | `setDisplay(rb, 'none')` | pending |
| features/attack-path.js:1099 | `document.getElementById('ap-about-backdrop').style.display = 'none'` | `setDisplay(document.getElementById('ap-about-backdrop'), 'none')` | pending |
| features/attack-path.js:1100 | `document.getElementById('ap-about-modal').style.display = 'none'` | `setDisplay(document.getElementById('ap-about-modal'), 'none')` | pending |
| features/attack-path.js:1128 | `document.getElementById('ap-schedule').style.display = 'none'` | `setDisplay(document.getElementById('ap-schedule'), 'none')` | pending |
| features/attack-path.js:2016 | `catEl.style.display = 'none'` | `setDisplay(catEl, 'none')` | pending |
| features/attack-path.js:2039 | `document.getElementById('sc-tmpl-filters').style.display = 'none'` | `setDisplay(document.getElementById('sc-tmpl-filters'), 'none')` | pending |
| features/attack-path.js:2053 | `landingEl.style.display = 'none'` | `setDisplay(landingEl, 'none')` | pending |
| features/attack-path.js:2070 | `catEl.style.display = 'none'` | `setDisplay(catEl, 'none')` | pending |
| features/attack-path.js:2077 | `landingEl.style.display = 'none'` | `setDisplay(landingEl, 'none')` | pending |
| features/attack-path.js:2080 | `document.getElementById('sc-filter-source').style.display = 'none'` | `setDisplay(document.getElementById('sc-filter-source'), 'none')` | pending |
| features/attack-path.js:2081 | `document.getElementById('sc-filter-os').style.display = 'none'` | `setDisplay(document.getElementById('sc-filter-os'), 'none')` | pending |
| features/attack-path.js:2086 | `landingEl.style.display = 'none'` | `setDisplay(landingEl, 'none')` | pending |
| features/campaigns.js:77 | `document.getElementById('campaigns-detail').style.display = 'none'` | `setDisplay(document.getElementById('campaigns-detail'), 'none')` | pending |
| features/campaigns.js:164 | `document.getElementById('campaigns-list').style.display = 'none'` | `setDisplay(document.getElementById('campaigns-list'), 'none')` | pending |
| features/campaigns.js:241 | `document.getElementById('ti-pack-preview').style.display = 'none'` | `setDisplay(document.getElementById('ti-pack-preview'), 'none')` | pending |
| features/campaigns.js:242 | `document.getElementById('ti-generated-preview').style.display = 'none'` | `setDisplay(document.getElementById('ti-generated-preview'), 'none')` | pending |
| features/campaigns.js:376 | `document.getElementById('ti-pack-preview').style.display = 'none'` | `setDisplay(document.getElementById('ti-pack-preview'), 'none')` | pending |
| features/campaigns.js:377 | `document.getElementById('ti-generated-preview').style.display = 'none'` | `setDisplay(document.getElementById('ti-generated-preview'), 'none')` | pending |
| features/campaigns.js:396 | `preview.style.display = 'none'` | `setDisplay(preview, 'none')` | pending |
| features/campaigns.js:401 | `document.getElementById('ti-generated-preview').style.display = 'none'` | `setDisplay(document.getElementById('ti-generated-preview'), 'none')` | pending |
| features/compliance.js:240 | `errEl.style.display = 'none'` | `setDisplay(errEl, 'none')` | pending |
| features/compliance.js:275 | `errEl.style.display = 'none'` | `setDisplay(errEl, 'none')` | pending |
| features/endpoint-mastery.js:163 | `document.getElementById('em-sweep-group-wrap').style.display = 'none'` | `setDisplay(document.getElementById('em-sweep-group-wrap'), 'none')` | pending |
| features/evidence.js:76 | `document.getElementById('evidence-overlay').style.display = 'none'` | `setDisplay(document.getElementById('evidence-overlay'), 'none')` | pending |
| features/findings.js:25 | `body.style.display = 'none'` | `setDisplay(body, 'none')` | pending |
| features/findings.js:28 | `empty.style.display = 'none'` | `setDisplay(empty, 'none')` | pending |
| features/findings.js:460 | `sec.style.display = 'none'` | `setDisplay(sec, 'none')` | pending |
| features/integrations.js:24 | `wrap.style.display = 'none'` | `setDisplay(wrap, 'none')` | pending |
| features/integrations.js:105 | `document.getElementById('cf-test-result').style.display = 'none'` | `setDisplay(document.getElementById('cf-test-result'), 'none')` | pending |
| features/integrations.js:123 | `document.getElementById('cf-test-result').style.display = 'none'` | `setDisplay(document.getElementById('cf-test-result'), 'none')` | pending |
| features/integrations.js:130 | `document.getElementById('connector-form-wrap').style.display = 'none'` | `setDisplay(document.getElementById('connector-form-wrap'), 'none')` | pending |
| features/integrations.js:224 | `inp.style.display = 'none'` | `setDisplay(inp, 'none')` | pending |
| features/integrations.js:440 | `document.getElementById('response-connector-form-wrap').style.display = 'none'` | `setDisplay(document.getElementById('response-connector-form-wrap'), 'none')` | pending |
| features/integrations.js:548 | `wrap.style.display = 'none'` | `setDisplay(wrap, 'none')` | pending |
| features/iocs.js:281 | `document.getElementById('ioc-import-err').style.display = 'none'` | `setDisplay(document.getElementById('ioc-import-err'), 'none')` | pending |
| features/iocs.js:289 | `errEl.style.display = 'none'` | `setDisplay(errEl, 'none')` | pending |
| features/openaev.js:70 | `errEl.style.display = 'none'` | `setDisplay(errEl, 'none')` | pending |
| features/openaev.js:102 | `empty.style.display = 'none'` | `setDisplay(empty, 'none')` | pending |
| features/openaev.js:209 | `empty.style.display = 'none'` | `setDisplay(empty, 'none')` | pending |
| features/openaev.js:224 | `empty.style.display = 'none'` | `setDisplay(empty, 'none')` | pending |
| features/openaev.js:570 | `bar.style.display = 'none'` | `setDisplay(bar, 'none')` | pending |
| features/openaev.js:595 | `p.style.display = 'none'` | `setDisplay(p, 'none')` | pending |
| features/reports.js:125 | `fwWrap.style.display = 'none'` | `setDisplay(fwWrap, 'none')` | pending |
| features/reports.js:129 | `filterWrap.style.display = 'none'` | `setDisplay(filterWrap, 'none')` | pending |
| features/reports.js:523 | `document.getElementById('modal-group-wrap').style.display = 'none'` | `setDisplay(document.getElementById('modal-group-wrap'), 'none')` | pending |
| features/reports.js:524 | `document.getElementById('modal-all-wrap').style.display = 'none'` | `setDisplay(document.getElementById('modal-all-wrap'), 'none')` | pending |
| features/reports.js:570 | `wrap.style.display = 'none'` | `setDisplay(wrap, 'none')` | pending |
| features/reports.js:571 | `warn.style.display = 'none'` | `setDisplay(warn, 'none')` | pending |
| features/reports.js:606 | `wrap.style.display = 'none'` | `setDisplay(wrap, 'none')` | pending |
| features/reports.js:615 | `warn.style.display = 'none'` | `setDisplay(warn, 'none')` | pending |
| features/reports.js:662 | `warn.style.display = 'none'` | `setDisplay(warn, 'none')` | pending |
| features/reports.js:713 | `wrap.style.display = 'none'` | `setDisplay(wrap, 'none')` | pending |
| features/reports.js:1200 | `filtersEl.style.display = 'none'` | `setDisplay(filtersEl, 'none')` | pending |
| features/reports.js:1202 | `selAllWrap.style.display = 'none'` | `setDisplay(selAllWrap, 'none')` | pending |
| features/reports.js:1204 | `applyBtn.style.display = 'none'` | `setDisplay(applyBtn, 'none')` | pending |
| features/reports.js:1387 | `cw.style.display = 'none'` | `setDisplay(cw, 'none')` | pending |
| features/reports.js:1387 | `note.style.display = 'none'` | `setDisplay(note, 'none')` | pending |
| features/reports.js:1400 | `note.style.display = 'none'` | `setDisplay(note, 'none')` | pending |
| features/reports.js:1480 | `note.style.display = 'none'` | `setDisplay(note, 'none')` | pending |
| features/reports.js:1483 | `note.style.display = 'none'` | `setDisplay(note, 'none')` | pending |
| features/reports.js:1508 | `filtersEl.style.display = 'none'` | `setDisplay(filtersEl, 'none')` | pending |
| features/reports.js:1765 | `search.style.display = 'none'` | `setDisplay(search, 'none')` | pending |
| features/reports.js:1802 | `wrap.querySelector('.st-tech-selected').style.display = 'none'` | `setDisplay(wrap.querySelector('.st-tech-selected'), 'none')` | pending |
| features/reports.js:2670 | `document.getElementById('results-summary').style.display = 'none'` | `setDisplay(document.getElementById('results-summary'), 'none')` | pending |
| features/reports.js:2671 | `document.getElementById('results-body').style.display = 'none'` | `setDisplay(document.getElementById('results-body'), 'none')` | pending |
| features/shell.js:122 | `document.getElementById('login-screen').style.display = 'none'` | `setDisplay(document.getElementById('login-screen'), 'none')` | pending |
| features/shell.js:123 | `document.getElementById('app').style.display = 'none'` | `setDisplay(document.getElementById('app'), 'none')` | pending |
| features/shell.js:240 | `document.getElementById('cpw-cancel-btn').style.display = 'none'` | `setDisplay(document.getElementById('cpw-cancel-btn'), 'none')` | pending |
| features/shell.js:252 | `document.getElementById('app').style.display = 'none'` | `setDisplay(document.getElementById('app'), 'none')` | pending |
| features/shell.js:259 | `document.getElementById('login-screen').style.display = 'none'` | `setDisplay(document.getElementById('login-screen'), 'none')` | pending |
| features/shell.js:277 | `el.style.display = 'none'` | `setDisplay(el, 'none')` | pending |
| features/shell.js:279 | `document.getElementById('sim-cov-card').style.display = 'none'` | `setDisplay(document.getElementById('sim-cov-card'), 'none')` | pending |
| features/shell.js:280 | `document.getElementById('sim-cov-detail').style.display = 'none'` | `setDisplay(document.getElementById('sim-cov-detail'), 'none')` | pending |
| features/shell.js:288 | `nb.style.display = 'none'` | `setDisplay(nb, 'none')` | pending |
| features/shell.js:289 | `ub.style.display = 'none'` | `setDisplay(ub, 'none')` | pending |
| features/shell.js:589 | `banner.style.display = 'none'` | `setDisplay(banner, 'none')` | pending |
| features/threat-intel.js:293 | `errEl.style.display = 'none'` | `setDisplay(errEl, 'none')` | pending |
| features/threat-intel.js:357 | `missingRow.style.display = 'none'` | `setDisplay(missingRow, 'none')` | pending |

### display-set (34)

| site (file:line at ac7c121f) | before | after | status |
|---|---|---|---|
| features/adversaries.js:154 | `overlay.style.display = 'flex'` | `setDisplay(overlay, 'flex')` | pending |
| features/adversaries.js:582 | `overlay.style.display = 'flex'` | `setDisplay(overlay, 'flex')` | pending |
| features/attack-path.js:901 | `doneDiv.style.display = 'flex'` | `setDisplay(doneDiv, 'flex')` | pending |
| features/attack-path.js:951 | `da.style.display = 'flex'` | `setDisplay(da, 'flex')` | pending |
| features/attack-path.js:999 | `doneDiv2.style.display = 'flex'` | `setDisplay(doneDiv2, 'flex')` | pending |
| features/attack-path.js:2017 | `landingEl.style.display = 'block'` | `setDisplay(landingEl, 'block')` | pending |
| features/attack-path.js:2054 | `catEl.style.display = 'block'` | `setDisplay(catEl, 'block')` | pending |
| features/attack-path.js:2071 | `landingEl.style.display = 'block'` | `setDisplay(landingEl, 'block')` | pending |
| features/attack-path.js:2078 | `catEl.style.display = 'block'` | `setDisplay(catEl, 'block')` | pending |
| features/attack-path.js:2079 | `document.getElementById('sc-tmpl-filters').style.display = 'flex'` | `setDisplay(document.getElementById('sc-tmpl-filters'), 'flex')` | pending |
| features/attack-path.js:2087 | `catEl.style.display = 'block'` | `setDisplay(catEl, 'block')` | pending |
| features/evidence.js:72 | `document.getElementById('evidence-overlay').style.display = 'block'` | `setDisplay(document.getElementById('evidence-overlay'), 'block')` | pending |
| features/evidence.js:1324 | `donutEl.style.display = 'flex'` | `setDisplay(donutEl, 'flex')` | pending |
| features/integrations.js:223 | `sel.style.display = 'block'` | `setDisplay(sel, 'block')` | pending |
| features/openaev.js:99 | `empty.style.display = 'block'` | `setDisplay(empty, 'block')` | pending |
| features/openaev.js:208 | `empty.style.display = 'block'` | `setDisplay(empty, 'block')` | pending |
| features/openaev.js:223 | `empty.style.display = 'block'` | `setDisplay(empty, 'block')` | pending |
| features/reports.js:522 | `document.getElementById('modal-individual-wrap').style.display = 'block'` | `setDisplay(document.getElementById('modal-individual-wrap'), 'block')` | pending |
| features/reports.js:609 | `warn.style.display = 'block'` | `setDisplay(warn, 'block')` | pending |
| features/reports.js:620 | `wrap.style.display = 'block'` | `setDisplay(wrap, 'block')` | pending |
| features/reports.js:627 | `warn.style.display = 'block'` | `setDisplay(warn, 'block')` | pending |
| features/reports.js:639 | `warn.style.display = 'block'` | `setDisplay(warn, 'block')` | pending |
| features/reports.js:648 | `warn.style.display = 'block'` | `setDisplay(warn, 'block')` | pending |
| features/reports.js:656 | `warn.style.display = 'block'` | `setDisplay(warn, 'block')` | pending |
| features/reports.js:714 | `wrap.style.display = 'block'` | `setDisplay(wrap, 'block')` | pending |
| features/reports.js:1395 | `cw.style.display = 'block'` | `setDisplay(cw, 'block')` | pending |
| features/reports.js:1413 | `cw.style.display = 'block'` | `setDisplay(cw, 'block')` | pending |
| features/reports.js:1428 | `note.style.display = 'block'` | `setDisplay(note, 'block')` | pending |
| features/reports.js:1444 | `note.style.display = 'block'` | `setDisplay(note, 'block')` | pending |
| features/reports.js:1474 | `note.style.display = 'block'` | `setDisplay(note, 'block')` | pending |
| features/reports.js:1477 | `note.style.display = 'block'` | `setDisplay(note, 'block')` | pending |
| features/shell.js:253 | `document.getElementById('login-screen').style.display = 'flex'` | `setDisplay(document.getElementById('login-screen'), 'flex')` | pending |
| features/shell.js:260 | `document.getElementById('app').style.display = 'flex'` | `setDisplay(document.getElementById('app'), 'flex')` | pending |
| features/shell.js:580 | `banner.style.display = 'flex'` | `setDisplay(banner, 'flex')` | pending |

### display-expr (85)

| site (file:line at ac7c121f) | before | after | status |
|---|---|---|---|
| features/adversaries.js:144 | `allLabel.style.display = (ROLE === 'admin') ? 'flex' : 'none'` | `setDisplay(allLabel, (ROLE === 'admin') ? 'flex' : 'none')` | pending |
| features/adversaries.js:178 | `indWrap.style.display = mode === 'individual' ? 'block' : 'none'` | `setDisplay(indWrap, mode === 'individual' ? 'block' : 'none')` | pending |
| features/adversaries.js:179 | `grpWrap.style.display = mode === 'group' ? 'block' : 'none'` | `setDisplay(grpWrap, mode === 'group' ? 'block' : 'none')` | pending |
| features/adversaries.js:180 | `allWrap.style.display = mode === 'all' ? 'block' : 'none'` | `setDisplay(allWrap, mode === 'all' ? 'block' : 'none')` | pending |
| features/adversaries.js:447 | `body.style.display = _adversaryCollapsed ? 'none' : ''` | `setDisplay(body, _adversaryCollapsed ? 'none' : '')` | pending |
| features/adversaries.js:472 | `section.style.display = _adversaries.length ? '' : 'none'` | `setDisplay(section, _adversaries.length ? '' : 'none')` | pending |
| features/agent-drawer.js:49 | `document.getElementById('agt-tab-' + t).style.display = (t === tab ? '' : 'none')` | `setDisplay(document.getElementById('agt-tab-' + t), t === tab ? '' : 'none')` | pending |
| features/attack-path.js:853 | `cancelEl.style.display = (!isTerminal && s !== 'queued') ? '' : 'none'` | `setDisplay(cancelEl, (!isTerminal && s !== 'queued') ? '' : 'none')` | pending |
| features/attack-path.js:903 | `retryBtn2.style.display = (s === 'completed') ? 'none' : ''` | `setDisplay(retryBtn2, (s === 'completed') ? 'none' : '')` | pending |
| features/attack-path.js:905 | `viewBtn.style.display = (s === 'completed') ? '' : 'none'` | `setDisplay(viewBtn, (s === 'completed') ? '' : 'none')` | pending |
| features/attack-path.js:1139 | `el.style.display = s === name ? '' : 'none'` | `setDisplay(el, s === name ? '' : 'none')` | pending |
| features/attack-path.js:1496 | `loadMoreWrap.style.display = state.agentsHasMore ? '' : 'none'` | `setDisplay(loadMoreWrap, state.agentsHasMore ? '' : 'none')` | pending |
| features/attack-path.js:2126 | `sEl.style.display = expanded ? 'inline' : 'none'` | `setDisplay(sEl, expanded ? 'inline' : 'none')` | pending |
| features/attack-path.js:2127 | `fEl.style.display = expanded ? 'none' : 'inline'` | `setDisplay(fEl, expanded ? 'none' : 'inline')` | pending |
| features/campaigns.js:273 | `document.getElementById('cmp-target-agents-wrap').style.display = (type === 'agents') ? 'block' : 'none'` | `setDisplay(document.getElementById('cmp-target-agents-wrap'), (type === 'agents') ? 'block' : 'none')` | pending |
| features/campaigns.js:274 | `document.getElementById('cmp-target-group-wrap').style.display = (type === 'group') ? 'block' : 'none'` | `setDisplay(document.getElementById('cmp-target-group-wrap'), (type === 'group') ? 'block' : 'none')` | pending |
| features/campaigns.js:275 | `document.getElementById('cmp-target-all-wrap').style.display = (type === 'all') ? 'block' : 'none'` | `setDisplay(document.getElementById('cmp-target-all-wrap'), (type === 'all') ? 'block' : 'none')` | pending |
| features/campaigns.js:351 | `document.getElementById('cmp-source-ti').style.display = (CMP_SOURCE === 'threat_informed') ? '' : 'none'` | `setDisplay(document.getElementById('cmp-source-ti'), (CMP_SOURCE === 'threat_informed') ? '' : 'none')` | pending |
| features/campaigns.js:352 | `document.getElementById('cmp-source-existing').style.display = (CMP_SOURCE === 'existing_scenario') ? '' : 'none'` | `setDisplay(document.getElementById('cmp-source-existing'), (CMP_SOURCE === 'existing_scenario') ? '' : 'none')` | pending |
| features/coverage.js:70 | `emEl.style.display = hasData ? 'none' : ''` | `setDisplay(emEl, hasData ? 'none' : '')` | pending |
| features/coverage.js:71 | `detEl.style.display = hasData ? '' : 'none'` | `setDisplay(detEl, hasData ? '' : 'none')` | pending |
| features/coverage.js:72 | `ratesEl.style.display = hasData ? '' : 'none'` | `setDisplay(ratesEl, hasData ? '' : 'none')` | pending |
| features/coverage.js:131 | `empty.style.display = hasTiers ? 'none' : ''` | `setDisplay(empty, hasTiers ? 'none' : '')` | pending |
| features/coverage.js:132 | `content.style.display = hasTiers ? '' : 'none'` | `setDisplay(content, hasTiers ? '' : 'none')` | pending |
| features/endpoint-mastery.js:198 | `document.getElementById('em-sweep-individual-wrap').style.display = mode === 'individual' ? '' : 'none'` | `setDisplay(document.getElementById('em-sweep-individual-wrap'), mode === 'individual' ? '' : 'none')` | pending |
| features/endpoint-mastery.js:199 | `document.getElementById('em-sweep-group-wrap').style.display = mode === 'group' ? '' : 'none'` | `setDisplay(document.getElementById('em-sweep-group-wrap'), mode === 'group' ? '' : 'none')` | pending |
| features/endpoint-mastery.js:770 | `stopBtn.style.display = (sw.status === 'running' \|\| sw.status === 'agent_disconnected') ? '' : 'none'` | `setDisplay(stopBtn, (sw.status === 'running' \|\| sw.status === 'agent_disconnected') ? '' : 'none')` | pending |
| features/findings.js:110 | `bulkBtn.style.display = canPush ? '' : 'none'` | `setDisplay(bulkBtn, canPush ? '' : 'none')` | pending |
| features/findings.js:111 | `ticketTh.style.display = canPush ? '' : 'none'` | `setDisplay(ticketTh, canPush ? '' : 'none')` | pending |
| features/findings.js:152 | `thTriage.style.display = canTriage ? '' : 'none'` | `setDisplay(thTriage, canTriage ? '' : 'none')` | pending |
| features/findings.js:153 | `thCheck.style.display = (_findingsBulkMode && canPush) ? '' : 'none'` | `setDisplay(thCheck, (_findingsBulkMode && canPush) ? '' : 'none')` | pending |
| features/findings.js:154 | `thTicket.style.display = canPush ? '' : 'none'` | `setDisplay(thTicket, canPush ? '' : 'none')` | pending |
| features/findings.js:528 | `checkCol.style.display = enabled ? '' : 'none'` | `setDisplay(checkCol, enabled ? '' : 'none')` | pending |
| features/findings.js:529 | `bulkBtn.style.display = enabled ? '' : 'none'` | `setDisplay(bulkBtn, enabled ? '' : 'none')` | pending |
| features/integrations.js:401 | `document.getElementById('rc-crowdstrike-fields').style.display = (prov === 'crowdstrike') ? '' : 'none'` | `setDisplay(document.getElementById('rc-crowdstrike-fields'), (prov === 'crowdstrike') ? '' : 'none')` | pending |
| features/integrations.js:402 | `document.getElementById('rc-defender-fields').style.display = (prov === 'microsoft_defender') ? '' : 'none'` | `setDisplay(document.getElementById('rc-defender-fields'), (prov === 'microsoft_defender') ? '' : 'none')` | pending |
| features/iocs.js:122 | `importBtn.style.display = ROLE === 'admin' ? '' : 'none'` | `setDisplay(importBtn, ROLE === 'admin' ? '' : 'none')` | pending |
| features/reports.js:499 | `scWrap.style.display = scenarioId ? 'none' : 'block'` | `setDisplay(scWrap, scenarioId ? 'none' : 'block')` | pending |
| features/reports.js:526 | `allLabel.style.display = (ROLE === 'admin') ? 'flex' : 'none'` | `setDisplay(allLabel, (ROLE === 'admin') ? 'flex' : 'none')` | pending |
| features/reports.js:533 | `pip1.style.display = scenarioId ? 'none' : ''` | `setDisplay(pip1, scenarioId ? 'none' : '')` | pending |
| features/reports.js:535 | `pip2.style.display = lockAgent ? 'none' : ''` | `setDisplay(pip2, lockAgent ? 'none' : '')` | pending |
| features/reports.js:623 | `reasonWrap.style.display = (mode === 'posture') ? 'none' : 'block'` | `setDisplay(reasonWrap, (mode === 'posture') ? 'none' : 'block')` | pending |
| features/reports.js:672 | `variantWrap.style.display = showVariant ? 'block' : 'none'` | `setDisplay(variantWrap, showVariant ? 'block' : 'none')` | pending |
| features/reports.js:743 | `document.getElementById('modal-individual-wrap').style.display = mode === 'individual' ? 'block' : 'none'` | `setDisplay(document.getElementById('modal-individual-wrap'), mode === 'individual' ? 'block' : 'none')` | pending |
| features/reports.js:744 | `document.getElementById('modal-group-wrap').style.display = mode === 'group' ? 'block' : 'none'` | `setDisplay(document.getElementById('modal-group-wrap'), mode === 'group' ? 'block' : 'none')` | pending |
| features/reports.js:745 | `document.getElementById('modal-all-wrap').style.display = mode === 'all' ? 'block' : 'none'` | `setDisplay(document.getElementById('modal-all-wrap'), mode === 'all' ? 'block' : 'none')` | pending |
| features/reports.js:856 | `pane.style.display = (n === step) ? 'block' : 'none'` | `setDisplay(pane, (n === step) ? 'block' : 'none')` | pending |
| features/reports.js:860 | `document.getElementById('wz-back').style.display = (step > _wzMin) ? '' : 'none'` | `setDisplay(document.getElementById('wz-back'), (step > _wzMin) ? '' : 'none')` | pending |
| features/reports.js:861 | `document.getElementById('wz-next').style.display = (step < 4) ? '' : 'none'` | `setDisplay(document.getElementById('wz-next'), (step < 4) ? '' : 'none')` | pending |
| features/reports.js:862 | `document.getElementById('modal-run-btn').style.display = (step === 4) ? '' : 'none'` | `setDisplay(document.getElementById('modal-run-btn'), (step === 4) ? '' : 'none')` | pending |
| features/reports.js:866 | `document.getElementById('wz-mode-note').style.display = (mw.style.display === 'none') ? 'block' : 'none'` | `setDisplay(document.getElementById('wz-mode-note'), (displayOf(mw) === 'none') ? 'block' : 'none')` | pending |
| features/reports.js:1119 | `filtersEl.style.display = fw === 'caldera' ? '' : 'none'` | `setDisplay(filtersEl, fw === 'caldera' ? '' : 'none')` | pending |
| features/reports.js:1615 | `document.getElementById('bld-custom').style.display = mode === 'custom' ? 'block' : 'none'` | `setDisplay(document.getElementById('bld-custom'), mode === 'custom' ? 'block' : 'none')` | pending |
| features/reports.js:1616 | `document.getElementById('bld-art').style.display = mode === 'art' ? 'block' : 'none'` | `setDisplay(document.getElementById('bld-art'), mode === 'art' ? 'block' : 'none')` | pending |
| features/reports.js:1617 | `document.getElementById('bld-caldera').style.display = mode === 'caldera' ? 'block' : 'none'` | `setDisplay(document.getElementById('bld-caldera'), mode === 'caldera' ? 'block' : 'none')` | pending |
| features/reports.js:1618 | `document.getElementById('bld-local').style.display = mode === 'local' ? 'block' : 'none'` | `setDisplay(document.getElementById('bld-local'), mode === 'local' ? 'block' : 'none')` | pending |
| features/reports.js:2781 | `panel.style.display = (panel.id === 'run-tab-' + tabId) ? '' : 'none'` | `setDisplay(panel, (panel.id === 'run-tab-' + tabId) ? '' : 'none')` | pending |
| features/scheduled.js:241 | `pane.style.display = (n === step) ? 'block' : 'none'` | `setDisplay(pane, (n === step) ? 'block' : 'none')` | pending |
| features/scheduled.js:245 | `document.getElementById('sched-wz-back').style.display = (step > 1) ? '' : 'none'` | `setDisplay(document.getElementById('sched-wz-back'), (step > 1) ? '' : 'none')` | pending |
| features/scheduled.js:246 | `document.getElementById('sched-wz-next').style.display = (step < 4) ? '' : 'none'` | `setDisplay(document.getElementById('sched-wz-next'), (step < 4) ? '' : 'none')` | pending |
| features/scheduled.js:247 | `document.getElementById('sched-create-btn').style.display = (step === 4) ? '' : 'none'` | `setDisplay(document.getElementById('sched-create-btn'), (step === 4) ? '' : 'none')` | pending |
| features/scheduled.js:414 | `document.getElementById('sched-mode-warn').style.display = isTelemetry ? 'block' : 'none'` | `setDisplay(document.getElementById('sched-mode-warn'), isTelemetry ? 'block' : 'none')` | pending |
| features/scheduled.js:415 | `document.getElementById('sched-reason-wrap').style.display = isTelemetry ? 'block' : 'none'` | `setDisplay(document.getElementById('sched-reason-wrap'), isTelemetry ? 'block' : 'none')` | pending |
| features/scheduled.js:420 | `document.getElementById('sched-once-wrap').style.display = (type === 'once') ? 'block' : 'none'` | `setDisplay(document.getElementById('sched-once-wrap'), (type === 'once') ? 'block' : 'none')` | pending |
| features/scheduled.js:421 | `document.getElementById('sched-dow-wrap').style.display = (type === 'weekly') ? 'block' : 'none'` | `setDisplay(document.getElementById('sched-dow-wrap'), (type === 'weekly') ? 'block' : 'none')` | pending |
| features/scheduled.js:422 | `document.getElementById('sched-dom-wrap').style.display = (type === 'monthly') ? 'block' : 'none'` | `setDisplay(document.getElementById('sched-dom-wrap'), (type === 'monthly') ? 'block' : 'none')` | pending |
| features/scheduled.js:423 | `document.getElementById('sched-time-wrap').style.display = (type === 'once') ? 'none' : 'block'` | `setDisplay(document.getElementById('sched-time-wrap'), (type === 'once') ? 'none' : 'block')` | pending |
| features/shell.js:266 | `navInt.style.display = ROLE === 'admin' ? '' : 'none'` | `setDisplay(navInt, ROLE === 'admin' ? '' : 'none')` | pending |
| features/shell.js:269 | `navSched.style.display = (ROLE === 'admin' \|\| ROLE === 'analyst') ? '' : 'none'` | `setDisplay(navSched, (ROLE === 'admin' \|\| ROLE === 'analyst') ? '' : 'none')` | pending |
| features/shell.js:293 | `remTicketActions.style.display = (ROLE === 'admin' \|\| ROLE === 'analyst') ? 'flex' : 'none'` | `setDisplay(remTicketActions, (ROLE === 'admin' \|\| ROLE === 'analyst') ? 'flex' : 'none')` | pending |
| features/shell.js:397 | `document.getElementById('profile-admin-shortcut').style.display = u.role === 'admin' ? '' : 'none'` | `setDisplay(document.getElementById('profile-admin-shortcut'), u.role === 'admin' ? '' : 'none')` | pending |
| features/shell.js:422 | `el.style.display = t === name ? '' : 'none'` | `setDisplay(el, t === name ? '' : 'none')` | pending |
| features/shell.js:444 | `document.getElementById('dash-view-operational').style.display = view === 'operational' ? '' : 'none'` | `setDisplay(document.getElementById('dash-view-operational'), view === 'operational' ? '' : 'none')` | pending |
| features/shell.js:445 | `document.getElementById('dash-view-executive').style.display = view === 'executive' ? '' : 'none'` | `setDisplay(document.getElementById('dash-view-executive'), view === 'executive' ? '' : 'none')` | pending |
| features/shell.js:454 | `document.getElementById('agents-view-systemtree').style.display = view === 'systemtree' ? '' : 'none'` | `setDisplay(document.getElementById('agents-view-systemtree'), view === 'systemtree' ? '' : 'none')` | pending |
| features/shell.js:455 | `document.getElementById('agents-view-operational').style.display = view === 'operational' ? '' : 'none'` | `setDisplay(document.getElementById('agents-view-operational'), view === 'operational' ? '' : 'none')` | pending |
| features/shell.js:456 | `document.getElementById('agents-view-risk').style.display = view === 'risk' ? '' : 'none'` | `setDisplay(document.getElementById('agents-view-risk'), view === 'risk' ? '' : 'none')` | pending |
| features/threat-intel.js:172 | `document.getElementById('taxii-conn-basic-fields').style.display = authType === 'basic' ? '' : 'none'` | `setDisplay(document.getElementById('taxii-conn-basic-fields'), authType === 'basic' ? '' : 'none')` | pending |
| features/threat-intel.js:378 | `det.style.display = SIM_COV_OPEN ? '' : 'none'` | `setDisplay(det, SIM_COV_OPEN ? '' : 'none')` | pending |
| features/variants.js:134 | `allLabel.style.display = (ROLE === 'admin') ? 'flex' : 'none'` | `setDisplay(allLabel, (ROLE === 'admin') ? 'flex' : 'none')` | pending |
| features/variants.js:329 | `indWrap.style.display = mode === 'individual' ? 'flex' : 'none'` | `setDisplay(indWrap, mode === 'individual' ? 'flex' : 'none')` | pending |
| features/variants.js:330 | `grpWrap.style.display = mode === 'group' ? 'block' : 'none'` | `setDisplay(grpWrap, mode === 'group' ? 'block' : 'none')` | pending |
| features/variants.js:586 | `indWrap.style.display = mode === 'individual' ? 'block' : 'none'` | `setDisplay(indWrap, mode === 'individual' ? 'block' : 'none')` | pending |
| features/variants.js:587 | `grpWrap.style.display = mode === 'group' ? 'block' : 'none'` | `setDisplay(grpWrap, mode === 'group' ? 'block' : 'none')` | pending |
| features/variants.js:588 | `allWrap.style.display = mode === 'all' ? 'block' : 'none'` | `setDisplay(allWrap, mode === 'all' ? 'block' : 'none')` | pending |

### display-read (16)

| site (file:line at ac7c121f) | before | after | status |
|---|---|---|---|
| features/attack-path.js:933 | `apPane.style.display` | `displayOf(apPane)` | pending |
| features/attack-path.js:965 | `document.getElementById('ap-progress').style.display` | `displayOf(document.getElementById('ap-progress'))` | pending |
| features/attack-path.js:984 | `document.getElementById('ap-done-actions').style.display` | `displayOf(document.getElementById('ap-done-actions'))` | pending |
| features/attack-path.js:1994 | `tab.style.display` | `displayOf(tab)` | pending |
| features/attack-path.js:2125 | `fEl.style.display` | `displayOf(fEl)` | pending |
| features/evidence.js:555 | `modeWrap.style.display` | `displayOf(modeWrap)` | pending |
| features/evidence.js:609 | `document.getElementById('modal-variant-wrap').style.display` | `displayOf(document.getElementById('modal-variant-wrap'))` | pending |
| features/integrations.js:234 | `sel.style.display` | `displayOf(sel)` | pending |
| features/openaev.js:260 | `tab.style.display` | `displayOf(tab)` | pending |
| features/openaev.js:591 | `p.style.display` | `displayOf(p)` | pending |
| features/openaev.js:591 | `p.style.display` | `displayOf(p)` | pending |
| features/reports.js:866 | `mw.style.display` | `displayOf(mw)` | pending |
| features/reports.js:878 | `modeWrap.style.display` | `displayOf(modeWrap)` | pending |
| features/reports.js:894 | `variantWrap2.style.display` | `displayOf(variantWrap2)` | pending |
| features/reports.js:961 | `warnEl.style.display` | `displayOf(warnEl)` | pending |
| features/shell.js:519 | `dash.style.display` | `displayOf(dash)` | pending |

### class-write (8)

| site (file:line at ac7c121f) | before | after | status |
|---|---|---|---|
| features/compliance.js:143 | `d.className = 'dot-live'` | `replaceClasses(d, 'dot-live')` | pending |
| features/compliance.js:145 | `d.className = ''` | `replaceClasses(d, '')` | pending |
| features/evidence.js:835 | `wrap.className = 'cmdk-scrim'` | `replaceClasses(wrap, 'cmdk-scrim')` | pending |
| features/reports.js:1769 | `box.className = 'st-tech-selected unresolved'` | `replaceClasses(box, 'st-tech-selected unresolved')` | pending |
| features/reports.js:1777 | `box.className = 'st-tech-selected'` | `replaceClasses(box, 'st-tech-selected')` | pending |
| features/reports.js:1905 | `div.className = 'bld-step'` | `replaceClasses(div, 'bld-step')` | pending |
| features/reports.js:2203 | `el.className = 'card-meta'` | `replaceClasses(el, 'card-meta')` | pending |
| features/shell.js:393 | `statusBadge.className = 'sbadge ' + (u.isActive ? 's-active' : 's-retired')` | `replaceClasses(statusBadge, 'sbadge ' + (u.isActive ? 's-active' : 's-retired'))` | pending |

### csstext-write (5)

| site (file:line at ac7c121f) | before | after | status |
|---|---|---|---|
| features/attack-path.js:1698 | `ta.style.cssText = 'position:fixed;opacity:0;pointer-events:none'` | `setCssText(ta, 'position:fixed;opacity:0;pointer-events:none')` | pending |
| features/compliance.js:145 | `d.style.cssText = 'display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--muted);vertical-align:middle;flex-shrink:0;'` | `setCssText(d, 'display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--muted);vertical-align:middle;flex-shrink:0;')` | pending |
| features/shell.js:126 | `el.style.cssText = 'position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:var(--bg,#0b0e14);z-index:9999;padding:2rem'` | `setCssText(el, 'position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:var(--bg,#0b0e14);z-index:9999;padding:2rem')` | pending |
| features/shell.js:192 | `el.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:90;padding:0.75rem 2.5rem;background:var(--warning,#d29922);color:#1a1200;font-size:0.85rem;line-height:1.5;text-align:center'` | `setCssText(el, 'position:fixed;top:0;left:0;right:0;z-index:90;padding:0.75rem 2.5rem;background:var(--warning,#d29922);color:#1a1200;font-size:0.85rem;line-height:1.5;text-align:center')` | pending |
| features/shell.js:209 | `overlay.style.cssText = 'position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.6);z-index:10000'` | `setCssText(overlay, 'position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.6);z-index:10000')` | pending |

### style-remove (1)

| site (file:line at ac7c121f) | before | after | status |
|---|---|---|---|
| features/compliance.js:143 | `d.removeAttribute('style')` | `clearInlineStyle(d)` | pending |

## Partial clears of other properties

Eleven `el.style.<prop> = ''` writes for properties other than `display`. Each was checked against the element's markup in `index.html` and its template in the module: a clear needs a class only when the element carries a literal inline value for that property in markup or a template. None does, so these stay as CSSOM writes (CSP does not restrict CSSOM) and need no class.

| site | element | literal inline value in markup/template? | rule |
|---|---|---|---|
| attack-path.js:2214 | `#scd-<id>` overlay (`.sc-tile-detail`, created by `scenarioDetailHTML`) | no (only `left`/`right` set by `_scPositionOverlay`) | CSSOM stays |
| attack-path.js:2215 | same overlay | no | CSSOM stays |
| campaigns.js:243 | `#ti-pack-grid .btn` (index.html:3321) | no (markup sets justify-content, gap, text-align only) | CSSOM stays |
| campaigns.js:378 | same buttons | no | CSSOM stays |
| campaigns.js:403 | same buttons | no | CSSOM stays |
| reports.js:1397 | `#modal-customize-link` (index.html:2856, no style attribute) | no | CSSOM stays |
| reports.js:1398 | same link | no | CSSOM stays |
| reports.js:1423 | same link | no | CSSOM stays |
| reports.js:1424 | same link | no | CSSOM stays |
| shell.js:590 | `<body>` (index.html:10, no style attribute); `paddingTop` set by shell.js:582 via CSSOM | no | CSSOM stays |
| threat-intel.js:382 | `#sim-cov-card` hover (index.html:705, style has `transition:box-shadow`, not `box-shadow`) | no | CSSOM stays |

