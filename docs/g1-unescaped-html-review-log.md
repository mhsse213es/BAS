# G1 review log: unescaped_html sites (89)

Baseline: fresh inventory, assembled view, 2026-11-23. Status: FIRST PASS. Verdicts are only given where the source was traced.

| # | line | function | target | verdict | note |
|---|---|---|---|---|---|
| 1 | 4452 | drawChart | el | SAFE | chart SVG: labels via escapeHTML (charts.js); numbers |
| 2 | 5176 | renderSummary | el | SAFE | kpi() escapes label, value and sub; tone whitelisted |
| 3 | 5294 | renderList | el | SAFE | provenance via detailList(), which escapes each item |
| 4 | 5449 | renderTemplateGrid | grid | SAFE | name, tactics, description, techniques all through x() |
| 5 | 5502 | openTmplRun | if (srcsEl) srcsEl | SAFE | scenario and adversary names through x() |
| 6 | 5611 | renderGroupCheckboxList | list | SAFE | emptyClass comes from three callers that all pass constant class names|
| 7 | 5619 | renderGroupCheckboxList | list | SAFE | all dynamic values through x() or numeric |
| 8 | 5867 | renderAdversaryLibrary | grid | SAFE | all text through x(); numeric counts |
| 9 | 5911 | openAdvDrawer | abEl | SAFE | tacticColors is a static literal in adversaries.js; text via x() |
| 10 | 5949 | openAdvRunModal | agSel | SAFE | agent id and hostname through x() |
| 11 | 6396 | loadAgtScenarios | pane | SAFE | run name and status through x() |
| 12 | 6494 | loadAgtLogs | pane | SAFE | tier buttons from a fixed list; metric and unit through x() |
| 13 | 6589 | loadAgtHealth | pane | SAFE | finding title, severity, name and notes through x() |
| 14 | 6722 | loadAgtAttackPath | pane | SAFE | status and detail through x() |
| 15 | 6934 | renderComplianceReport | document.getElementById('cmp-domain-area | SAFE | domain name via x(); the rest numeric or g1safe helper |
| 16 | 6954 | renderControlsTable | document.getElementById('cmp-controls-bo | FIXED (41eb5231) | c.status is concatenated raw into a class attribute; value set by our compliance code; harden with a whitelist or x() |
| 17 | 7551 | paint | tbody | SAFE | agent cells: agentCell escapes every field; statusCellHtml escapes labels; row actions use on()|
| 18 | 9587 | apiInvWriteSync | list | SAFE | operation/values/owner all wrapped in x() |
| 19 | 10296 | renderAPAssets | tb | SAFE | asset labels, hosts, crown jewel and segment via x(); tier options from a constant list|
| 20 | 10467 | renderAgentGroupTree | root | SAFE | group names via x(); node ids in on() args; counts numeric (renderAgentGroupNode) |
| 21 | 10511 | openAgentGroupMenu | m | SAFE | group menu labels are static; groupId passed through x() action args |
| 22 | 11761 | renderPhishingRunResults | box | SAFE | phishing run label, text, status, scenario and note all via x(); tones from a fixed map|
| 23 | 12035 | renderBackupJobsTable | tbody | SAFE | all text via x(); colours from a constant map |
| 24 | 12398 | renderBlackouts | body | SAFE | name, schedule and creator via x(); id via x() action args |
| 25 | 13018 | renderCampaignGroupPreview | document.getElementById('cmp-group-previ | SAFE | OS label comes from cmpAgentOS, which returns only windows, darwin or linux |
| 26 | 13265 | renderCampaignTargets | document.getElementById('cmp-targets') | SAFE | agent id and hostname via x(); OS label from cmpAgentOS (fixed set) |
| 27 | 13553 | renderChips | host | SAFE | chip labels are a static list; counts numeric (cloud-scenarios.js:66) |
| 28 | 13570 | renderCards | host | SAFE | all text via x(); provider mark from a fixed MARK map with a constant fallback |
| 29 | 13766 | renderRunsTable | host | SAFE | every cell through x(); the table header is static |
| 30 | 14596 | renderCoverageAnalytics | if (root) root | SAFE | tables and rings via tableWrap/ringBlock (escape); missed rows: pill() for IDs, x() for names and counts; chart labels escaped in charts.js|
| 31 | 14714 | cell | if (body) body | SAFE | technique IDs, names, tactic chips and counts via x(); verdict dot from a fixed set|
| 32 | 14792 | renderThreatExposure | body | SAFE | threat initial, title, date and chip text all escaped; counts numeric|
| 33 | 14802 | renderCovMatrix | document.getElementById('cov-matrix') | SAFE | tactic, technique and ids via x(); state classes from a fixed set |
| 34 | 14816 | renderCovToolbar | document.getElementById('cov-toolbar') | SAFE | chip labels via x(); chip list is a static constant; tone classes fixed |
| 35 | 16548 | renderList | box | SAFE | name, provider, summary and last-test text via x(); mode via pill(); ids via on()|
| 36 | 17200 | idx | tbody | SAFE | cellHtml (detection-verification.js) escapes every text cell; status via pill; button label constant|
| 37 | 17321 | set | host | SAFE | vfPaintFacts: status via pill() with constant tones; state note via x(); drawer rows via kit kv() which escapes label and value|
| 38 | 17451 | vfLoadEvidence | host | SAFE | file name, hash, uploader via x(); size numeric; href uses encodeURIComponent |
| 39 | 17490 | vfLoadHistory | host | SAFE | dates via fmtDate (formatted string); statuses via vfStatusColor (fixed set); text via x() |
| 40 | 17838 | fail | el | SAFE | area labels, reasons and summary via x(); icons constant; ring numeric|
| 41 | 17867 | fail | el | FIXED (41eb5231) | tile values and notes via x(); the tone class is built raw from t.tone; constrain it or wrap it |
| 42 | 17997 | renderEmailTabs | t | SAFE | template name and id via x(); catalog is a static constant |
| 43 | 18049 | renderEmailCampaignRows | tb | SAFE | name and id via x(); status via pill(), which escapes; dates formatted |
| 44 | 18144 | loadEmailRuns | tb | SAFE | name, environment, errors via x(); status via egStatusBadge (pill escapes); time formatted|
| 45 | 18376 | loadEmTab | gridEl | SAFE | numbers are computed locally with Math.round from counts; names via x(); agent ID via x(); ago() yields text; catalog is constant|
| 46 | 19027 | renderEMSweepProgress | list | FIXED (41eb5231) | layer labels constant; agent ID, status escaped; step pass/fail/timeout counts (pr.stepsFailed etc.) inserted raw; wrap in Number()|
| 47 | 20372 | paintTable | tbody | SAFE | verification table: cells via cellHtml (escapes text); checkbox, row and button IDs via on(); column headers via x(); the run-time fixed labels only|
| 48 | 21051 | paintTable | tbody | SAFE | cellHtml (exp-view.js) escapes every text cell; scores and chips are fixed-tone or numeric|
| 49 | 21430 | idx | tbody | SAFE | cellHtml (factory-health.js) escapes every cell; relative titles via x(); numbers via x()|
| 50 | 21538 | renderFactoryHealthFunnel | el | FIXED (41eb5231) | values and labels escaped; stage and quality tones inserted raw into class attributes; confirm they come from a fixed set or wrap them|
| 51 | 21702 | renderSparkline | el | SAFE | sparkline built from numeric coordinates and fixed colours|
| 52 | 22133 | none | el | SAFE | both summary grids: card titles and chart labels escaped; 'Nothing open' is constant|
| 53 | 22195 | renderFindingsRows | tb | SAFE | all visible cells escape; ticket and triage cells are fixed text; option values come from a constant list; ids via on()|
| 54 | 22412 | renderRemToolbar | el | SAFE | segmented control (kit seg): labels via x(); ids via action args|
| 55 | 22438 | renderEndpointList | el | FIXED (41eb5231) | endpoint names, IDs and counts escaped via x(String()); the severity counts in the summary line are inserted raw; wrap them|
| 56 | 22529 | renderRemList | el | FIXED (41eb5231) | titles, closes and agents escaped; the missed and detected-only counts are inserted raw; wrap them|
| 57 | 22678 | loadFindingTickets | container | SAFE | ticket ID and URL via x(); revalidate badge is constant text|
| 58 | 23461 | paintChips | chipsEl | SAFE | chip labels via x(); scope values and counts from fixed sources|
| 59 | 24081 | initiativeRenderAttachList | list | SAFE | id, type via x(); state label via g1safe helper|
| 60 | 24277 | paintGrid | el | SAFE | integration cards (cardHtml): name, meta, detail via x(); status via pill; actions via on()|
| 61 | 24482 | renderConnectorSettings | document.getElementById('cf-settings') | SAFE | labels/hints come from the static CONNECTOR_FIELDS constant (integrations.js:114) |
| 62 | 25177 | renderRunIOCList | el | FIXED (41eb5231) | type, source, tags, families and actors via x(); confidence is a server number inserted raw; wrap it in Number()|
| 63 | 25480 | fmt | el | SAFE | drawer rows rendered by kit kv(), which escapes both label and value via x(); date uses toLocaleString|
| 64 | 25721 | renderK8sClusters | host | FIXED (41eb5231) | cluster ID, label and footers escaped; the counts nsCount, cleanPct and runs are inserted raw; wrap them in Number() or x()|
| 65 | 26419 | renderLog | el | FIXED (41eb5231) | message text via x(); the tone class is built raw from l.tone; constrain it or wrap it|
| 66 | 26659 | openSweepDrilldown | document.getElementById('sweep-drilldown | SAFE | title and summary set with textContent; run names via x(); IDs via on(). Display issue (not security): the non-button branch wraps verdict HTML in x(), so its tags would show as text|
| 67 | 27287 | loadAPHistory | tb | FIXED (41eb5231) | host via x(); node and edge counts from the server are inserted raw; wrap them in Number() or x()|
| 68 | 28574 | idx | tbody | SAFE | recommendation rows: cells via cellHtml (escapes); actionsCellHtml and on() pass only IDs; tier class from a fixed tier map; checkbox IDs via on()|
| 69 | 29242 | openModal | document.getElementById('modal-agent') | SAFE | agent id and hostname via x(); OS label fixed text|
| 70 | 29367 | renderRunMode | warn | SAFE | mode comes from the run-mode select, which only holds its own option values; the OS message is built from constants and an escaped target OS|
| 71 | 29451 | renderAdditionalAgents | list | SAFE | agent id and hostname via x(); OS label from cmpAgentOS (fixed set)|
| 72 | 29870 | openPickerWith | tacticSel | SAFE | tactic names via x(); options from a set built in the same function|
| 73 | 30027 | renderPickerList | document.getElementById('picker-list') | SAFE | label, name, meta, IDs and badges all via x(); checkbox ids via x()|
| 74 | 31429 | soonPanel | document.getElementById('run-tab-content | SAFE | soonPanel label escaped via x(); tab buttons use x(label) and on(); tab labels are constants|
| 75 | 31466 | soonPanel | document.getElementById('run-tabbar') | SAFE | soonPanel label escaped via x(); tab buttons use x(label) and on(); tab labels are constants|
| 76 | 31668 | renderDetectionValidationTab | el | FIXED (41eb5231) | product, technique, provider, domain, agent and labels escaped; coverage, missRate and verified counts inserted raw (coverage + '%'); wrap in Number()|
| 77 | 31815 | openRerunReview | document.getElementById('rerun-review-bo | FINDING | rerun-review.js:62 Techniques row joins technique IDs from run data without x(); fix: wrap in x() |
| 78 | 31910 | openCampaignRerunReview | document.getElementById('rerun-review-bo | SAFE | rerun rows: scenario, agent, mode and privilege each pass through x(); labels are constants|
| 79 | 34765 | renderScheduledAssessmentsList | tbody | SAFE | row cells built by cellHtml (escapes text); id-bound actions via on(); rowActions passes only IDs|
| 80 | 35156 | renderSchedAgentList | root | SAFE | agent ID, hostname and OS via x(); checkboxes use on() args|
| 81 | 36671 | paintTable | tbody | SAFE | user table (set-view): cells via cellHtml (escapes text); actionsHtml passes only IDs, usernames and roles via on(); labels constant|
| 82 | 37006 | renderBreadcrumb | trail | SAFE | breadcrumb labels and tab targets via x(); separators constant|
| 83 | 37615 | renderAgentRiskSummary | tb | FIXED (41eb5231) | health score inserted raw into a cell; it should be a number from the server, but wrap it in Number() or x()|
| 84 | 38044 | idx | tbody | SAFE | technique coverage table: cellHtml escapes text; dimCell uses fixed pill tones; row id via on()|
| 85 | 38365 | renderTAXIIConnectorsList | tbody | SAFE | result colour from a fixed set; counts numeric; errors via x()|
| 86 | 38722 | loadSimCoverage | bodyEl | SAFE | row labels are static literals; values numeric (threat-intel.js) |
| 87 | 39040 | paintTable | tbody | SAFE | name and trend escaped; tpTrend escapes delta; scoreCell escapes score; gap and total via x()|
| 88 | 40336 | renderVexSweepList | el | FIXED (41eb5231) | IDs and technique escaped; server counters and pct inserted raw; wrap in Number()|
| 89 | 41056 | renderVariantRun | panel | SAFE | wrapper and results table escape every value (technique, status, encoding, context, evasion, risk, verdict, taskId); verdict colour from a fixed map|

Totals: SAFE 75, FINDING 1, FIXED 13, PENDING 0
