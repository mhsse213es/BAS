// Pure rules for the Detection Connectors card on the Detection Verification page: which fields each provider
// uses, what must be filled in, and the request body the server expects (POST/PUT /api/detectverify/configs).
// No DOM and no network, so it is unit-tested on its own.

// What the form shows per field. `secret` fields are never shown back: the server only says whether one is stored.
export var FIELD_META = {
  tenantId:     { label: 'Tenant ID', secret: false, placeholder: 'Entra tenant ID' },
  clientId:     { label: 'Client ID', secret: false, placeholder: '' },
  clientSecret: { label: 'Client secret', secret: true, placeholder: '' },
  workspaceId:  { label: 'Workspace ID', secret: false, placeholder: 'Log Analytics workspace ID' },
  baseUrl:      { label: 'Base URL', secret: false, placeholder: 'https://' },
  apiToken:     { label: 'API token', secret: true, placeholder: '' },
  insecureTls:  { label: 'Skip TLS certificate check', secret: false, placeholder: '' },
};

// One entry per provider the server accepts (CreateDetectionConnector's validProviders).
//   fields   what the connector reads; everything else is sent empty
//   required what must be filled in (secrets only on create: a stored one is kept on edit)
export var PROVIDERS = [
  { id: 'microsoft_sentinel', label: 'Microsoft Sentinel',
    fields: ['tenantId', 'clientId', 'clientSecret', 'workspaceId'], required: ['tenantId', 'clientId', 'clientSecret', 'workspaceId'],
    hint: 'An Entra app registration that can read the Log Analytics workspace.' },
  { id: 'microsoft_defender', label: 'Microsoft Defender XDR',
    fields: ['tenantId', 'clientId', 'clientSecret'], required: ['tenantId', 'clientId', 'clientSecret'],
    hint: 'An Entra app registration with security alert read access.' },
  { id: 'splunk', label: 'Splunk',
    fields: ['baseUrl', 'apiToken', 'insecureTls'], required: ['baseUrl', 'apiToken'],
    hint: 'The management API address (usually port 8089) and a bearer token.' },
  { id: 'qradar', label: 'IBM QRadar',
    fields: ['baseUrl', 'apiToken', 'insecureTls'], required: ['baseUrl', 'apiToken'],
    hint: 'The console address and an authorised service token.' },
  { id: 'crowdstrike', label: 'CrowdStrike Falcon',
    fields: ['baseUrl', 'clientId', 'clientSecret'], required: ['baseUrl', 'clientId', 'clientSecret'],
    hint: 'The Falcon API cloud address and an API client with detection read access.' },
  { id: 'trellix', label: 'Trellix',
    fields: ['baseUrl', 'apiToken', 'insecureTls'], required: ['apiToken'],
    hint: 'Leave the base URL empty to use the default Trellix endpoint.' },
  { id: 'elastic', label: 'Elastic',
    fields: ['baseUrl', 'apiToken', 'clientId', 'clientSecret', 'insecureTls'], required: ['baseUrl'],
    hint: 'Use an API key, or a username (Client ID field) and password (Client secret field), not both.' },
];

export function providerById(id) {
  return PROVIDERS.filter(function(p) { return p.id === id; })[0] || null;
}

export function fieldsFor(id) {
  var p = providerById(id);
  return p ? p.fields.slice() : [];
}

var KEEP = '***'; // the server's "keep the stored value" marker (UpdateDetectionConnector)

function str(v) { return v == null ? '' : String(v).trim(); }

// Is a secret field satisfied? Typed now, or already stored and left blank on an edit.
function secretPresent(key, values, existing) {
  if (str(values[key]) !== '') return true;
  if (!existing) return false;
  return key === 'clientSecret' ? !!existing.hasClientSecret : key === 'apiToken' ? !!existing.hasApiToken : false;
}

// validate returns the first problem as a sentence, or '' when the form can be saved. `existing` is the saved
// connector when editing, null when adding.
export function validate(providerId, values, existing) {
  var p = providerById(providerId);
  if (!p) return 'Choose a provider.';
  values = values || {};
  if (str(values.name) === '') return 'Give the connector a name.';
  for (var i = 0; i < p.required.length; i++) {
    var key = p.required[i];
    var ok = FIELD_META[key].secret ? secretPresent(key, values, existing) : str(values[key]) !== '';
    if (!ok) return FIELD_META[key].label + ' is required.';
  }
  if (providerId === 'elastic') {
    var hasKey = secretPresent('apiToken', values, existing);
    var user = str(values.clientId), hasPw = secretPresent('clientSecret', values, existing);
    var hasBasic = user !== '' || (str(values.clientSecret) !== '');
    if (hasKey && hasBasic) return 'Use either an API key or a username and password, not both.';
    if (!hasKey && !hasBasic && !(existing && hasPw && user !== '')) return 'Set an API key, or a username and password.';
    if (!hasKey && (user === '' || !hasPw)) return 'Basic auth needs both a username and password.';
  }
  var delay = str(values.verifyDelaySeconds);
  if (delay !== '') {
    var n = Number(delay);
    if (!/^\d+$/.test(delay) || n < 0 || n > 3600) return 'Delay must be a whole number of seconds from 0 to 3600.';
  }
  return '';
}

// buildBody is the JSON to send. Fields the provider does not read go out empty, so switching nothing else
// leaves no stale values behind. enabled is always explicit: the server treats a missing flag as disabled.
export function buildBody(providerId, values, existing) {
  var used = fieldsFor(providerId);
  values = values || {};
  var body = {
    name: str(values.name),
    enabled: values.enabled !== false,
    autoVerify: !!values.autoVerify,
    tenantId: '', clientId: '', clientSecret: '', workspaceId: '', baseUrl: '', apiToken: '', insecureTls: false,
    verifyDelaySeconds: str(values.verifyDelaySeconds) === '' ? 120 : Number(values.verifyDelaySeconds),
  };
  used.forEach(function(key) {
    if (key === 'insecureTls') { body.insecureTls = !!values.insecureTls; return; }
    var v = str(values[key]);
    if (FIELD_META[key].secret && v === '' && existing && secretPresent(key, values, existing)) v = KEEP;
    body[key] = v;
  });
  if (!existing) body.provider = providerId;
  return body;
}

// rowSummary: what the connector points at, for the list.
export function rowSummary(c) {
  if (c.provider === 'microsoft_sentinel') return c.workspaceId ? 'Workspace ' + c.workspaceId : 'No workspace';
  if (c.provider === 'microsoft_defender') return c.tenantId ? 'Tenant ' + c.tenantId : 'No tenant';
  if (c.provider === 'trellix' && !c.baseUrl) return 'Default Trellix endpoint';
  return c.baseUrl || '—';
}

// modeLabel: whether runs are checked by themselves, on request, or not at all.
export function modeLabel(c) {
  if (!c.enabled) return 'Disabled';
  return c.autoVerify ? 'Auto-verify' : 'On demand';
}

export function canManage(perms) { return Array.isArray(perms) && perms.indexOf('detectverify:configs:list') >= 0; }
export function canRun(perms) { return Array.isArray(perms) && perms.indexOf('detectverify:run') >= 0; }
