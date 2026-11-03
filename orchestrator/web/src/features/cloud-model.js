// Pure helpers for the Cloud Scenarios page (O-10, first increment). No DOM, no network. They turn the
// catalogue from GET /api/cloud-scenarios into cards, check the run form before it is sent to
// POST /api/cloud-scenario-runs, and turn server refusals into plain messages.

var PROVIDERS = { aws: 'AWS', azure: 'Azure', gcp: 'GCP' };

// cloudProviderLabel returns the display name for a provider key, or the key itself when unknown.
export function cloudProviderLabel(provider) {
  return PROVIDERS[provider] || String(provider || '');
}

// scenarioCards turns the catalogue into cards, grouped by provider then name. Accepts either the
// {scenarios: [...]} envelope or a bare array.
export function scenarioCards(catalogue) {
  var list = Array.isArray(catalogue) ? catalogue : ((catalogue && catalogue.scenarios) || []);
  return list
    .filter(function(s) { return s && s.id; })
    .map(function(s) {
      return {
        id: s.id,
        name: s.name || s.id,
        provider: s.provider || '',
        providerLabel: cloudProviderLabel(s.provider),
        description: s.description || '',
        stepCount: Array.isArray(s.steps) ? s.steps.length : 0,
      };
    })
    .sort(function(a, b) {
      if (a.providerLabel !== b.providerLabel) return a.providerLabel < b.providerLabel ? -1 : 1;
      return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
    });
}

// buildCloudRunRequest checks the run form and returns the request body. It sends only the fields the
// server reads. The server still checks everything, including the allow-list; this only catches
// mistakes before the request is sent.
export function buildCloudRunRequest(form) {
  var f = form || {};
  var scenarioId = String(f.scenarioId || '').trim();
  var provider = String(f.provider || '').trim();
  var accountId = String(f.accountId || '').trim();
  var principal = String(f.principal || '').trim();
  var resource = String(f.resource || '').trim();
  if (!scenarioId) return { ok: false, error: 'Choose a scenario.' };
  if (!PROVIDERS[provider]) return { ok: false, error: 'Choose a provider: AWS, Azure or GCP.' };
  if (!accountId) return { ok: false, error: 'Enter the account ID to run against.' };
  if (!principal) return { ok: false, error: 'Enter the principal the scenario starts from.' };
  if (!resource) return { ok: false, error: 'Enter the resource the scenario targets.' };
  var account = { provider: provider, accountId: accountId };
  var region = String(f.region || '').trim();
  if (region) account.region = region;
  return { ok: true, body: { scenarioId: scenarioId, account: account, principal: principal, resource: resource } };
}

// describeRunError turns a failed request into a sentence the operator can act on. A 403 is the
// server-side account allow-list refusing the account, and the page says so rather than showing a bare status.
export function describeRunError(status, serverMessage) {
  var msg = serverMessage ? String(serverMessage) : '';
  if (status === 403) {
    return 'This account is not on the server’s cloud allow-list. An administrator must add it (CLOUD_ALLOWED_ACCOUNTS).';
  }
  if (status === 409) {
    return 'A discovery pass for this account is already running. Try again when it finishes.';
  }
  if (status === 503) {
    return 'The server is at its cloud discovery limit, or cloud credentials are not configured. Try again later.';
  }
  if (status === 400 && msg) return msg;
  if (msg) return msg;
  return 'The request failed (HTTP ' + status + ').';
}

// runTone maps a run status to a display tone: ok, warn, bad or neutral.
export function runTone(status) {
  switch (status) {
    case 'completed': return 'ok';
    case 'partial': return 'warn';
    case 'failed':
    case 'error': return 'bad';
    default: return 'neutral';
  }
}
