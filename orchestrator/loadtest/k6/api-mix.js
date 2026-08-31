import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const BASE_URL = __ENV.BAS_SERVER_URL || 'https://localhost:9443';
const TOKEN = __ENV.BAS_JWT || ''; // a valid bas_token, obtained out-of-band before the run

const errorRate = new Rate('api_error_rate');
const dashboardTrend = new Trend('dashboard_read_duration');
const runResultTrend = new Trend('run_result_duration');
const findingsTrend = new Trend('findings_duration');
const reportTrend = new Trend('report_gen_duration');

export const options = {
	scenarios: {
		mixed_api_load: {
			executor: 'ramping-vus',
			startVUs: 0,
			stages: [
				{ duration: '2m', target: 50 },
				{ duration: '10m', target: 50 },
				{ duration: '2m', target: 0 },
			],
		},
	},
	thresholds: {
		api_error_rate: ['rate<0.01'],
		dashboard_read_duration: ['p(95)<2000'],
		run_result_duration: ['p(95)<3000'],
		findings_duration: ['p(95)<3000'],
		report_gen_duration: ['p(95)<8000'],
	},
};

function authedGet(path) {
	return http.get(`${BASE_URL}${path}`, { headers: { Cookie: `bas_token=${TOKEN}` } });
}
function authedPost(path, body) {
	return http.post(`${BASE_URL}${path}`, JSON.stringify(body || {}), {
		headers: { Cookie: `bas_token=${TOKEN}`, 'Content-Type': 'application/json' },
	});
}

// report_handlers.go's CreateReport (POST /api/reports) requires a real,
// currently-enrolled agentId for every reportType (posture/audit/
// compliance all reject an empty one) -- fetch one real agent once via
// k6's setup() rather than hardcoding an ID that may not exist on the
// target server.
export function setup() {
	const res = authedGet('/api/agents');
	const agents = res.json();
	if (!Array.isArray(agents) || agents.length === 0) {
		throw new Error('setup: /api/agents returned no agents -- seed at least one enrolled agent on staging before running this script');
	}
	return { agentId: agents[0].agentId || agents[0].id };
}

// Working mix: 60% dashboard/read, 20% run/result queries, 10% findings/posture, 10% report gen.
// Paths grounded against orchestrator/internal/api/routes.go's actual
// registered GET/POST routes at plan-writing time -- re-verify with
// `grep -n 'r\.Get("/api/dashboard\|r\.Get("/api/agents"\|r\.Get("/api/scenarios/runs"\|r\.Get("/api/campaigns"\|r\.Get("/api/findings"\|r\.Post("/api/reports"' orchestrator/internal/api/routes.go`
// before running, in case routes have changed since.
const DASHBOARD_ENDPOINTS = ['/api/dashboard/current', '/api/dashboard/trends', '/api/agents', '/api/campaigns'];
const RUN_ENDPOINTS = ['/api/scenarios/runs'];
const FINDINGS_ENDPOINTS = ['/api/findings'];

export default function (data) {
	const roll = Math.random();
	let res, group;

	if (roll < 0.60) {
		group = 'dashboard';
		const path = DASHBOARD_ENDPOINTS[Math.floor(Math.random() * DASHBOARD_ENDPOINTS.length)];
		res = authedGet(path);
		dashboardTrend.add(res.timings.duration);
	} else if (roll < 0.80) {
		group = 'run_result';
		const path = RUN_ENDPOINTS[Math.floor(Math.random() * RUN_ENDPOINTS.length)];
		res = authedGet(path);
		runResultTrend.add(res.timings.duration);
	} else if (roll < 0.90) {
		group = 'findings';
		res = authedGet(FINDINGS_ENDPOINTS[0]);
		findingsTrend.add(res.timings.duration);
	} else {
		group = 'report';
		res = authedPost('/api/reports', { reportType: 'posture', format: 'pdf', agentId: data.agentId });
		reportTrend.add(res.timings.duration);
	}

	const ok = check(res, { [`${group}: status is 2xx`]: (r) => r.status >= 200 && r.status < 300 });
	errorRate.add(!ok);
	sleep(1 + Math.random() * 2); // 1-3s think time between requests, per simulated user
}
