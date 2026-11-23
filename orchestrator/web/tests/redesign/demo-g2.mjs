// Dummy-data overrides, page group 2: { 'GET /api/path': value | (url) => value }
import { DEMO as B } from './demo-b.mjs';

// Real shape: trend points are {day, value} and metric state is "measured" | "no_data".
const fixDay = (a) => a.map((p) => ({ day: p.day || p.date, value: p.value }));
const factory = () => {
  const f = typeof B['GET /api/analytics/factory-health'] === 'function' ? B['GET /api/analytics/factory-health']() : B['GET /api/analytics/factory-health'];
  const out = JSON.parse(JSON.stringify(f));
  for (const k of Object.keys(out)) if (out[k] && out[k].state === 'ok') out[k].state = 'measured';
  out.trends.threatsProcessedByDay = fixDay(out.trends.threatsProcessedByDay);
  out.trends.tcvByDay = fixDay(out.trends.tcvByDay);
  return out;
};

export const DEMO = {
  'GET /api/analytics/factory-health': factory,
};
