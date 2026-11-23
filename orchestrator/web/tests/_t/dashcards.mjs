import { boot } from './intlib.mjs';
const b = await boot(); await b.go('dashboard'); await b.page.waitForTimeout(2500);
await b.page.locator('#dop-valruns').screenshot({ path: b.T + 'dd-val.png' }); await b.page.locator('#dop-runs').screenshot({ path: b.T + 'dd-runs.png' }); await b.close();
