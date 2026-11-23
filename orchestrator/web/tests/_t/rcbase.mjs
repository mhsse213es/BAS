import { boot } from './rclib.mjs';
const b = await boot(); await b.go(); console.log('errors', JSON.stringify(b.errs));
await b.page.screenshot({ path: b.T + 'rc-0.png', fullPage: true }); await b.close();
