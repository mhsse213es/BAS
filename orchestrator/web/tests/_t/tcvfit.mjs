import { boot } from './tcvlib.mjs';
const b = await boot(); await b.go();
console.log('table overflows card horizontally:', await b.page.evaluate(() => { const w = document.getElementById('tcv-table-wrap'); return w.scrollWidth > w.clientWidth + 1; }));
await b.page.screenshot({ path: b.T + 'tcv-fit.png', clip: { x: 260, y: 790, width: 1180, height: 200 } });
await b.close();
