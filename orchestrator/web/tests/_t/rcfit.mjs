import { boot } from './rclib.mjs';
const b = await boot(); await b.go();
console.log('overflow:', await b.page.evaluate(() => { const w = document.getElementById('rec-table-wrap'); return w.scrollWidth > w.clientWidth + 1; }));
await b.page.screenshot({ path: b.T + 'rc-fit.png', clip: { x: 260, y: 440, width: 1180, height: 300 } }); await b.close();
