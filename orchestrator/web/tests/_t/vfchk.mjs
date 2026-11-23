import { boot } from './vflib.mjs';
const b = await boot({ viewport: { width: 420, height: 900 } }); await b.go('run-1');
console.log('select within card:', await b.page.evaluate(() => { const s = document.getElementById('vf-run').getBoundingClientRect(), c = document.querySelector('.vf-run').getBoundingClientRect(); return s.right <= c.right + 1; }));
await b.page.locator('[data-on-click="loadVerificationTab"]').first().click(); await b.page.waitForTimeout(1200);
console.log('refresh keeps run:', await b.page.inputValue('#vf-run'), '| rows', await b.page.locator('#vf-body tr').count(), '| errors', JSON.stringify(b.errs));
await b.close();
