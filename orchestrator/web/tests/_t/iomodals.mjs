import { boot } from './iolib.mjs';
const b = await boot(); const { page, T } = b; await b.go();
const rows = () => page.locator('#ioc-registry-body tr').count();
const post = () => JSON.stringify(b.reqs.splice(0)).slice(0, 220);
// ADD
await page.locator('#ioc-add-btn').click(); await page.waitForTimeout(500);
await page.locator('#ioc-add-overlay .modal').screenshot({ path: T + 'io-m-add.png' });
console.log('add modal: type default =', await page.locator('#ioc-add-type').inputValue(), '| options', await page.locator('#ioc-add-type option').count());
await page.locator('#ioc-add-submit-btn').click(); await page.waitForTimeout(300);
console.log('empty submit -> err:', await page.locator('#ioc-add-err').innerText(), '| posts', post());
await page.locator('#ioc-add-value').fill('evil-c2.example.org'); await page.locator('#ioc-add-type').selectOption('domain');
b.state.fail['/import'] = 'database is read-only'; await page.locator('#ioc-add-submit-btn').click(); await page.waitForTimeout(700);
console.log('server refuses -> err:', await page.locator('#ioc-add-err').innerText(), '| modal open:', await b.overlays(), '| btn disabled:', await page.locator('#ioc-add-submit-btn').isDisabled());
delete b.state.fail['/import']; const before = await rows(); await page.locator('#ioc-add-submit-btn').click(); await page.waitForTimeout(1000);
console.log('add ok -> toast:', await b.toast(), '| modal:', JSON.stringify(await b.overlays()), '| rows', before, '->', await rows(), '| posts', post());
console.log('  new row visible on screen? first row:', (await page.locator('#ioc-registry-body tr').first().innerText()).replace(/\s+/g, ' ').slice(0, 80), '| scrollY', await page.evaluate(() => scrollY));
// duplicate add
await page.locator('#ioc-add-btn').click(); await page.waitForTimeout(300); await page.locator('#ioc-add-value').fill('evil-c2.example.org'); await page.locator('#ioc-add-type').selectOption('domain'); await page.locator('#ioc-add-submit-btn').click(); await page.waitForTimeout(900);
console.log('duplicate add -> toast:', await b.toast(), '| rows', await rows());
// IMPORT
await page.locator('#ioc-import-btn').click(); await page.waitForTimeout(500);
await page.locator('#ioc-import-overlay .modal').screenshot({ path: T + 'io-m-import.png' });
await page.locator('#ioc-import-submit-btn').click(); await page.waitForTimeout(300); console.log('import empty -> err:', await page.locator('#ioc-import-err').innerText());
await page.locator('#ioc-import-text').fill('domain,a.example\nbadline'); await page.locator('#ioc-import-submit-btn').click(); await page.waitForTimeout(300); console.log('import bad line -> err:', await page.locator('#ioc-import-err').innerText(), '| posts', post());
const r0 = await rows();
await page.locator('#ioc-import-text').fill('domain,ok1.example\nfoo_type,whatever\nip,192.0.2.9'); await page.locator('#ioc-import-submit-btn').click(); await page.waitForTimeout(1000);
console.log('import w/ unknown type -> err:', await page.locator('#ioc-import-err').innerText(), '| modal open:', await b.overlays(), '| server rows', b.state.rows.length, '| table rows', r0, '->', await rows());
await page.locator('#ioc-import-text').fill('domain,ok2.example\nip,192.0.2.10'); await page.locator('#ioc-import-submit-btn').click(); await page.waitForTimeout(1000);
console.log('import ok -> toast:', await b.toast(), '| modal:', JSON.stringify(await b.overlays()), '| rows', await rows());
await page.locator('#ioc-import-btn').click(); await page.waitForTimeout(300); await page.locator('#ioc-import-text').fill('domain,ok2.example\nip,192.0.2.10'); await page.locator('#ioc-import-submit-btn').click(); await page.waitForTimeout(900);
console.log('import all-duplicates -> toast:', await b.toast());
console.log('errors', JSON.stringify(b.errs)); await b.close();
