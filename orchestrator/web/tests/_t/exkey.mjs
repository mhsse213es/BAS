import { boot } from './exlib.mjs';
const b = await boot(); const { page } = b; await b.go('exercises');
for (const sel of ['#ex-execs-box tbody tr', '#openaev-scenarios-body tr']) {
  for (const key of ['Enter', ' ']) {
    await page.locator(sel).nth(1).focus();
    console.log(sel, JSON.stringify(key), 'focused tag:', await page.evaluate(() => document.activeElement.tagName));
    await page.keyboard.press(key === ' ' ? 'Space' : key); await page.waitForTimeout(900);
    console.log('   ->', JSON.stringify(await b.overlays()));
    await page.locator('.drawer-overlay.open .drawer-close').first().click().catch(() => {}); await page.waitForTimeout(300);
  }
}
console.log(JSON.stringify(b.errs)); await b.close();
