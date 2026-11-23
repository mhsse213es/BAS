import { boot } from './setlib.mjs';
const b = await boot(); const { page, T } = b;
for (const s of ['users', 'engine', 'intel', 'taxii', 'art', 'audit', 'theme', 'dashprefs', 'license', 'backup']) {
  await b.go(s); await page.waitForTimeout(500);
  await page.screenshot({ path: T + 'sb-' + s + '.png', fullPage: true });
  console.log(s, 'errors so far', JSON.stringify(b.errs));
}
await b.close();
