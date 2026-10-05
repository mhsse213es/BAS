// Fails unless the installed @playwright/test matches the browser build
// bundled in the pinned Playwright image (PLAYWRIGHT_IMAGE_VERSION).
import { readFileSync } from 'node:fs';
const want = process.env.PLAYWRIGHT_IMAGE_VERSION;
if (!want) { console.error('PLAYWRIGHT_IMAGE_VERSION is not set'); process.exit(1); }
const got = JSON.parse(readFileSync(new URL('../node_modules/@playwright/test/package.json', import.meta.url))).version;
if (got !== want) {
  console.error(`@playwright/test ${got} does not match Playwright image ${want}`);
  process.exit(1);
}
console.log(`@playwright/test ${got} matches Playwright image ${want}`);
