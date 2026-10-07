import { defineConfig } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const web = resolve(here, '../..');
const serve = resolve(web, 'tests/smoke/serve.mjs');

export default defineConfig({
  testDir: here,
  testMatch: /.*\.spec\.mjs$/,
  timeout: 1_800_000,
  workers: 1,
  reporter: [['list']],
  outputDir: resolve(web, '.visual/results'),
  // Rasterisation flags: without them two loads of the same page differ by
  // +-1-2 in a few pixel channels (partial/multi-threaded raster, colour
  // profile, LCD text), which a byte-identical comparison cannot tolerate.
  use: {
    headless: true,
    launchOptions: {
      args: ['--force-color-profile=srgb', '--disable-lcd-text', '--disable-partial-raster', '--num-raster-threads=1',
        '--disable-skia-runtime-opts', '--disable-gpu-rasterization', '--font-render-hinting=none'],
    },
  },
  webServer: [
    { command: `node ${serve} "${resolve(web, '.visual/base/dist')}" 4174`, url: 'http://127.0.0.1:4174/index.html', reuseExistingServer: false },
    { command: `node ${serve} "${resolve(web, 'dist')}" 4175`, url: 'http://127.0.0.1:4175/index.html', reuseExistingServer: false },
  ],
});
