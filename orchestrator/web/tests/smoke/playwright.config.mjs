import { defineConfig } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../..', process.env.SMOKE_ROOT || '../wwwroot');

export default defineConfig({
  testDir: here,
  timeout: 600_000,
  workers: 1,
  reporter: [['list']],
  use: { baseURL: 'http://127.0.0.1:4173', headless: true },
  webServer: { command: `node ${resolve(here, 'serve.mjs')} "${root}" 4173`, url: 'http://127.0.0.1:4173/index.html', reuseExistingServer: false },
});
