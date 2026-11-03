import { test, expect } from '@playwright/test';
// Signed out and the session check fails WITHOUT a 401 (server error): the app shell must still be hidden.
test('login screen alone', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('bas_role', 'admin'));
  await page.route('**/*', (route) => {
    const u = new URL(route.request().url());
    if (u.pathname === '/ready') return route.fulfill({ status: 200, contentType: 'application/json', body: '{"version":"x"}' });
    if (u.pathname === '/api/license/status') return route.fulfill({ status: 200, contentType: 'application/json', body: '{"state":"valid"}' });
    if (u.pathname.startsWith('/api/')) return route.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"x"}' });
    if (u.hostname !== '127.0.0.1') return route.fulfill({ status: 204, body: '' });
    return route.continue();
  });
  await page.goto('/index.html');
  await page.waitForTimeout(1200);
  await expect(page.locator('#app')).toBeHidden();
  await expect(page.locator('#login-screen')).toBeVisible();
});
