// Dummy-data overrides, page group 31: Settings (Users & roles with 11 accounts so the full table toolbar shows).
// Response shape follows GET /api/users: id, username, role (admin|analyst|viewer), isActive, mustChangePw, createdAt, lastLogin.
const NOW = new Date('2026-10-26T09:30:00Z').getTime();
const DAY = 86_400_000;
const iso = (msAgo) => new Date(NOW - msAgo).toISOString();

export const DEMO = {
  'GET /api/users': [
    { id: 1, username: 'asha.nair', role: 'admin', isActive: true, mustChangePw: false, createdAt: iso(400 * DAY), lastLogin: iso(25 * 60_000) },
    { id: 2, username: 'r.mehta', role: 'analyst', isActive: true, mustChangePw: false, createdAt: iso(310 * DAY), lastLogin: iso(180 * 60_000) },
    { id: 3, username: 'j.okafor', role: 'analyst', isActive: true, mustChangePw: false, createdAt: iso(260 * DAY), lastLogin: iso(1 * DAY + 90 * 60_000) },
    { id: 4, username: 'l.fernandes', role: 'analyst', isActive: true, mustChangePw: true, createdAt: iso(12 * DAY), lastLogin: iso(5 * DAY) },
    { id: 5, username: 'ciso.office', role: 'viewer', isActive: true, mustChangePw: false, createdAt: iso(200 * DAY), lastLogin: iso(3 * DAY) },
    { id: 6, username: 'audit.readonly', role: 'viewer', isActive: true, mustChangePw: false, createdAt: iso(150 * DAY), lastLogin: iso(21 * DAY) },
    { id: 7, username: 'p.dsouza', role: 'analyst', isActive: false, mustChangePw: false, createdAt: iso(330 * DAY), lastLogin: iso(94 * DAY) },
    { id: 8, username: 'm.haddad', role: 'analyst', isActive: true, mustChangePw: false, createdAt: iso(90 * DAY), lastLogin: iso(2 * DAY) },
    { id: 9, username: 'k.tanaka', role: 'viewer', isActive: true, mustChangePw: false, createdAt: iso(75 * DAY), lastLogin: iso(8 * DAY) },
    { id: 10, username: 'svc.reporting', role: 'viewer', isActive: true, mustChangePw: false, createdAt: iso(60 * DAY), lastLogin: '' },
    { id: 11, username: 'o.ibrahim', role: 'admin', isActive: true, mustChangePw: false, createdAt: iso(45 * DAY), lastLogin: iso(6 * 60 * 60_000) },
  ],
};
