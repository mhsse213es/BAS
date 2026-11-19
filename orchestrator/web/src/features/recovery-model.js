// Pure checks for the forgotten-password form on the login screen. The server checks everything again; this only
// saves a round trip and tells the person what is wrong before they send the recovery passphrase anywhere.

const PASSPHRASE = /^[A-Za-z0-9]{14}$/;

// Returns an error message, or null when the form is fine to send.
export function checkRecoveryForm(f) {
  if (!String(f.username || '').trim()) return 'Enter the administrator username or email.';
  if (!f.passphrase) return 'Enter the recovery passphrase.';
  if (!PASSPHRASE.test(f.passphrase)) return 'The recovery passphrase is exactly 14 letters and digits.';
  if (!f.next) return 'Enter a new password.';
  if (f.next.length < 10) return 'The new password must be at least 10 characters.';
  if (f.next !== f.again) return 'The two new passwords do not match.';
  return null;
}
