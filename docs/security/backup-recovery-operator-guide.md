# Backup and recovery: operator guide

This guide lists what the installer asks of you, what each choice means, and what happens if you choose it. The installer prints the same options at the point you need them.

## Keys you must keep

| Key | Where it lives on the host | Without it |
|---|---|---|
| Backup key | `/etc/audspect/secrets/backup-encryption.key` | Archives made with it cannot be read |
| Database encryption key | `/etc/audspect/secrets/db-encryption.key` | Stored credentials and the backed-up CA key cannot be read |

Each key has a recovery copy, encrypted with a passphrase. Create them with:

    sudo bash install.sh --export-backup-key <file outside this host's backups>
    sudo bash install.sh --export-db-key <file outside this host's backups>

Keep both recovery copies and both passphrases somewhere other than this host. The passphrases cannot be recovered.

## Situations and options

**1. Fresh install or upgrade asks for a recovery copy.**
Backups are blocked until a verified recovery copy exists. Options:
- Enter a path outside the backup directory and a passphrase of 16 characters or more when asked.
- Stop, create the copy with `--export-backup-key`, then start again.

**2. A non-interactive install or upgrade stops with "no confirmed recovery copy".**
Nothing has been changed. Options:
- Set `BAS_BACKUP_KEY_RECOVERY_PATH` and `BAS_BACKUP_KEY_PASSPHRASE`, then run again.
- Create the copy first with `--export-backup-key`.

**3. The upgrade lists "Legacy backup key ... still present".**
The legacy key opens only archives made before this version. Options:
- Keep it. Older archives still restore with it.
- Remove it only after a new backup has restored on a clean host and older archives are erased. The steps are in `req-039-customer-managed-keys.md`, under "Historical cleanup".

**4. The upgrade lists older backups that still hold a plaintext CA key.**
Options:
- Keep them until a new backup has restored successfully.
- Then remove them by secure erasure, and record what was removed.

**5. Restore on a clean host says the backup key could not be imported.**
Nothing has been changed. Options:
- Run `sudo bash install.sh --import-backup-key <recovery file>`, then restore again.
- Set `BAS_BACKUP_KEY_RECOVERY_PATH` and `BAS_BACKUP_KEY_PASSPHRASE`, then restore again.
- Stop.

**6. Restore says the CA key does not unwrap with this host's database encryption key.**
This is the usual result on a fresh host. The installer generated a new database key, which cannot open the archive. Nothing has been changed. Options:
- Move `/etc/audspect/secrets/db-encryption.key` aside, run `sudo bash install.sh --import-db-key <recovery file>`, then restore again.
- Restore a different archive that this host's key can open.
- Stop.

**7. Restore says decryption failed.**
Either the backup key is missing on this host, or the archive is corrupt. Nothing has been changed. Options:
- Import the backup key (situation 5), then try again.
- Try another archive.

**8. Restore says the CA key restore failed.**
The previous CA key was put back, and services have not started. Options:
- Read the error, then run the restore again. The archive is unchanged.
- Stop, and keep the pre-restore snapshot in the backups directory.

**9. The database TLS check or setup fails.**
Nothing has been changed. Options:
- Fix the file the installer reports.
- Or move `DATA_DIR/dbtls` aside, so the installer regenerates the certificate, then run again.

## Rollback caveat

Archives made by this version can only be restored with this version's installer. A previous version cannot read them, because it only knows the old co-located key. Do not copy the new key next to the archives to work around this.

## What this guide does not cover

Restore has been tested at component level only. Run a restore on a clean host with the real bundle before you rely on it. See `req-039-customer-managed-keys.md`, "Not verified".
