# Threat Intelligence Package: open items

Status as of 2026-10-20. The installer source is committed under `packaging/threat-intel-package/`. The `.deb` has not been built, and nothing has been installed on a real host.

## Blocked on staging access

1. **Build the `.deb`.** Run `sudo packaging/threat-intel-package/build/build-deb.sh` on a Linux host with Docker and internet access. It pulls about 40 images, which is roughly 30 GB or more, and writes `dist/Threat Intelligence Package.deb`. Deferred until staging is available, per the rule that heavy jobs run there. A dry run (`SKIP_IMAGES=1`) already builds the package layout and passes `dpkg-deb`.
2. **Install and test on a real host.** Ubuntu 22.04 and 24.04, x86_64, with 16 GB RAM and at least 150 GB free. Confirm that all three stacks come up together, that the credentials file is written with mode 0600, and that `tip-show-credentials` prints it.
3. **Confirm the health endpoints.** These were assumed, not checked:
   - MISP: `/users/login`
   - OpenCTI: `/health`
   - OpenAEV: `/api/health`
   If one is wrong, `tip-install` will wait 30 minutes and then fail.
4. **Confirm the API credential checks.**
   - MISP: the key check calls `/users/view/me` with the `ADMIN_KEY` set at install.
   - OpenCTI: the token check is a GraphQL `{ me { id } }` query.
   - OpenAEV: no automated check. The token must be verified in the OpenAEV dashboard.

## Decisions to confirm during testing

5. **Docker from the Ubuntu archive.** The package declares Docker as a dependency. A server with no apt access must already have Docker installed. "Offline" in this package means the images only.
6. **Image tags.** Most service images are `latest`. The build records each digest in `MANIFEST.txt`. Pin specific versions before a release.
7. **MinIO host port.** Port 9000 is removed from the OpenCTI and OpenAEV stacks so both can run together. Confirm nothing depends on that port from outside the host.
8. **XTM One.** Both stacks include XTM One, which may need an enterprise licence for full function. The installer does not supply one. Confirm what works without a licence.
9. **Mail is disabled.** SMTP and IMAP are off. OpenAEV mail features will not work until they are configured.
10. **Port layout.** The installer uses base to base+5. Confirm the layout works with the firewall and any existing services on the server.
11. **Ubuntu 22.04 and 24.04.** Both are supported on paper. Both need testing.

## Decisions taken on the record

- The orchestrator is not configured automatically. The installer prints the MISP, OpenCTI, and OpenAEV URLs and keys, and they are pasted into the BAS UI by hand.
- MISP is deployed with the official `misp-docker` compose, vendored into `packaging/threat-intel-package/vendor/misp-docker/` with checksums.
- The memory entry `project_threat_intel_package` was reopened on 2026-10-20 at the user's request. It was previously declined on 2026-08-31.

## Repo fixes made while building

- The root `.gitignore` excludes every `bin/` and `build/` folder. The installer scripts were force-added. Changes to them need `git add -f` until that rule is narrowed.
- Shell scripts are forced to LF line endings by `.gitattributes` in the package folder.
