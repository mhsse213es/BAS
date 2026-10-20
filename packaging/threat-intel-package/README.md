# Threat Intelligence Package

Offline installer for MISP, OpenCTI and OpenAEV on one Ubuntu server.

## Install (on the target server)

```
sudo apt install ./"Threat Intelligence Package.deb"
sudo tip-install --host <server-ip-or-hostname> --port <base-port>
```

Example: `sudo tip-install --host 192.168.10.50 --port 8080`

The install needs no internet access. The first run takes a long time while the images load and the stacks start.

## Requirements

- Ubuntu 22.04 or 24.04, x86_64
- 16 GB RAM (the installer refuses to run below 14 GB)
- 150 GB free under `/var/lib`
- Docker Engine and the Compose plugin. The package pulls these in as dependencies from the Ubuntu archive.

## Ports

The base port is the one you pass with `--port`. The installer uses base through base+5 and checks that they are free.

| Port        | Service                 |
|-------------|-------------------------|
| base        | MISP (HTTP)             |
| base+1      | MISP (HTTPS)            |
| base+2      | OpenCTI                 |
| base+3      | OpenCTI XTM One         |
| base+4      | OpenAEV                 |
| base+5      | OpenAEV XTM One         |

## What the installer does

1. Checks the OS, RAM, disk, Docker, and free ports.
2. Generates every password, token, and encryption key on this host.
3. Loads the bundled images from `/usr/share/threat-intelligence-package/images`.
4. Starts MISP, then OpenCTI, then OpenAEV, one at a time.
5. Waits for each web interface and checks the MISP and OpenCTI API credentials.
6. Writes all logins and API keys to `/etc/threat-intelligence-package/credentials.txt` (mode 0600, root only), and prints them once.

To show them again: `sudo tip-show-credentials`.

## Connecting BAS

The installer prints a block titled "Enter these in BAS". Paste the values into the BAS UI:

- MISP base URL and API key: Intel tab, MISP card.
- OpenCTI base URL and API key: Intel tab, OpenCTI card.
- OpenAEV base URL and API token: OpenAEV card.

The orchestrator config is not written by this package. Values are pasted in by hand, as agreed for this package.

## Known limits

- The bundle is pinned to the image tags in `build/images.list` and the digests in `MANIFEST.txt`. Image versions are whatever was current when the package was built.
- MinIO's host port 9000 is removed from both vendor stacks so they can run together. MinIO is reachable only inside each stack's network.
- SMTP and IMAP are disabled. OpenAEV mail features will not work until they are configured.
- The OpenCTI and OpenAEV health-check URLs and the OpenAEV token check are not verified automatically. They must be confirmed on the staging server.
- XTM One may need an enterprise licence for full function. The installer does not supply one.
- Not tested on a live host yet. Testing happens on the staging server.
