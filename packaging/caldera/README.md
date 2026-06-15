# bas-caldera image

Extends `ghcr.io/mitre/caldera:latest` with the CTID adversary-emulation
library baked in (the `emu` plugin), so APT kill-chains load air-gapped.

- Built by `packaging/windows-build.ps1` on the internet-connected Windows host.
- The clone happens inside the Docker build layer — nothing touches the host FS.
- The library contains REAL offensive payloads. The resulting image (and the
  `bas-caldera-*.tar` in the bundle) WILL be flagged by AV/EDR. See
  `docs/CALDERA_EMU.md` for the client AV-allowlist guidance.
- Rebuild when upgrading Caldera or refreshing the emulation library.

## Verify after build

```sh
docker run --rm -d --name emu-check -e API_KEY_RED=devkey -p 8899:8888 bas-caldera:<tag>
sleep 45
curl -s -H "KEY: devkey" http://localhost:8899/api/v2/abilities  | python -c "import sys,json;print(len(json.load(sys.stdin)))"
curl -s -H "KEY: devkey" http://localhost:8899/api/v2/adversaries | python -c "import sys,json;print(len(json.load(sys.stdin)))"
docker rm -f emu-check
```

Expect abilities well above 166 and adversaries > 0.
