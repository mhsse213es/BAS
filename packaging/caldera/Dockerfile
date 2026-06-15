# bas-caldera — MITRE Caldera with the CTID adversary-emulation library baked in
# so APT kill-chains are available fully air-gapped. Built ONLY on the internet-
# connected Windows build host; the clone happens inside this image layer and is
# never written to the host filesystem (keeps host AV out of the loop).
FROM ghcr.io/mitre/caldera:latest

# 1. Pull the full adversary-emulation library into the emu plugin's data dir.
#    The base image ships a stub adversary-emulation-plans/turla directory (payloads
#    only, no YAML); remove it first so git clone finds an empty destination.
RUN rm -rf plugins/emu/data/adversary-emulation-plans && \
    git clone --depth 1 \
      https://github.com/center-for-threat-informed-defense/adversary_emulation_library \
      plugins/emu/data/adversary-emulation-plans

# 2. Install emu's Python deps (pyminizip for payload decryption at runtime).
#    pip is provided by the image's venv at /opt/venv/caldera/bin/pip (on PATH).
RUN pip install --no-cache-dir -r plugins/emu/requirements.txt

# 3. Enable the emu plugin in the image's default config. local.yml is removed so
#    a fresh container regenerates it from default.yml (now including emu) AND
#    still receives the API_KEY_RED/API_KEY_BLUE env injection on boot.
RUN sed -i '/^plugins:/a - emu' conf/default.yml && rm -f conf/local.yml

# 4. Build-time assertion: fail the build if emu data didn't materialize.
#    Counts .yml and .yaml files under the cloned library (abilities are generated
#    at runtime by hook.py → populate_data_directory(); the library YAMLs prove
#    the clone was successful and the plugin can ingest air-gapped).
RUN test "$(find plugins/emu/data -name '*.yml' -o -name '*.yaml' | wc -l)" -gt 0
