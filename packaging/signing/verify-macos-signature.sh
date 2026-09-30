#!/usr/bin/env bash
# packaging/signing/verify-macos-signature.sh
#
# Same honesty note as sign-macos.sh: written against Apple's documented
# interface, not verified against real codesign/spctl output in this
# session (no macOS host available).

verify_macos_signature() {
    local path="$1"

    if [ ! -f "$path" ]; then
        echo "verify_macos_signature: file not found: $path" >&2
        return 1
    fi

    if ! codesign --verify --deep --strict "$path" 2>&1; then
        echo "verify_macos_signature: codesign --verify failed for $path" >&2
        return 1
    fi

    if ! spctl --assess --type execute "$path" 2>&1; then
        echo "verify_macos_signature: spctl --assess failed for $path (not notarized or not stapled)" >&2
        return 1
    fi

    return 0
}
