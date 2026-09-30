#!/usr/bin/env bash
# packaging/signing/sign-macos.sh
#
# sign_macos wraps codesign -> notarytool submit -> stapler staple. Written
# against Apple's documented interface but not end-to-end tested against the
# real tools in this session -- no macOS host was available. Credentials
# (identity, team_id, notary_profile) are always parameters, never
# hardcoded, matching sign-windows.ps1's pattern. See
# docs/superpowers/specs/2026-09-30-d1-release-signing-architecture-design.md.

sign_macos() {
    local path="$1" identity="$2" team_id="$3" notary_profile="$4"

    if [ ! -f "$path" ]; then
        echo "sign_macos: file not found: $path" >&2
        return 1
    fi

    codesign --sign "$identity" --timestamp --options runtime "$path" || {
        echo "sign_macos: codesign failed for $path" >&2
        return 1
    }

    xcrun notarytool submit "$path" --keychain-profile "$notary_profile" --team-id "$team_id" --wait || {
        echo "sign_macos: notarytool submit failed for $path" >&2
        return 1
    }

    xcrun stapler staple "$path" || {
        echo "sign_macos: stapler staple failed for $path" >&2
        return 1
    }

    return 0
}
