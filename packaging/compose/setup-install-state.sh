#!/usr/bin/env bash
# packaging/compose/setup-install-state.sh
#
# FRESH / INTERRUPTED / COMPLETE install-state detection for setup.sh.
# Kept as its own sourceable library (not inline in the 1000+ line
# setup.sh) so it is testable without sourcing a script whose last line
# is `main "$@"`.
#
# A rerun must never regenerate secrets in an existing .env -- that is
# the single invariant this file exists to protect. detect_install_state
# only reads; it never writes or deletes anything. The caller decides
# what to do with the result.

# detect_install_state INSTALL_DIR
# Echoes FRESH, INTERRUPTED, or COMPLETE.
detect_install_state() {
  local install_dir="$1"
  local env_exists=false complete_exists=false

  [[ -f "${install_dir}/.env" ]] && env_exists=true
  [[ -f "${install_dir}/.install-complete" ]] && complete_exists=true

  if ! $env_exists && ! $complete_exists; then
    echo "FRESH"
  elif $env_exists && ! $complete_exists; then
    echo "INTERRUPTED"
  else
    echo "COMPLETE"
  fi
}

# write_install_complete_marker INSTALL_DIR
# Written only after every install step has run to completion -- never
# speculatively, never as part of any cleanup path.
write_install_complete_marker() {
  local install_dir="$1"
  date -u +"%Y-%m-%dT%H:%M:%SZ" > "${install_dir}/.install-complete"
  chmod 640 "${install_dir}/.install-complete"
}

# install_state_message STATE
# The operator-facing explanation of what was detected and what to do
# next -- never a silent proceed.
install_state_message() {
  local state="$1"
  case "$state" in
    INTERRUPTED)
      echo "Install state: INTERRUPTED (existing .env, no completion marker). Existing credentials will be preserved. Re-run with --resume to continue, or inspect ${INSTALL_DIR:-the install directory} manually first."
      ;;
    COMPLETE)
      echo "Install state: COMPLETE. Re-run with --reinstall to replace it, or use uninstall.sh first. Nothing was changed."
      ;;
    FRESH)
      echo "No existing install detected. Proceeding with a fresh install."
      ;;
    *)
      echo "Unknown install state: $state"
      ;;
  esac
}
