#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

export THREEX_ABUSE_GUARD_INSTALL_SOURCE_ONLY=1
# shellcheck source=install.sh
. "$(dirname "$0")/install.sh"

CONFIG_DIR="$ROOT/etc/3x-abuse-guard"
STATE_DIR="$ROOT/var/lib/3x-abuse-guard"
LOG_DIR="$ROOT/var/log/3x-abuse-guard"
printf 'release-payload' >"$ROOT/release.tar.gz"
if command -v sha256sum >/dev/null 2>&1; then
  release_sha="$(sha256sum "$ROOT/release.tar.gz" | awk '{print $1}')"
else
  release_sha="$(shasum -a 256 "$ROOT/release.tar.gz" | awk '{print $1}')"
fi
verify_sha256 "$ROOT/release.tar.gz" "$release_sha"
if (verify_sha256 "$ROOT/release.tar.gz" "0000000000000000000000000000000000000000000000000000000000000000") >/dev/null 2>&1; then
  printf 'mismatched release checksum was accepted\n' >&2
  exit 1
fi
TOKEN="first-token"
write_config

config_before="$(cksum "$CONFIG_DIR/config.yaml")"
env_before="$(cksum "$CONFIG_DIR/env")"
TOKEN="second-token"
PANEL_URL="http://example.invalid/"
write_config

[ "$(cksum "$CONFIG_DIR/config.yaml")" = "$config_before" ]
[ "$(cksum "$CONFIG_DIR/env")" = "$env_before" ]
grep -q "first-token" "$CONFIG_DIR/env"
TOKEN=""
if ! has_stored_panel_auth; then
  printf 'stored credentials were not detected\n' >&2
  exit 1
fi

sed -i.bak 's/token_env: "THREEX_ABUSE_GUARD_TOKEN"/token_env: "CUSTOM_PANEL_TOKEN"/' "$CONFIG_DIR/config.yaml"
sed -i.bak "s/^THREEX_ABUSE_GUARD_TOKEN=.*/CUSTOM_PANEL_TOKEN='custom-token'/" "$CONFIG_DIR/env"
if ! has_stored_panel_auth; then
  printf 'custom stored credential variable was not detected\n' >&2
  exit 1
fi
rm -f "$CONFIG_DIR/config.yaml.bak" "$CONFIG_DIR/env.bak"

REPLACE_CONFIG=1
TOKEN="second-token"
write_config
grep -q "second-token" "$CONFIG_DIR/env"
grep -q "http://example.invalid/" "$CONFIG_DIR/config.yaml"
grep -q "event_retention_days: 30" "$CONFIG_DIR/config.yaml"

printf 'install configuration preservation tests passed\n'
