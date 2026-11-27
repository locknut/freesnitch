#!/usr/bin/env bash
# The helper's direct policy delivery to the network extension. The delivery
# itself needs a running, approved extension, so this pins the invariants
# that keep it narrow, and proves the firewall safety audit enforces them:
# each mutation below must make the audit fail.
#  - the helper is accepted only under its own code requirement, and every
#    other peer still needs the GUI's;
#  - the helper (like the CLI) never becomes the connection alerts go to;
#  - a snapshot's sender is fixed when its connection is accepted;
#  - only policy the app delivered (and saved for the next start) moves the
#    extension's watermark, so a helper delivery cannot make the next start
#    refuse the saved policy and fail open;
#  - the helper delivers policy only while a helper-driven feature is on.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-helper-push.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() { printf 'helper policy push: FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'helper policy push: PASS: %s\n' "$*"; }

HELPER="$ROOT/Sources/Helper/HelperService.swift"
PUSHER="$ROOT/Sources/Helper/ExtensionPolicyPusher.swift"
PROVIDER="$ROOT/Sources/NetExt/FilterDataProvider.swift"

bash "$ROOT/Scripts/audit_firewall_safety.sh" >/dev/null 2>&1 || fail "the firewall safety audit fails on the clean tree"
pass "the firewall safety audit passes on the clean tree"

grep -Fq 'guard isEnabled() else {' "$PUSHER" || fail "the pusher no longer checks whether it is enabled"
grep -Fq 'isEnabled: { [weak self] in self?.helperDeliversPolicy() ?? false })' "$HELPER" \
  || fail "the helper delivers policy without a feature that needs it"
pass "the helper delivers policy only while a helper-driven feature is on"

grep -Fq 'if let status, status.isReady, status.epoch == ours.epoch, status.generation == ours.generation { return }' "$PUSHER" \
  || fail "the helper resends its policy although the extension already holds it"
pass "between changes the helper only checks, and resends only on a difference"

grep -Fq 'if source == .app { snapshotStatus = status }' "$PROVIDER" \
  || fail "a refused helper delivery replaces the status the app acts on"
if grep -Fq 'liveSnapshotFromHelper' "$PROVIDER"; then
  fail "an older app relay is again reported as accepted, which can hide a rollback"
fi
pass "a refused helper delivery is not shown to the app; no refusal is reported as accepted"

mutate() { # <label> <file> <old> <new>
  local label="$1" file="$2" old="$3" new="$4" tree="$TMP/$1"
  mkdir -p "$tree"
  cp -R "$ROOT/Sources" "$ROOT/Scripts" "$tree/"
  cp "$ROOT/project.yml" "$ROOT/project-netext.yml" "$tree/"
  python3 - "$tree/$file" "$old" "$new" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1]); text = path.read_text()
if sys.argv[2] not in text:
    raise SystemExit(f"mutation target not found in {path}")
path.write_text(text.replace(sys.argv[2], sys.argv[3]))
PY
  if bash "$tree/Scripts/audit_firewall_safety.sh" >/dev/null 2>&1; then
    fail "mutation $label: the audit still passes"
  fi
  pass "mutation $label is caught by the audit"
}

mutate accept-every-peer Sources/Shared/IPCConnection.swift \
  'let fromHelper = XPCPeerValidator.isTrustedHelper(newConnection)' 'let fromHelper = true'
mutate helper-skips-own-requirement Sources/Shared/XPCPeerValidator.swift \
  'trustedPeer(connection, requirement: requirement(for: [AppConstants.bundleIdHelper]))' 'true'
mutate helper-answers-alerts Sources/Shared/IPCConnection.swift \
  'if !fromHelper && !XPCPeerValidator.isCLI(newConnection) {' 'if !XPCPeerValidator.isCLI(newConnection) {'
mutate any-peer-is-helper Sources/Shared/IPCConnection.swift \
  'newConnection.exportedObject = ProviderEndpoint(owner: self, source: fromHelper ? .helper : .app)' \
  'newConnection.exportedObject = ProviderEndpoint(owner: self, source: .helper)'
mutate helper-moves-watermark Sources/NetExt/FilterDataProvider.swift \
  'if decision == .accepted, source == .app { recordLiveWatermark(accepted) }' \
  'if decision == .accepted { recordLiveWatermark(accepted) }'
mutate helper-in-shared-peer-list Sources/Shared/XPCPeerValidator.swift \
  '        AppConstants.bundleIdCLI
    ]' '        AppConstants.bundleIdCLI,
        AppConstants.bundleIdHelper
    ]'

printf 'helper policy push: PASS\n'
