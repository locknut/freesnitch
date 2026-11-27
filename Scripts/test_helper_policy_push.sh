#!/usr/bin/env bash
# Static checks for the helper's direct policy delivery to the network
# extension. The delivery itself needs a running, approved extension, so this
# pins the invariants that keep it narrow: the helper is never the alert
# connection, it is not added to the identities the helper's own listener
# accepts, it delivers only while a helper-driven feature is on, and the
# extension never applies an older relay over the helper's newer policy.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fail() { printf 'helper policy push: FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'helper policy push: PASS: %s\n' "$*"; }

IPC="$ROOT/Sources/Shared/IPCConnection.swift"
PEER="$ROOT/Sources/Shared/XPCPeerValidator.swift"
HELPER="$ROOT/Sources/Helper/HelperService.swift"
PUSHER="$ROOT/Sources/Helper/ExtensionPolicyPusher.swift"
PROVIDER="$ROOT/Sources/NetExt/FilterDataProvider.swift"

grep -Fq 'if !fromHelper && !XPCPeerValidator.isCLI(newConnection) {' "$IPC" \
  || fail "the extension may make the helper its alert connection"
pass "the helper never becomes the connection that answers alerts"

permitted="$(awk '/permittedPeerIdentifiers: \[String\] = \[/{f=1} f{print} f&&/\]/{exit}' "$PEER")"
grep -Fq 'bundleIdHelper' <<<"$permitted" \
  && fail "the helper identity was added to the shared peer list, which the helper's own listener accepts"
pass "the helper identity is accepted only by the extension, not by the helper's listener"

grep -Fq 'trustedPeer(connection, requirement: requirement(for: [AppConstants.bundleIdHelper]))' "$PEER" \
  || fail "the helper is no longer checked against its own code requirement"
pass "the helper is checked against its signed identity"

grep -Fq 'guard isEnabled() else {' "$PUSHER" || fail "the pusher no longer checks whether it is enabled"
grep -Fq 'isEnabled: { [weak self] in self?.helperDeliversPolicy() ?? false }' "$HELPER" \
  || fail "the helper delivers policy without a feature that needs it"
pass "the helper delivers policy only while a helper-driven feature is on"

grep -Fq 'if authority == .sameSession, source == .app, snapshotOrigin == .live, liveSnapshotFromHelper {' "$PROVIDER" \
  || fail "an older app relay is no longer told apart from a rollback"
grep -Fq 'let status = SharedRuleBridge.SnapshotStatus.ready(for: current)' "$PROVIDER" \
  || fail "the newer policy is not the one reported after an older relay"
pass "an older app relay after the helper's newer delivery keeps the newer policy and asks for no restart"

printf 'helper policy push: PASS\n'
