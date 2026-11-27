#!/usr/bin/env bash
# Checks VPN triggers ("activate this profile when <a VPN> is <connected |
# not connected>"): which trigger wins, how triggers rank against gateway
# bindings, that a user's pick is never undone by a repeated delivery, and
# that a failed switch is retried. Compiled from the shipping Sources/Shared.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-tunnel-triggers.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# A trigger is a profile switch: it must stay unable to touch a flow.
for symbol in NEFilterFlow dropFlow resumeFlow pauseFlow terminateFlow closeFlow; do
  for file in TunnelTrigger.swift TunnelStatus.swift TunnelMonitor.swift; do
    if grep -Fq -- "$symbol" "$ROOT/Sources/Shared/$file"; then
      echo "tunnel trigger verification: FAIL: $file references $symbol" >&2
      exit 1
    fi
  done
done
echo "tunnel trigger verification: PASS: no VPN trigger source can touch a live flow"

cat > "$TMP/main.swift" <<'SWIFT'
import Foundation

var failures = 0
func check(_ name: String, _ condition: Bool) {
    print("tunnel trigger harness: \(condition ? "PASS" : "FAIL"): \(name)")
    if !condition { failures += 1 }
}

final class FixedGatewayProvider: GatewayMACProviding, @unchecked Sendable {
    var value: String?
    init(_ value: String?) { self.value = value }
    func currentGatewayMAC() -> String? { value }
}

let office = "8E3F2A61-OFFICE"
let travel = "C07D9B12-TRAVEL"

// 1. Which trigger wins.
let anyUp = TunnelTrigger(service: nil, whenConnected: true, profile: "A")
let anyDown = TunnelTrigger(service: nil, whenConnected: false, profile: "B")
let officeUp = TunnelTrigger(service: office, whenConnected: true, profile: "C")
let officeDown = TunnelTrigger(service: office, whenConnected: false, profile: "D")
let all = [anyUp, anyDown, officeUp, officeDown]
check("nothing connected: a named not-connected trigger beats any-not-connected", TunnelTrigger.winner(all, connected: []) == officeDown)
check("the named VPN connected beats any connected", TunnelTrigger.winner(all, connected: [office]) == officeUp)
check("another VPN connected: any-connected beats the named not-connected", TunnelTrigger.winner(all, connected: [travel]) == anyUp)
check("no triggers, no winner", TunnelTrigger.winner([], connected: [office]) == nil)
check("only a not-connected trigger and a VPN up: no winner", TunnelTrigger.winner([anyDown], connected: [travel]) == nil)
check("an empty service means any VPN", TunnelTrigger(service: "", whenConnected: true, profile: "A") == anyUp)
check("one trigger per condition", anyUp.id == TunnelTrigger(service: nil, whenConnected: true, profile: "Z").id && anyUp.id != anyDown.id)

// 2. Stored triggers.
let store = try RuleStore(path: CommandLine.arguments[1])
_ = try store.createProfile(name: "Work", mode: .silentAllow)
_ = try store.createProfile(name: "Restricted", mode: .silentDeny)
_ = try store.createProfile(name: "Office", mode: .alert)
check("no triggers when none were saved", (try? store.tunnelTriggers()) == [])
do { _ = try store.setTunnelTrigger(TunnelTrigger(service: nil, whenConnected: true, profile: "Wrok")); check("a missing profile is refused", false) }
catch { check("a missing profile is refused", true) }
do { _ = try store.setTunnelTrigger(TunnelTrigger(service: nil, whenConnected: true, profile: Profile.alwaysName)); check("Always is refused", false) }
catch { check("Always is refused", true) }
_ = try store.setTunnelTrigger(TunnelTrigger(service: nil, whenConnected: true, profile: "Office"))
let replaced = try store.setTunnelTrigger(TunnelTrigger(service: nil, whenConnected: true, profile: "Work"))
check("a second trigger for the same condition replaces the first", replaced == [TunnelTrigger(service: nil, whenConnected: true, profile: "Work")])
check("removing by id works", try store.removeTunnelTrigger(id: "*|up").isEmpty)

// 3. The coordinator.
let officeMAC = "aa:bb:cc:dd:ee:01"
_ = try store.bindGatewayMAC(officeMAC, toProfile: "Office")
let coordinator = ProfileCoordinator(store: store, watcher: GatewayMACWatcher(provider: FixedGatewayProvider(officeMAC)))
var switches: [ProfileCoordinator.SwitchReason] = []
coordinator.onSwitch = { switches.append($0.reason) }
check("the gateway binding applies", coordinator.applyObservedGatewayMAC(officeMAC) && store.activeProfileName() == "Office")
check("with no triggers, a VPN changes nothing", coordinator.applyObservedTunnelState([travel]) && store.activeProfileName() == "Office")

try coordinator.setTunnelTrigger(TunnelTrigger(service: nil, whenConnected: true, profile: "Work"))
check("adding a trigger applies it to the VPN state at once", store.activeProfileName() == "Work" && switches.last == .tunnel)
try coordinator.setTunnelTrigger(TunnelTrigger(service: nil, whenConnected: false, profile: "Restricted"))
check("a repeated delivery does nothing", { let n = switches.count; return coordinator.applyObservedTunnelState([travel]) && switches.count == n }())
check("the gateway does not override a matching trigger",
      coordinator.applyObservedGatewayMAC("aa:bb:cc:dd:ee:02") && coordinator.applyObservedGatewayMAC(officeMAC)
      && store.activeProfileName() == "Work")
check("no VPN: the not-connected trigger wins", coordinator.applyObservedTunnelState([]) && store.activeProfileName() == "Restricted")
check("and can be undone", coordinator.canUndo)

// 4. A user's pick holds until another trigger wins.
_ = try coordinator.activate(profileName: "Office", reason: .user)
check("a repeated delivery does not undo the user's pick", coordinator.applyObservedTunnelState([]) && store.activeProfileName() == "Office")
check("a VPN coming up switches again", coordinator.applyObservedTunnelState([office]) && store.activeProfileName() == "Work")

// 5. A named VPN beats any VPN; removing the trigger hands back.
try coordinator.setTunnelTrigger(TunnelTrigger(service: office, whenConnected: true, profile: "Office"))
check("the named VPN's trigger wins while it is up", store.activeProfileName() == "Office")
check("another VPN alone: any-VPN applies", coordinator.applyObservedTunnelState([travel]) && store.activeProfileName() == "Work")
try coordinator.removeTunnelTrigger(id: "*|up")
try coordinator.removeTunnelTrigger(id: "*|down")
check("with no trigger matching, the gateway binding decides again", store.activeProfileName() == "Office")

// 6. A deleted profile: the switch fails, is owed, and works once it exists.
try coordinator.setTunnelTrigger(TunnelTrigger(service: nil, whenConnected: false, profile: "Restricted"))
_ = try coordinator.activate(profileName: "Work", reason: .user)
_ = try store.deleteProfile(name: "Restricted")
check("a switch to a deleted profile reports failure", coordinator.applyObservedTunnelState([]) == false)
check("and is owed", coordinator.pendingTunnelSwitch?.profile == "Restricted")
check("the active profile stays", store.activeProfileName() == "Work")
_ = try store.createProfile(name: "Restricted", mode: .silentDeny)
check("a retry works once it exists", coordinator.applyObservedTunnelState([]) && store.activeProfileName() == "Restricted")
check("nothing is owed any more", coordinator.pendingTunnelSwitch == nil)

// 7. An unreadable trigger list never blocks gateway bindings.
coordinator.tunnelTriggers = { throw ProfileValidationError.invalidTunnelTrigger("test") }
check("an unreadable list changes nothing on a VPN change", coordinator.applyObservedTunnelState([office]) && store.activeProfileName() == "Restricted")
check("and the gateway binding decides", coordinator.applyObservedGatewayMAC("aa:bb:cc:dd:ee:03") && coordinator.applyObservedGatewayMAC(officeMAC)
      && store.activeProfileName() == "Office")

// 8. Edits can be refused (MDM).
coordinator.tunnelTriggers = { try store.tunnelTriggers() }
coordinator.triggerEditRefusal = { "VPN triggers are set by MDM" }
do { try coordinator.setTunnelTrigger(TunnelTrigger(service: nil, whenConnected: true, profile: "Work")); check("a refused edit throws", false) }
catch { check("a refused edit throws: \(error.localizedDescription)", true) }

if failures > 0 { print("tunnel trigger harness: \(failures) FAILURES"); exit(1) }
print("tunnel trigger harness: PASS (all checks)")
SWIFT

xcrun swiftc -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 \
  "$ROOT"/Sources/Shared/*.swift "$TMP/main.swift" -lsqlite3 -o "$TMP/run"
"$TMP/run" "$TMP/profiles.sqlite"
