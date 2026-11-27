#!/usr/bin/env bash
# Checks the opt-in tunnel profile switch: which profile is active while
# Cloudflare WARP carries this Mac's traffic and which while it does not,
# how it ranks against gateway bindings, and that a user's pick is never
# undone by a repeated delivery. Compiled from the shipping Sources/Shared.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-tunnel-switch.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# A tunnel switch is a profile switch: it must stay unable to touch a flow.
for symbol in NEFilterFlow dropFlow resumeFlow pauseFlow terminateFlow closeFlow; do
  for file in "$ROOT/Sources/Shared/TunnelProfileSwitch.swift" "$ROOT/Sources/Shared/TunnelStatus.swift" "$ROOT/Sources/Shared/TunnelMonitor.swift"; do
    if grep -Fq -- "$symbol" "$file"; then
      echo "tunnel switch verification: FAIL: $file references $symbol" >&2
      exit 1
    fi
  done
done
echo "tunnel switch verification: PASS: no tunnel source can touch a live flow"

cat > "$TMP/main.swift" <<'SWIFT'
import Foundation

var failures = 0
func check(_ name: String, _ condition: Bool) {
    print("tunnel switch harness: \(condition ? "PASS" : "FAIL"): \(name)")
    if !condition { failures += 1 }
}

final class FixedGatewayProvider: GatewayMACProviding, @unchecked Sendable {
    var value: String?
    init(_ value: String?) { self.value = value }
    func currentGatewayMAC() -> String? { value }
}

let store = try RuleStore(path: CommandLine.arguments[1])
_ = try store.createProfile(name: "Work", mode: .silentAllow)
_ = try store.createProfile(name: "Restricted", mode: .silentDeny)
_ = try store.createProfile(name: "Office", mode: .alert)
let homeMAC = "aa:bb:cc:dd:ee:01"
_ = try store.bindGatewayMAC(homeMAC, toProfile: "Office")

let coordinator = ProfileCoordinator(store: store, watcher: GatewayMACWatcher(provider: FixedGatewayProvider(homeMAC)))
var switches: [(ProfileCoordinator.SwitchReason, String)] = []
coordinator.onSwitch = { switches.append(($0.reason, $0.notice.activeProfile)) }

// 1. Off by default: nothing stored means off, and the tunnel changes nothing.
check("the setting is off when never saved", (try? store.tunnelProfileSwitch()) == .off)
check("the gateway binding applies", coordinator.applyObservedGatewayMAC(homeMAC) && store.activeProfileName() == "Office")
check("with the setting off, WARP coming up changes nothing",
      coordinator.applyObservedTunnelState(true) && store.activeProfileName() == "Office")
check("nor going down", coordinator.applyObservedTunnelState(false) && store.activeProfileName() == "Office")

// 2. Saving validates the names.
do { try store.setTunnelProfileSwitch(TunnelProfileSwitch(enabled: true, connectedProfile: "Wrok", disconnectedProfile: nil)); check("a missing profile is refused", false) }
catch { check("a missing profile is refused: \(error.localizedDescription)", true) }
do { try store.setTunnelProfileSwitch(TunnelProfileSwitch(enabled: true, connectedProfile: Profile.alwaysName, disconnectedProfile: nil)); check("Always is refused", false) }
catch { check("Always is refused", true) }
check("a refused save leaves the setting off", (try? store.tunnelProfileSwitch()) == .off)

// 3. On: the tunnel decides, both ways.
let setting = TunnelProfileSwitch(enabled: true, connectedProfile: "Work", disconnectedProfile: "Restricted")
try store.setTunnelProfileSwitch(setting)
check("the setting round-trips through the store", (try? store.tunnelProfileSwitch()) == setting)
switches.removeAll()
check("WARP up switches to Work", coordinator.applyObservedTunnelState(true) && store.activeProfileName() == "Work")
check("reported as a tunnel switch", switches.last?.0 == .tunnel && switches.last?.1 == "Work")
check("a repeated delivery does nothing", coordinator.applyObservedTunnelState(true) && switches.count == 1)
check("the gateway does not override the tunnel",
      coordinator.applyObservedGatewayMAC("aa:bb:cc:dd:ee:02") && coordinator.applyObservedGatewayMAC(homeMAC)
      && store.activeProfileName() == "Work")
check("WARP down switches to Restricted", coordinator.applyObservedTunnelState(false) && store.activeProfileName() == "Restricted")
check("and can be undone like any switch", coordinator.canUndo)

// 4. A user's pick holds until the tunnel really changes state.
_ = try coordinator.activate(profileName: "Office", reason: .user)
check("a repeated down delivery does not undo the user's pick",
      coordinator.applyObservedTunnelState(false) && store.activeProfileName() == "Office")
check("the next real change switches again", coordinator.applyObservedTunnelState(true) && store.activeProfileName() == "Work")

// 5. One side unset: the gateway decides that side.
try store.setTunnelProfileSwitch(TunnelProfileSwitch(enabled: true, connectedProfile: "Work", disconnectedProfile: nil))
check("WARP down with no profile named falls back to the gateway binding",
      coordinator.applyObservedTunnelState(false) && store.activeProfileName() == "Office")
check("WARP up still switches", coordinator.applyObservedTunnelState(true) && store.activeProfileName() == "Work")

// 6. A profile deleted after it was named: the switch fails, is kept as
//    owed, and works once the profile exists again.
try store.setTunnelProfileSwitch(TunnelProfileSwitch(enabled: true, connectedProfile: "Work", disconnectedProfile: "Restricted"))
_ = try coordinator.activate(profileName: "Work", reason: .user)
_ = try store.deleteProfile(name: "Restricted")
check("a switch to a deleted profile reports failure", coordinator.applyObservedTunnelState(false) == false)
check("and is kept as owed", coordinator.pendingTunnelSwitch?.profile == "Restricted" && coordinator.pendingTunnelSwitch?.up == false)
check("the active profile stays where it was", store.activeProfileName() == "Work")
_ = try store.createProfile(name: "Restricted", mode: .silentDeny)
check("a retry works once the profile exists", coordinator.applyObservedTunnelState(false) && store.activeProfileName() == "Restricted")
check("and nothing is owed any more", coordinator.pendingTunnelSwitch == nil)

// 7. An unreadable setting never blocks gateway bindings.
coordinator.tunnelSwitchSettings = { throw ProfileValidationError.invalidTunnelProfileSwitch("test") }
check("an unreadable setting changes nothing on a tunnel change", coordinator.applyObservedTunnelState(true) && store.activeProfileName() == "Restricted")
check("and the gateway binding decides again", coordinator.applyObservedGatewayMAC("aa:bb:cc:dd:ee:03") && coordinator.applyObservedGatewayMAC(homeMAC)
      && store.activeProfileName() == "Office")

// 8. Disabling hands the profile back to the gateway on the next tunnel change.
coordinator.tunnelSwitchSettings = { try store.tunnelProfileSwitch() }
try store.setTunnelProfileSwitch(TunnelProfileSwitch(enabled: false, connectedProfile: "Work", disconnectedProfile: "Restricted"))
check("with the setting disabled, WARP up changes nothing", coordinator.applyObservedTunnelState(true) && store.activeProfileName() == "Office")

if failures > 0 { print("tunnel switch harness: \(failures) FAILURES"); exit(1) }
print("tunnel switch harness: PASS (all checks)")
SWIFT

xcrun swiftc -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 \
  "$ROOT"/Sources/Shared/*.swift "$TMP/main.swift" -lsqlite3 -o "$TMP/run"
"$TMP/run" "$TMP/profiles.sqlite"
