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

// 6. A switch that fails is owed and retried. Here a (managed) trigger
//    names a profile that does not exist yet.
coordinator.tunnelTriggers = { [TunnelTrigger(service: nil, whenConnected: false, profile: "Ghost")] }
_ = try coordinator.activate(profileName: "Work", reason: .user)
check("a switch to a missing profile reports failure", coordinator.applyObservedTunnelState([]) == false)
check("and is owed", coordinator.pendingTunnelSwitch?.profile == "Ghost" && coordinator.tunnelRetryOwed)
check("the active profile stays", store.activeProfileName() == "Work")
// 6b. While that trigger matches but has not switched, a gateway change is
//     set aside, and applied once the trigger stops matching.
check("a gateway delivered meanwhile is set aside", coordinator.applyObservedGatewayMAC("aa:bb:cc:dd:ee:09")
      && coordinator.applyObservedGatewayMAC(officeMAC) && store.activeProfileName() == "Work")
check("when the unsettled trigger stops matching, the gateway decides after all",
      coordinator.applyObservedTunnelState([travel]) && store.activeProfileName() == "Office")
_ = try store.createProfile(name: "Ghost", mode: .silentDeny)
check("once the profile exists the trigger works", coordinator.applyObservedTunnelState([]) && store.activeProfileName() == "Ghost")
check("nothing is owed any more", coordinator.pendingTunnelSwitch == nil && !coordinator.tunnelRetryOwed)
coordinator.tunnelTriggers = { try store.tunnelTriggers() }

// 6c. Handing back to the gateway is retried when it fails, like any
//     gateway switch. The network switch is made to fail once by renaming
//     the bound profile just before it is applied.
for t in try store.tunnelTriggers() { try coordinator.removeTunnelTrigger(id: t.id) }
try coordinator.setTunnelTrigger(TunnelTrigger(service: nil, whenConnected: true, profile: "Work"))
check("set up: VPN up selects Work", coordinator.applyObservedTunnelState([travel]) && store.activeProfileName() == "Work")
var renamedOnce = false
coordinator.networkSwitchHookForTesting = {
    guard !renamedOnce, let officeProfile = store.profile(named: "Office") else { return }
    renamedOnce = true
    var renamed = officeProfile; renamed.name = "Office 2"
    _ = try? store.updateProfile(renamed)
}
check("a hand-back that fails reports failure", coordinator.applyObservedTunnelState([]) == false && coordinator.tunnelRetryOwed)
check("and the profile has not moved yet", store.activeProfileName() == "Work")
check("the retry hands back", coordinator.applyObservedTunnelState([]) && store.activeProfileName() == "Office 2" && !coordinator.tunnelRetryOwed)
coordinator.networkSwitchHookForTesting = nil
var back = store.profile(named: "Office 2")!; back.name = "Office"; _ = try store.updateProfile(back)

// 6d. A manual pick holds when the trigger stops matching; only a new
//     gateway or another winning trigger replaces it.
check("VPN up again selects Work", coordinator.applyObservedTunnelState([travel]) && store.activeProfileName() == "Work")
_ = try coordinator.activate(profileName: "Restricted", reason: .user)
check("the VPN dropping keeps the user's pick", coordinator.applyObservedTunnelState([]) && store.activeProfileName() == "Restricted")
check("a new gateway decides again", coordinator.applyObservedGatewayMAC("aa:bb:cc:dd:ee:0a")
      && coordinator.applyObservedGatewayMAC(officeMAC) && store.activeProfileName() == "Office")
_ = try coordinator.activate(profileName: "Restricted", reason: .user)
try coordinator.setTunnelTrigger(TunnelTrigger(service: office, whenConnected: false, profile: "Ghost"))
check("editing an unrelated trigger does not undo the user's pick", store.activeProfileName() == "Ghost" || store.activeProfileName() == "Restricted")

// 6e. Triggers follow their profile: renamed with it, deleted with it.
for t in try store.tunnelTriggers() { try coordinator.removeTunnelTrigger(id: t.id) }
_ = try store.setTunnelTrigger(TunnelTrigger(service: office, whenConnected: true, profile: "Work"))
var work = store.profile(named: "Work")!; work.name = "Corp VPN"; _ = try store.updateProfile(work)
check("renaming a profile carries its trigger", (try? store.tunnelTriggers()) == [TunnelTrigger(service: office, whenConnected: true, profile: "Corp VPN")])
_ = try store.deleteProfile(name: "Corp VPN")
check("deleting a profile deletes its trigger", (try? store.tunnelTriggers()) == [])
_ = try store.createProfile(name: "Corp VPN", mode: .alert)
check("a new profile with the old name inherits nothing", (try? store.tunnelTriggers()) == [])
_ = try store.createProfile(name: "Work", mode: .silentAllow)

// 6f. Bounds.
func refused(_ t: TunnelTrigger) -> Bool { (try? store.setTunnelTrigger(t)) == nil }
check("an over-long service id is refused", refused(TunnelTrigger(service: String(repeating: "x", count: 300), whenConnected: true, profile: "Work")))
check("the unlisted-tunnel marker is not a service", refused(TunnelTrigger(service: TunnelStatus.unlistedTunnelID, whenConnected: true, profile: "Work")))
check("a control character is refused", refused(TunnelTrigger(service: "a\nb", whenConnected: true, profile: "Work")))
for i in 0..<TunnelTrigger.maximumCount { _ = try? store.setTunnelTrigger(TunnelTrigger(service: "S\(i)", whenConnected: true, profile: "Work")) }
check("the number of triggers is bounded", refused(TunnelTrigger(service: "one-too-many", whenConnected: true, profile: "Work")))
check("but replacing an existing condition still works", !refused(TunnelTrigger(service: "S0", whenConnected: true, profile: "Ghost")))
for t in try store.tunnelTriggers() { _ = try store.removeTunnelTrigger(id: t.id) }
let decoded = try JSONDecoder().decode(TunnelTrigger.self, from: Data(#"{"service":"","whenConnected":true,"profile":"Work"}"#.utf8))
check("a decoded empty service means any VPN", decoded.service == nil)
check("an unlisted tunnel counts for any VPN, never for a named one",
      anyUp.matches([TunnelStatus.unlistedTunnelID]) && !officeUp.matches([TunnelStatus.unlistedTunnelID]))

// 7. An unreadable trigger list never blocks gateway bindings.
coordinator.tunnelTriggers = { throw ProfileValidationError.invalidTunnelTrigger("test") }
let beforeUnreadable = store.activeProfileName()
check("an unreadable list changes nothing on a VPN change", coordinator.applyObservedTunnelState([office]) && store.activeProfileName() == beforeUnreadable)
check("and the gateway binding decides", coordinator.applyObservedGatewayMAC("aa:bb:cc:dd:ee:03") && coordinator.applyObservedGatewayMAC(officeMAC)
      && store.activeProfileName() == "Office")

// 8. Edits can be refused (MDM).
coordinator.tunnelTriggers = { try store.tunnelTriggers() }
coordinator.triggerEditRefusal = { "VPN triggers are set by MDM" }
do { try coordinator.setTunnelTrigger(TunnelTrigger(service: nil, whenConnected: true, profile: "Work")); check("a refused edit throws", false) }
catch { check("a refused edit throws: \(error.localizedDescription)", true) }

// 9. A named VPN whose service is completely absent (some clients remove
//    their service when disconnected) is "not connected".
let absent = TunnelTrigger(service: "CloudflareWARP", whenConnected: false, profile: "Restricted")
check("a named VPN that is absent matches its not-connected trigger", absent.matches([]) && absent.matches([office]))
check("and wins over any-VPN-not-connected", TunnelTrigger.winner([anyDown, absent], connected: []) == absent)
coordinator.triggerEditRefusal = nil
_ = try coordinator.activate(profileName: "Office", reason: .user)
check("set up: no trigger, the user's pick", coordinator.applyObservedTunnelState([travel]) && store.activeProfileName() == "Office")
try coordinator.setTunnelTrigger(absent)
check("with its service gone, the trigger switches", store.activeProfileName() == "Restricted")
for t in try store.tunnelTriggers() { _ = try store.removeTunnelTrigger(id: t.id) }

// 10. Remembering the VPN services seen.
let t0 = Date(timeIntervalSince1970: 1_800_000_000)
check("nothing is remembered at first", KnownTunnelServices.all(in: store).isEmpty)
check("services seen are remembered",
      try KnownTunnelServices.remember([TunnelService(id: "CloudflareWARP", name: nil), TunnelService(id: office, name: "Office VPN")], in: store, at: t0))
check("they are listed by name, the unnamed one by its id",
      KnownTunnelServices.all(in: store).map(\.displayName) == ["CloudflareWARP", "Office VPN"])
check("seeing the same again writes nothing",
      try !KnownTunnelServices.remember([TunnelService(id: office, name: "Office VPN")], in: store, at: t0.addingTimeInterval(60)))
check("a service that disappears is still listed",
      try !KnownTunnelServices.remember([TunnelService(id: office, name: "Office VPN")], in: store, at: t0.addingTimeInterval(120))
      && KnownTunnelServices.all(in: store).contains { $0.id == "CloudflareWARP" })
_ = try KnownTunnelServices.remember([TunnelService(id: office, name: nil)], in: store, at: t0.addingTimeInterval(180))
check("a name seen before is kept when the service now has none",
      KnownTunnelServices.all(in: store).first { $0.id == office }?.name == "Office VPN")
check("a renamed service is updated",
      try KnownTunnelServices.remember([TunnelService(id: office, name: "HQ VPN")], in: store, at: t0.addingTimeInterval(240))
      && KnownTunnelServices.all(in: store).first { $0.id == office }?.name == "HQ VPN")
let many = (0..<(KnownTunnelServices.maximumCount + 10)).map { TunnelService(id: "S\($0)", name: nil) }
_ = try KnownTunnelServices.remember(many, in: store, at: t0.addingTimeInterval(1000))
check("the list is bounded", KnownTunnelServices.all(in: store).count == KnownTunnelServices.maximumCount)

if failures > 0 { print("tunnel trigger harness: \(failures) FAILURES"); exit(1) }
print("tunnel trigger harness: PASS (all checks)")
SWIFT

xcrun swiftc -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 \
  "$ROOT"/Sources/Shared/*.swift "$TMP/main.swift" -lsqlite3 -o "$TMP/run"
"$TMP/run" "$TMP/profiles.sqlite"
