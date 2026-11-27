#!/usr/bin/env bash
# Checks MDM-managed preferences: how the managed plist is read (all or
# nothing), how managed profiles, bindings and rules are applied to the store
# without touching the user's own rules, and how a managed tunnel switch and
# LockSettings refuse changes from the app. Compiled from Sources/Shared.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-managed.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
HELPER="$ROOT/Sources/Helper/HelperService.swift"

fail() { printf 'managed preferences verification: FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'managed preferences verification: PASS: %s\n' "$*"; }

grep -Fq 'if ManagedPolicySync.managedRuleIDs(in: store).contains(id) {' "$HELPER" \
  || fail "the helper lets the app delete a rule MDM set"
grep -Fq 'self?.managed.tunnelTriggers != nil ? "VPN triggers are set by MDM" : nil' "$HELPER" \
  || fail "the helper lets the app change managed VPN triggers"
grep -Fq 'if let managed = self?.managed.tunnelTriggers { return managed }' "$HELPER" \
  || fail "managed VPN triggers no longer take precedence over the stored ones"
pass "the helper gives managed values precedence and refuses changes to them"

cat > "$TMP/main.swift" <<'SWIFT'
import Foundation

var failures = 0
func check(_ name: String, _ condition: Bool) {
    print("managed preferences harness: \(condition ? "PASS" : "FAIL"): \(name)")
    if !condition { failures += 1 }
}
func refused(_ dict: [String: Any]) -> Bool { (try? ManagedPreferences.parse(dict)) == nil }

let dir = CommandLine.arguments[1]
let plistPath = dir + "/io.isaaclins.freesnitch.plist"

// 1. Reading the file.
check("no file means not managed", (try? ManagedPreferences.read(path: plistPath)) == .some(nil))
try! Data("not a plist".utf8).write(to: URL(fileURLWithPath: plistPath))
check("an unreadable file throws instead of looking unmanaged", (try? ManagedPreferences.read(path: plistPath)) == nil)

let full: [String: Any] = [
    "LockSettings": true,
    "HelperDeliversPolicy": true,
    "VPNTriggers": [["Profile": "Work", "When": "connected"], ["Profile": "Restricted", "When": "disconnected"]],
    "Profiles": [["Name": "Work", "Mode": "silentAllow"], ["Name": "Restricted", "Mode": "silentDeny"]],
    "Rules": [
        ["Host": "*.teamviewer.com", "Profile": "Restricted", "Comment": "remote support"],
        ["BundleID": "com.tinyspeck.slackmacgap", "TeamID": "BQR82RBBHL"],
        ["Host": "ads.example", "Action": "deny"],
        ["BundleID": "com.example.Unwanted", "Action": "deny"],
    ],
    "NetworkBindings": [["GatewayMAC": "AA-BB-CC-DD-EE-01", "Profile": "Work"]],
]
let data = try! PropertyListSerialization.data(fromPropertyList: full, format: .xml, options: 0)
try! data.write(to: URL(fileURLWithPath: plistPath))
let prefs = try! ManagedPreferences.read(path: plistPath)!
check("the file is read", prefs.lockSettings && prefs.helperDeliversPolicy && prefs.rules.count == 4 && prefs.profiles.count == 2)
check("the VPN triggers are read",
      prefs.tunnelTriggers == [TunnelTrigger(service: nil, whenConnected: true, profile: "Work"),
                               TunnelTrigger(service: nil, whenConnected: false, profile: "Restricted")])
check("bindings are normalized", prefs.bindings.first?.gatewayMAC == "aa:bb:cc:dd:ee:01")
check("managed rules sit above user rules and are grouped",
      prefs.rules.allSatisfy { $0.priority > 100 && $0.groupName == ManagedPreferences.ruleGroupName })
check("a deny may name a bundle id without a team", prefs.rules[3].action == .deny && prefs.rules[3].processTeamId == nil)
check("ids are stable across reads", (try! ManagedPreferences.parse(full)).rules.map(\.id) == prefs.rules.map(\.id))

// 2. All or nothing.
check("an allow naming a bundle id without its team refuses the whole set",
      refused(["Rules": [["Host": "ok.example"], ["BundleID": "com.example.App"]]]))
check("an unknown action is refused", refused(["Rules": [["Host": "x.example", "Action": "ask"]]]))
check("an entry that matches everything is refused", refused(["Rules": [["Comment": "all"]]]))
check("a bad mode is refused", refused(["Profiles": [["Name": "X", "Mode": "loud"]]]))
check("Always cannot be created", refused(["Profiles": [["Name": "always"]]]))
check("a bad MAC is refused", refused(["NetworkBindings": [["GatewayMAC": "nope", "Profile": "Work"]]]))
check("a trigger without When is refused", refused(["VPNTriggers": [["Profile": "Work"]]]))
check("two triggers with one condition are refused",
      refused(["VPNTriggers": [["Profile": "Work", "When": "connected"], ["Profile": "Other", "When": "connected"]]]))
check("a trigger for one VPN service is read",
      (try? ManagedPreferences.parse(["VPNTriggers": [["Profile": "Work", "When": "connected", "Service": "ABC"]]]))?
        .tunnelTriggers?.first?.service == "ABC")

// 3. Applying to a real store.
let store = try RuleStore(path: dir + "/rules.sqlite")
func rules(_ profile: String? = nil) -> [Rule] { (try? store.allRules(profile: profile)) ?? [] }
let userRule = Rule(remoteHost: "mine.example", action: .allow, scope: .domain)
_ = try store.mutatePolicy { $0.rules.append(userRule) }
let first = try ManagedPolicySync.apply(prefs, to: store)
check("missing profiles are created with their modes",
      first.createdProfiles == ["Work", "Restricted"] && store.profile(named: "Restricted")?.mode == .silentDeny)
check("the binding is stored", store.networkBinding(forGatewayMAC: "aa:bb:cc:dd:ee:01")?.profileName == "Work")
check("every managed rule is stored", first.addedRules == 4 && Set(rules().map(\.id)).isSuperset(of: prefs.rules.map(\.id)))
check("a managed rule keeps its profile", rules("Restricted").contains { $0.remoteHost == "*.teamviewer.com" })
check("the user's own rule is untouched", rules().contains { $0.id == userRule.id })
check("their ids are remembered", ManagedPolicySync.managedRuleIDs(in: store) == Set(prefs.rules.map(\.id)))
let again = try ManagedPolicySync.apply(prefs, to: store)
check("applying the same set again changes nothing", !again.policyChanged && again.createdProfiles.isEmpty)

_ = try store.mutatePolicy { draft in
    if let i = draft.rules.firstIndex(where: { $0.id == prefs.rules[1].id }) { draft.rules[i].enabled = false }
}
check("a managed rule the user disabled is restored", try ManagedPolicySync.apply(prefs, to: store).addedRules == 1
      && (rules().first { $0.id == prefs.rules[1].id }?.enabled == true))

var fewer = prefs
fewer.rules = Array(prefs.rules.prefix(2))
let shrink = try ManagedPolicySync.apply(fewer, to: store)
check("a rule MDM no longer sends is removed", shrink.removedRules == 2 && !(rules().contains { $0.id == prefs.rules[3].id }))
check("the user's rule survives that too", rules().contains { $0.id == userRule.id })
let cleared = try ManagedPolicySync.apply(.none, to: store)
check("with no managed file, every managed rule is removed", cleared.removedRules == 2 && ManagedPolicySync.managedRuleIDs(in: store).isEmpty)
check("and still the user's rule stays", rules().contains { $0.id == userRule.id })

var orphan = ManagedPreferences.none
orphan.rules = try ManagedPreferences.parse(["Rules": [["Host": "x.example", "Profile": "Nowhere"]]]).rules
let orphanOutcome = try ManagedPolicySync.apply(orphan, to: store)
check("a rule for a missing profile is reported, not stored", orphanOutcome.addedRules == 0 && orphanOutcome.problems.count == 1)

// 4. Precedence and locking through the coordinator, wired as the helper does.
final class NoGateway: GatewayMACProviding, @unchecked Sendable { func currentGatewayMAC() -> String? { nil } }
_ = try ManagedPolicySync.apply(prefs, to: store)
let coordinator = ProfileCoordinator(store: store, watcher: GatewayMACWatcher(provider: NoGateway()))
var managed = prefs
coordinator.tunnelTriggers = { if let t = managed.tunnelTriggers { return t }; return try store.tunnelTriggers() }
coordinator.triggerEditRefusal = { managed.tunnelTriggers != nil ? "VPN triggers are set by MDM" : nil }
coordinator.userSwitchRefusal = {
    guard managed.lockSettings, let t = managed.tunnelTriggers, let connected = coordinator.currentTunnelConnected,
          TunnelTrigger.winner(t, connected: connected) != nil else { return nil }
    return "the profile follows a VPN trigger set by MDM"
}
check("managed triggers apply with nothing stored",
      coordinator.applyObservedTunnelState([]) && store.activeProfileName() == "Restricted")
do { try coordinator.setTunnelTrigger(TunnelTrigger(service: nil, whenConnected: true, profile: "Restricted")); check("the app cannot change managed triggers", false) }
catch { check("the app cannot change managed triggers", true) }
do { _ = try coordinator.activate(profileName: "Work", reason: .user); check("LockSettings refuses a manual pick", false) }
catch { check("LockSettings refuses a manual pick: \(error.localizedDescription)", true) }
check("and the managed profile stays", store.activeProfileName() == "Restricted")
check("the VPN itself still switches", coordinator.applyObservedTunnelState(["SVC"]) && store.activeProfileName() == "Work")
managed.lockSettings = false
check("without LockSettings the user may pick", (try? coordinator.activate(profileName: "Restricted", reason: .user)) != nil)
managed = .none
check("once unmanaged, the app may save a trigger",
      (try? coordinator.setTunnelTrigger(TunnelTrigger(service: nil, whenConnected: true, profile: "Work"))) != nil)

if failures > 0 { print("managed preferences harness: \(failures) FAILURES"); exit(1) }
print("managed preferences harness: PASS (all checks)")
SWIFT

xcrun swiftc -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 \
  "$ROOT"/Sources/Shared/*.swift "$TMP/main.swift" -lsqlite3 -o "$TMP/run"
"$TMP/run" "$TMP"
