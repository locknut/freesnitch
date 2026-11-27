#!/usr/bin/env bash
# Checks the opt-in fail-closed configuration: how an MDM VendorConfig value
# is read, which recovery entries are refused, and which flows the recovery
# policy lets through when the extension holds no policy. The matching runs
# through the shipping RuleMatcher, exactly as the extension evaluates it.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-fail-closed.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
FILTER="$ROOT/Sources/NetExt/FilterDataProvider.swift"

fail() { printf 'fail-closed verification: FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'fail-closed verification: PASS: %s\n' "$*"; }

# Static: fail-open stays the default, and fail-closed only ever stands in for
# a missing policy, never for one that is in force.
grep -Fq 'if snapshot == nil, let failClosedSnapshot, let failClosedRules {' "$FILTER" \
  || fail "the recovery policy is no longer limited to the no-policy state"
grep -Fq 'guard policy.enabled else { failClosedRules = nil; failClosedSnapshot = nil; return }' "$FILTER" \
  || fail "fail-closed is no longer off unless enabled"
grep -Fq 'guard let snapshot = policy.snapshot else' "$FILTER" || fail "the fail-open no-policy path is gone"
grep -Fq 'setFailClosed(FailClosedPolicy.builtInRecoveryRules)' "$FILTER" \
  || fail "a malformed fail-closed configuration no longer keeps fail-closed on"
pass "fail-open stays the default; fail-closed only replaces a missing policy"

grep -Fq 'DispatchTime.now().uptimeNanoseconds &- lastPolicyDeliveryNanos > maximumPolicyAgeNanos' "$FILTER" \
  || fail "a policy older than MaximumPolicyAge is no longer treated as no policy"
grep -Fq 'lastPolicyDeliveryNanos = DispatchTime.now().uptimeNanoseconds' "$FILTER" \
  || fail "a delivered policy no longer refreshes its age"
recovery_body="$(awk '/private func currentPolicy\(\)/{f=1} f{print} f&&/^    }$/{exit}' "$FILTER")"
grep -Fq 'PSLog' <<<"$(sed -n '/snapshotLock.lock()/,/snapshotLock.unlock()/p' <<<"$recovery_body")" \
  && fail "currentPolicy logs while holding the policy lock"
pass "an undelivered policy expires into fail-closed (opt-in), logged outside the lock"

cat > "$TMP/main.swift" <<'SWIFT'
import Foundation

var failures = 0
func check(_ name: String, _ condition: Bool) {
    print("fail-closed harness: \(condition ? "PASS" : "FAIL"): \(name)")
    if !condition { failures += 1 }
}
func refused(_ value: Any) -> Bool {
    (try? FailClosedPolicy.parse(value)) == nil
}

// 1. Reading the provider configuration.
check("no key is off", (try? FailClosedPolicy.read(fromVendorConfiguration: nil)) == .off
      && (try? FailClosedPolicy.read(fromVendorConfiguration: ["other": 1])) == .off)
check("Enabled false is off", (try? FailClosedPolicy.parse(["Enabled": false]))?.enabled == false)
check("a non-dictionary value is refused", refused("yes"))

let config: [String: Any] = [
    "Enabled": true,
    "RecoveryEntries": [
        ["Host": "*.teamviewer.com", "Comment": "TeamViewer"],
        ["Port": 5938, "Comment": "TeamViewer direct"],
        ["BundleID": "com.example.Support", "TeamID": "ABCDE12345"],
        ["Host": "login.microsoftonline.com"],
        ["Path": "/Applications/Example Remote.app"],
        ["Address": "162.159.197.0/24", "Port": 443],
    ],
]
let policy = try! FailClosedPolicy.parse(config)
check("an MDM-style dictionary is read", policy.enabled && policy.recoveryRules.count == 6)
check("every recovery rule allows and is grouped", policy.recoveryRules.allSatisfy { $0.action == .allow && $0.groupName == FailClosedPolicy.groupName })
check("built-in Apple entries come first", policy.effectiveRules.prefix(FailClosedPolicy.builtInRecoveryRules.count).elementsEqual(FailClosedPolicy.builtInRecoveryRules))

// 1b. MaximumPolicyAge.
let aged = try! FailClosedPolicy.parse(["Enabled": true, "MaximumPolicyAge": 120])
check("MaximumPolicyAge is read", aged.maximumPolicyAge == 120)
check("a policy within the age is fresh", !aged.policyIsStale(age: 119))
check("a policy past the age is stale", aged.policyIsStale(age: 121))
check("without MaximumPolicyAge a policy never goes stale", !policy.policyIsStale(age: 1_000_000))
check("with fail-closed off nothing goes stale",
      !(try! FailClosedPolicy.parse(["Enabled": false, "MaximumPolicyAge": 120])).policyIsStale(age: 1_000_000))
check("an age below the minimum is refused", refused(["Enabled": true, "MaximumPolicyAge": 10]))
check("an age given as text is refused", refused(["Enabled": true, "MaximumPolicyAge": "120"]))

// 2. Entries that would be unsafe or meaningless are refused.
check("an empty entry (allow everything) is refused", refused(["Enabled": true, "RecoveryEntries": [["Comment": "x"]]]))
check("a bundle id without its team is refused", refused(["Enabled": true, "RecoveryEntries": [["BundleID": "com.example.App"]]]))
check("a team without a bundle id is refused", refused(["Enabled": true, "RecoveryEntries": [["TeamID": "ABCDE12345"]]]))
check("a relative path is refused", refused(["Enabled": true, "RecoveryEntries": [["Path": "Applications/X.app"]]]))
check("a bare wildcard host is refused", refused(["Enabled": true, "RecoveryEntries": [["Host": "*"]]]))
check("a port out of range is refused", refused(["Enabled": true, "RecoveryEntries": [["Port": 70000]]]))
check("a malformed address is refused", refused(["Enabled": true, "RecoveryEntries": [["Address": "162.159.197.0/33"]]]))
check("a port given as text is refused", refused(["Enabled": true, "RecoveryEntries": [["Port": "5938"]]]))
check("an entry that is not a dictionary is refused", refused(["Enabled": true, "RecoveryEntries": ["teamviewer.com"]]))

// 3. What the recovery policy lets through, judged by the shipping matcher
//    with Silent Deny as the default, as the extension does.
let matcher = RuleMatcher()
let prepared = PreparedRuleSet(rules: policy.effectiveRules)
func verdict(_ c: Connection) -> RuleAction {
    matcher.explainedDecision(for: c, prepared: prepared, defaultMode: .silentDeny).action
}
func flow(_ path: String, host: String = "", ip: String = "203.0.113.9", port: Int = 443,
          bundle: String? = nil, team: String? = nil, claimed: String? = nil) -> Connection {
    Connection(pid: 100, processName: (path as NSString).lastPathComponent, processPath: path,
               processBundleId: bundle, processTeamId: team, claimedBundleId: claimed,
               remoteHost: host, remoteIP: ip, remotePort: port)
}
check("a recovery host is allowed for any app", verdict(flow("/Applications/Safari.app/Contents/MacOS/Safari", host: "router1.teamviewer.com")) == .allow)
check("the recovery domain itself is allowed", verdict(flow("/usr/bin/curl", host: "teamviewer.com")) == .allow)
check("a look-alike domain is denied", verdict(flow("/usr/bin/curl", host: "teamviewer.com.evil.example")) == .deny)
check("the recovery port is allowed", verdict(flow("/usr/bin/nc", ip: "198.51.100.7", port: 5938)) == .allow)
check("anything else is denied", verdict(flow("/usr/bin/curl", host: "example.com")) == .deny)
check("a signed app with its team is allowed anywhere",
      verdict(flow("/Applications/Support.app/Contents/MacOS/Support", host: "example.com", bundle: "com.example.Support", team: "ABCDE12345")) == .allow)
check("the same bundle id signed by another team is denied",
      verdict(flow("/tmp/Support.app/Contents/MacOS/Support", host: "example.com", bundle: "com.example.Support", team: "ZZZZZ99999")) == .deny)
check("the bundle id only claimed by an unsigned Info.plist is denied",
      verdict(flow("/tmp/Support.app/Contents/MacOS/Support", host: "example.com", claimed: "com.example.Support")) == .deny)
check("a path entry covers the app's executables",
      verdict(flow("/Applications/Example Remote.app/Contents/MacOS/Example Remote", host: "example.com")) == .allow)
check("but not an app whose name only starts the same",
      verdict(flow("/Applications/Example Remote.app.evil/x", host: "example.com")) == .deny)
check("a tunnel's outer flow to a recovery address and port is allowed",
      verdict(flow("/Library/SystemExtensions/X/com.example.tunnel.systemextension/Contents/MacOS/t", ip: "162.159.197.2", port: 443)) == .allow)
check("the same address on another port is denied",
      verdict(flow("/usr/bin/curl", ip: "162.159.197.2", port: 80)) == .deny)
check("Apple push (apsd) is allowed",
      verdict(flow("/System/Library/PrivateFrameworks/ApplePushService.framework/apsd", host: "1-courier.push.apple.com", port: 5223)) == .allow)
check("MDM check-in (mdmclient) is allowed", verdict(flow("/usr/libexec/mdmclient", host: "i.manage.microsoft.com")) == .allow)
check("network time is allowed", verdict(flow("/usr/libexec/timed", host: "time.apple.com", port: 123)) == .allow)
check("the captive portal check host is allowed for any app", verdict(flow("/usr/bin/curl", host: "captive.apple.com", port: 80)) == .allow)
check("the captive portal assistant may reach any login page",
      verdict(flow("/System/Library/CoreServices/Captive Network Assistant.app/Contents/MacOS/Captive Network Assistant", host: "wifi-login.hotel.example", port: 80)) == .allow)
check("the built-in list alone denies an unlisted app",
      matcher.explainedDecision(for: flow("/usr/bin/curl", host: "example.com"),
                                prepared: PreparedRuleSet(rules: FailClosedPolicy.builtInRecoveryRules), defaultMode: .silentDeny).action == .deny)

if failures > 0 { print("fail-closed harness: \(failures) FAILURES"); exit(1) }
print("fail-closed harness: PASS (all checks)")
SWIFT

xcrun swiftc -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 \
  "$ROOT"/Sources/Shared/*.swift "$TMP/main.swift" -o "$TMP/run"
"$TMP/run"
