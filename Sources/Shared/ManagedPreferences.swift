import CryptoKit
import Foundation

/// Settings an organization delivers through MDM, in the app's own preference
/// domain (`io.isaaclins.freesnitch`), which a configuration profile with a
/// `com.apple.ManagedClient.preferences` or custom-settings payload writes to
/// `/Library/Managed Preferences/io.isaaclins.freesnitch.plist`.
///
/// Managed values take precedence over the user's: managed VPN triggers
/// replace the stored ones, managed rules sit above every user rule, and with
/// `LockSettings` the user cannot change or remove what MDM set. Nothing here
/// applies without the file; FreeSnitch behaves as before.
public struct ManagedPreferences: Equatable, Sendable {
    public static let domain = AppConstants.bundleIdGUI
    public static let defaultPath = "/Library/Managed Preferences/\(domain).plist"
    /// Group every managed rule carries, so the rule list can show it.
    public static let ruleGroupName = "Managed by your organization"
    /// Above every user rule (default 100) and below nothing else.
    public static let rulePriority = 950

    public struct ManagedProfile: Equatable, Sendable {
        public let name: String
        public let mode: AppMode?
    }

    public struct Binding: Equatable, Sendable {
        public let gatewayMAC: String
        public let profile: String
    }

    /// Nil when MDM does not manage triggers; then the user's own apply.
    public var tunnelTriggers: [TunnelTrigger]?
    public var profiles: [ManagedProfile]
    /// Nil when the key is absent: then rules MDM added earlier are removed.
    public var rules: [Rule]
    public var bindings: [Binding]
    public var lockSettings: Bool
    /// The helper delivers policy to the extension itself (see
    /// ExtensionPolicyPusher), so fail-closed fleets get a policy before any
    /// user logs in. Implied by any VPN trigger.
    public var helperDeliversPolicy: Bool

    public static let none = ManagedPreferences(tunnelTriggers: nil, profiles: [], rules: [], bindings: [],
                                                lockSettings: false, helperDeliversPolicy: false)

    public enum ParseError: Error, Equatable, LocalizedError {
        case unreadable(String)
        case invalid(key: String, reason: String)

        public var errorDescription: String? {
            switch self {
            case .unreadable(let detail): return "managed preferences could not be read: \(detail)"
            case .invalid(let key, let reason): return "managed preference \(key) is invalid: \(reason)"
            }
        }
    }

    /// Reads the managed file. Nil when there is none (not managed). A file
    /// that exists but cannot be parsed throws, and the caller keeps what it
    /// applied last: a broken profile must not silently drop managed rules.
    public static func read(path: String = defaultPath) throws -> ManagedPreferences? {
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        let data: Data
        do { data = try Data(contentsOf: URL(fileURLWithPath: path)) } catch {
            throw ParseError.unreadable(error.localizedDescription)
        }
        let plist: Any
        do { plist = try PropertyListSerialization.propertyList(from: data, format: nil) } catch {
            throw ParseError.unreadable(error.localizedDescription)
        }
        guard let dict = plist as? [String: Any] else { throw ParseError.unreadable("not a dictionary") }
        return try parse(dict)
    }

    /// All or nothing: one invalid entry refuses the whole set, so a typo can
    /// never apply half of an organization's rules.
    public static func parse(_ dict: [String: Any]) throws -> ManagedPreferences {
        var result = ManagedPreferences.none
        result.lockSettings = (dict["LockSettings"] as? Bool) ?? false

        if let raw = dict["VPNTriggers"] {
            guard let list = raw as? [Any] else { throw ParseError.invalid(key: "VPNTriggers", reason: "not an array") }
            var seen = Set<String>()
            result.tunnelTriggers = try list.enumerated().map { index, item in
                let key = "VPNTriggers[\(index)]"
                guard let entry = item as? [String: Any],
                      let profile = (entry["Profile"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
                      !profile.isEmpty else {
                    throw ParseError.invalid(key: key, reason: "needs a Profile")
                }
                let whenConnected: Bool
                switch (entry["When"] as? String)?.lowercased() {
                case "connected": whenConnected = true
                case "disconnected", "not connected": whenConnected = false
                default: throw ParseError.invalid(key: key, reason: "When must be connected or disconnected")
                }
                var service: String?
                if let raw = entry["Service"] {
                    guard let text = raw as? String else { throw ParseError.invalid(key: key, reason: "Service is not text") }
                    service = text.trimmingCharacters(in: .whitespacesAndNewlines)
                }
                let trigger = TunnelTrigger(service: service, whenConnected: whenConnected, profile: profile)
                guard seen.insert(trigger.id).inserted else {
                    throw ParseError.invalid(key: key, reason: "another trigger already has this condition")
                }
                return trigger
            }
        }
        result.helperDeliversPolicy = (dict["HelperDeliversPolicy"] as? Bool) ?? false

        if let raw = dict["Profiles"] {
            guard let list = raw as? [Any] else { throw ParseError.invalid(key: "Profiles", reason: "not an array") }
            result.profiles = try list.enumerated().map { index, item in
                guard let entry = item as? [String: Any], let rawName = entry["Name"] as? String else {
                    throw ParseError.invalid(key: "Profiles[\(index)]", reason: "needs a Name")
                }
                let name: String
                do { name = try ProfileNameValidator.normalized(rawName) } catch {
                    throw ParseError.invalid(key: "Profiles[\(index)]", reason: error.localizedDescription)
                }
                guard name.caseInsensitiveCompare(Profile.alwaysName) != .orderedSame else {
                    throw ParseError.invalid(key: "Profiles[\(index)]", reason: "Always is not a profile one can create")
                }
                var mode: AppMode?
                if let rawMode = entry["Mode"] {
                    guard let text = rawMode as? String, let parsed = AppMode(rawValue: text) else {
                        throw ParseError.invalid(key: "Profiles[\(index)].Mode", reason: "use alert, silentAllow or silentDeny")
                    }
                    mode = parsed
                }
                return ManagedProfile(name: name, mode: mode)
            }
        }

        if let raw = dict["Rules"] {
            guard let list = raw as? [Any] else { throw ParseError.invalid(key: "Rules", reason: "not an array") }
            result.rules = try list.enumerated().map { index, item in
                guard let entry = item as? [String: Any] else {
                    throw ParseError.invalid(key: "Rules[\(index)]", reason: "not a dictionary")
                }
                let action: RuleAction
                switch (entry["Action"] as? String)?.lowercased() ?? "allow" {
                case "allow": action = .allow
                case "deny": action = .deny
                default: throw ParseError.invalid(key: "Rules[\(index)].Action", reason: "use allow or deny")
                }
                let profile = (entry["Profile"] as? String).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .flatMap { $0.isEmpty ? nil : $0 } ?? Profile.alwaysName
                do {
                    var rule = try ConfigurationRuleEntry.rule(from: entry, action: action, priority: rulePriority,
                                                               groupName: ruleGroupName, notesPrefix: ruleGroupName,
                                                               profile: profile)
                    rule.id = stableID(for: rule)
                    rule.createdAt = Date(timeIntervalSince1970: 0)
                    return rule
                } catch let error as ConfigurationRuleEntry.EntryError {
                    throw ParseError.invalid(key: "Rules[\(index)]", reason: error.reason)
                }
            }
        }

        if let raw = dict["NetworkBindings"] {
            guard let list = raw as? [Any] else { throw ParseError.invalid(key: "NetworkBindings", reason: "not an array") }
            result.bindings = try list.enumerated().map { index, item in
                guard let entry = item as? [String: Any],
                      let mac = entry["GatewayMAC"] as? String, let profile = entry["Profile"] as? String else {
                    throw ParseError.invalid(key: "NetworkBindings[\(index)]", reason: "needs GatewayMAC and Profile")
                }
                guard let canonical = GatewayMAC.normalized(mac) else {
                    throw ParseError.invalid(key: "NetworkBindings[\(index)]", reason: "\(mac) is not a MAC address")
                }
                return Binding(gatewayMAC: canonical, profile: profile)
            }
        }
        return result
    }

    /// The same entry always gets the same id, so applying the managed set
    /// again changes nothing, and an edited entry replaces the old one.
    static func stableID(for rule: Rule) -> UUID {
        let key = [rule.processBundleId, rule.processTeamId, rule.processPath, rule.remoteHost, rule.remoteIP,
                   rule.remotePort.map(String.init), rule.action.rawValue, rule.profile, rule.notes]
            .map { $0 ?? "" }.joined(separator: "\u{1F}")
        var bytes = Array(SHA256.hash(data: Data(("freesnitch.managed\u{1F}" + key).utf8)).prefix(16))
        bytes[6] = (bytes[6] & 0x0F) | 0x50   // name-based (version 5 layout)
        bytes[8] = (bytes[8] & 0x3F) | 0x80   // RFC 4122 variant
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                           bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
}

/// Applies managed preferences to the helper's store. Pure store work, so the
/// harness drives it against a real database.
public enum ManagedPolicySync {
    /// Settings key holding the ids of rules MDM added, so they can be
    /// replaced or removed later without touching any rule the user made.
    public static let managedRuleIDsKey = "managed_rule_ids"

    public struct Outcome: Equatable {
        public var createdProfiles: [String] = []
        public var addedRules = 0
        public var removedRules = 0
        public var problems: [String] = []
        public var policyChanged: Bool { addedRules > 0 || removedRules > 0 }
    }

    public static func managedRuleIDs(in store: RuleStore) -> Set<UUID> {
        guard let raw = store.getSetting(managedRuleIDsKey), let data = raw.data(using: .utf8),
              let ids = try? JSONDecoder().decode([UUID].self, from: data) else { return [] }
        return Set(ids)
    }

    @discardableResult
    public static func apply(_ prefs: ManagedPreferences, to store: RuleStore) throws -> Outcome {
        var outcome = Outcome()
        for profile in prefs.profiles {
            if let existing = store.profile(named: profile.name) {
                if let mode = profile.mode, existing.mode != mode {
                    _ = try store.setProfileMode(name: existing.name, mode: mode)
                }
            } else {
                _ = try store.createProfile(name: profile.name, mode: profile.mode ?? .alert)
                outcome.createdProfiles.append(profile.name)
            }
        }
        for binding in prefs.bindings {
            if store.networkBinding(forGatewayMAC: binding.gatewayMAC)?.profileName == binding.profile { continue }
            do { _ = try store.bindGatewayMAC(binding.gatewayMAC, toProfile: binding.profile) } catch {
                outcome.problems.append("binding \(binding.gatewayMAC) to \(binding.profile): \(error.localizedDescription)")
            }
        }
        // A rule for a profile that does not exist would never apply; say so
        // rather than store it.
        let rules = prefs.rules.filter { rule in
            guard rule.profile == Profile.alwaysName || store.profile(named: rule.profile) != nil else {
                outcome.problems.append("a managed rule names the profile \(rule.profile), which does not exist")
                return false
            }
            return true
        }
        for trigger in prefs.tunnelTriggers ?? [] where store.profile(named: trigger.profile) == nil {
            outcome.problems.append("a VPN trigger names the profile \(trigger.profile), which does not exist")
        }
        let previous = managedRuleIDs(in: store)
        let wanted = Set(rules.map(\.id))
        let stored = try store.allRules()
        let storedByID = Dictionary(stored.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        let missingOrChanged = rules.filter { rule in
            guard let current = storedByID[rule.id] else { return true }
            return current.action != rule.action || current.enabled == false || current.priority != rule.priority
                || current.profile != rule.profile
        }
        let stale = previous.subtracting(wanted).filter { storedByID[$0] != nil }
        if !missingOrChanged.isEmpty || !stale.isEmpty {
            _ = try store.mutatePolicy { draft in
                let replace = Set(missingOrChanged.map(\.id)).union(stale)
                draft.rules.removeAll { replace.contains($0.id) }
                draft.rules.append(contentsOf: missingOrChanged)
            }
            outcome.addedRules = missingOrChanged.count
            outcome.removedRules = stale.count
        }
        if previous != wanted {
            let data = try JSONEncoder().encode(wanted.sorted { $0.uuidString < $1.uuidString })
            try store.setSetting(managedRuleIDsKey, String(decoding: data, as: UTF8.self))
        }
        return outcome
    }
}
