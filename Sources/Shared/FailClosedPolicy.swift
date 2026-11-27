import Foundation

/// Opt-in fail-closed for the network extension (off by default).
///
/// FreeSnitch fails open by design: while the extension holds no policy
/// (just installed, the app never ran, a saved policy was refused) every flow
/// is allowed, so a missing app can never become a network outage. A managed
/// fleet may need the opposite: with no policy in force, only a short
/// recovery list gets through (remote support, the MDM, the identity
/// provider, the tunnel client, Apple's device management and time), and
/// everything else is denied until the helper or the app delivers a policy.
///
/// It is read from the content filter's provider configuration under
/// `vendorConfigurationKey`, which an MDM `com.apple.webcontent-filter`
/// payload sets through its `VendorConfig` dictionary, so it is in force from
/// the extension's first flow, before any app or helper exists.
public struct FailClosedPolicy: Equatable, Sendable {
    public static let vendorConfigurationKey = "io.isaaclins.freesnitch.failClosed"

    public var enabled: Bool
    /// The administrator's recovery entries, already turned into allow rules.
    public var recoveryRules: [Rule]

    public init(enabled: Bool, recoveryRules: [Rule]) {
        self.enabled = enabled
        self.recoveryRules = recoveryRules
    }

    public static let off = FailClosedPolicy(enabled: false, recoveryRules: [])

    /// The rules in force while no policy is: Apple's own device management,
    /// push, time and captive portal first, then the administrator's entries.
    /// Evaluated with Silent Deny as the default, so only these get through.
    public var effectiveRules: [Rule] { Self.builtInRecoveryRules + recoveryRules }

    /// What macOS itself needs to stay manageable and reach a captive
    /// portal. Pinned to Apple-signed code at system paths (SIP-protected),
    /// never to a host alone, except the captive portal check host.
    public static let builtInRecoveryRules: [Rule] = {
        let applePaths = [
            "/usr/libexec/mdmclient",                 // MDM check-in and commands
            "/System/Library/PrivateFrameworks/ApplePushService.framework", // apsd (APNs)
            "/usr/libexec/timed",                     // network time
            "/usr/libexec/captiveagent",              // captive portal detection
            "/System/Library/CoreServices/Captive Network Assistant.app",
            "/usr/libexec/trustd",                    // certificate revocation (OCSP/CRL)
        ]
        var rules = applePaths.map { path in
            Rule(processPath: path, direction: .outgoing, action: .allow, scope: .process, priority: 1000,
                 groupName: groupName, notes: "Built-in fail-closed recovery: Apple system service")
        }
        rules.append(Rule(remoteHost: "captive.apple.com", direction: .outgoing, action: .allow, scope: .domain,
                          priority: 1000, groupName: groupName, notes: "Built-in fail-closed recovery: captive portal check"))
        return rules
    }()

    public static let groupName = "Fail-closed recovery"

    public enum ParseError: Error, Equatable, LocalizedError {
        case notADictionary
        case invalidEntry(index: Int, reason: String)

        public var errorDescription: String? {
            switch self {
            case .notADictionary: return "the fail-closed configuration is not a dictionary"
            case .invalidEntry(let index, let reason): return "recovery entry \(index + 1): \(reason)"
            }
        }
    }

    /// Reads the provider configuration. A missing key is `.off`. A present
    /// but malformed value throws, and the caller decides; the extension
    /// keeps fail-closed ON with only the built-in list then, because an
    /// administrator who asked for fail-closed must not get fail-open from a
    /// typo.
    public static func read(fromVendorConfiguration vendor: [String: Any]?) throws -> FailClosedPolicy {
        guard let value = vendor?[vendorConfigurationKey] else { return .off }
        return try parse(value)
    }

    /// The configuration as a property list dictionary:
    ///
    ///     Enabled         Bool
    ///     RecoveryEntries [Dictionary], each with any of:
    ///         Host      "teamviewer.com" or "*.teamviewer.com"
    ///         Address   "162.159.197.0/24" (an address or CIDR, for flows
    ///                   that carry no host name, such as a tunnel's own)
    ///         Port      5938
    ///         BundleID  "com.teamviewer.TeamViewer"   (requires TeamID)
    ///         TeamID    "H7UGFBUGV6", or "apple" for Apple's own code
    ///         Path      "/Applications/TeamViewer.app" (an app or executable)
    ///         Comment   free text
    ///
    /// The fields of one entry must all match; entries are alternatives.
    public static func parse(_ value: Any) throws -> FailClosedPolicy {
        guard let dict = value as? [String: Any] else { throw ParseError.notADictionary }
        let enabled = (dict["Enabled"] as? Bool) ?? false
        let entries = (dict["RecoveryEntries"] as? [Any]) ?? []
        var rules: [Rule] = []
        for (index, raw) in entries.enumerated() {
            guard let entry = raw as? [String: Any] else {
                throw ParseError.invalidEntry(index: index, reason: "not a dictionary")
            }
            rules.append(try rule(from: entry, index: index))
        }
        return FailClosedPolicy(enabled: enabled, recoveryRules: rules)
    }

    static func rule(from entry: [String: Any], index: Int) throws -> Rule {
        func string(_ key: String) throws -> String? {
            guard let value = entry[key] else { return nil }
            guard let text = value as? String else {
                throw ParseError.invalidEntry(index: index, reason: "\(key) is not text")
            }
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }
        let host = try string("Host")?.lowercased()
        let bundleID = try string("BundleID")
        let teamID = try string("TeamID")
        let path = try string("Path")
        let address = try string("Address")
        if let address, let reason = RuleAddressValidator.rejectionReason(forRemoteIP: address) {
            throw ParseError.invalidEntry(index: index, reason: "Address \(address): \(reason)")
        }
        let comment = try string("Comment")
        var port: Int?
        if let raw = entry["Port"] {
            guard let number = raw as? Int, (1...65535).contains(number) else {
                throw ParseError.invalidEntry(index: index, reason: "Port must be a number from 1 to 65535")
            }
            port = number
        }
        guard host != nil || address != nil || port != nil || bundleID != nil || path != nil else {
            throw ParseError.invalidEntry(index: index, reason: "it names no Host, Address, Port, BundleID or Path, so it would allow everything")
        }
        // A bundle id alone is a claim anyone can put in an Info.plist. Only
        // the signing team makes it an identity (#351, #364).
        if bundleID != nil, teamID == nil {
            throw ParseError.invalidEntry(index: index, reason: "BundleID needs the TeamID that signs the app")
        }
        if teamID != nil, bundleID == nil {
            throw ParseError.invalidEntry(index: index, reason: "TeamID applies to a BundleID; name the app's BundleID too")
        }
        if let path, !path.hasPrefix("/") {
            throw ParseError.invalidEntry(index: index, reason: "Path must be absolute")
        }
        if let host, host.contains("/") || host.contains(" ") || host == "*" || host.hasPrefix("*.") && host.count <= 2 {
            throw ParseError.invalidEntry(index: index, reason: "Host must be a name such as example.com or *.example.com")
        }
        let scope: RuleScope = bundleID != nil || path != nil ? .process
            : (host != nil ? .domain : (address != nil ? .ip : .port))
        return Rule(processBundleId: bundleID, processTeamId: teamID, processPath: path,
                    remoteHost: host, remoteIP: address, remotePort: port, direction: .outgoing, action: .allow, scope: scope,
                    priority: 900, groupName: groupName,
                    notes: comment.map { "Fail-closed recovery: \($0)" } ?? "Fail-closed recovery")
    }
}
