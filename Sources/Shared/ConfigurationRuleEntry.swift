import Foundation

/// One rule written by an administrator in a property list (an MDM payload),
/// in the vocabulary an administrator uses rather than FreeSnitch's rule
/// fields. Shared by the fail-closed recovery list and managed rules, so both
/// refuse the same unsafe entries.
///
///     Host      "teamviewer.com" or "*.teamviewer.com"
///     Address   "162.159.197.0/24"
///     Port      5938
///     BundleID  "com.teamviewer.TeamViewer"   (requires TeamID for allow)
///     TeamID    "H7UGFBUGV6", or "apple" for Apple's own code
///     Path      "/Applications/TeamViewer.app"
///     Comment   free text
///
/// The fields of one entry must all match.
public enum ConfigurationRuleEntry {
    public struct EntryError: Error, Equatable {
        public let reason: String
    }

    public static func rule(from entry: [String: Any], action: RuleAction, priority: Int,
                            groupName: String, notesPrefix: String, profile: String = Profile.alwaysName) throws -> Rule {
        func string(_ key: String) throws -> String? {
            guard let value = entry[key] else { return nil }
            guard let text = value as? String else { throw EntryError(reason: "\(key) is not text") }
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }
        let host = try string("Host")?.lowercased()
        let bundleID = try string("BundleID")
        let teamID = try string("TeamID")
        let path = try string("Path")
        let address = try string("Address")
        if let address, let reason = RuleAddressValidator.rejectionReason(forRemoteIP: address) {
            throw EntryError(reason: "Address \(address): \(reason)")
        }
        let comment = try string("Comment")
        var port: Int?
        if let raw = entry["Port"] {
            guard let number = raw as? Int, (1...65535).contains(number) else {
                throw EntryError(reason: "Port must be a number from 1 to 65535")
            }
            port = number
        }
        guard host != nil || address != nil || port != nil || bundleID != nil || path != nil else {
            throw EntryError(reason: "it names no Host, Address, Port, BundleID or Path, so it would match everything")
        }
        // A bundle id alone is a claim anyone can put in an Info.plist. Only
        // the signing team makes it an identity (#351, #364). A deny may use
        // the claim: it can only ever block more.
        if bundleID != nil, teamID == nil, action != .deny {
            throw EntryError(reason: "BundleID needs the TeamID that signs the app")
        }
        if teamID != nil, bundleID == nil {
            throw EntryError(reason: "TeamID applies to a BundleID; name the app's BundleID too")
        }
        if let path, !path.hasPrefix("/") {
            throw EntryError(reason: "Path must be absolute")
        }
        if let host, host.contains("/") || host.contains(" ") || host == "*" || (host.hasPrefix("*.") && host.count <= 2) {
            throw EntryError(reason: "Host must be a name such as example.com or *.example.com")
        }
        let scope: RuleScope = bundleID != nil || path != nil ? .process
            : (host != nil ? .domain : (address != nil ? .ip : .port))
        return Rule(processBundleId: bundleID, processTeamId: teamID, processPath: path,
                    remoteHost: host, remoteIP: address, remotePort: port, direction: .outgoing, action: action,
                    scope: scope, priority: priority, profile: profile, groupName: groupName,
                    notes: comment.map { "\(notesPrefix): \($0)" } ?? notesPrefix)
    }
}
