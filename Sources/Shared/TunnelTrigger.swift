import Foundation

/// "Activate this profile when <a VPN> is <connected | not connected>."
///
/// A sibling of the gateway network binding: a binding activates a profile on
/// a network, a trigger activates one while a VPN tunnel does or does not
/// carry this Mac's traffic. A VPN is either any tunnel service or one
/// service by its id; "connected" means it owns the default route (see
/// `TunnelStatus`). Triggers are opt-in: with none, nothing about VPNs
/// changes the active profile.
public struct TunnelTrigger: Codable, Equatable, Hashable, Sendable, Identifiable {
    /// A service id from the dynamic store, or nil for any VPN.
    public var service: String?
    /// True for "is connected", false for "is not connected".
    public var whenConnected: Bool
    public var profile: String

    public init(service: String?, whenConnected: Bool, profile: String) {
        self.service = service.flatMap { $0.isEmpty ? nil : $0 }
        self.whenConnected = whenConnected
        self.profile = profile
    }

    /// One trigger per condition, as one gateway selects one profile.
    public var id: String { "\(service ?? "*")|\(whenConnected ? "up" : "down")" }

    public func matches(_ connected: Set<String>) -> Bool {
        let up = service.map { connected.contains($0) } ?? !connected.isEmpty
        return up == whenConnected
    }

    /// Which trigger wins when several match: a named VPN over any VPN, and a
    /// connected condition over a not-connected one, because the more
    /// specific statement is the one the user meant.
    var rank: Int { (whenConnected ? 0 : 2) + (service == nil ? 1 : 0) }

    /// The trigger that decides the profile for a set of connected services,
    /// or nil when none matches (gateway bindings decide then).
    public static func winner(_ triggers: [TunnelTrigger], connected: Set<String>) -> TunnelTrigger? {
        triggers.filter { $0.matches(connected) }
            .min { ($0.rank, $0.service ?? "", $0.profile) < ($1.rank, $1.service ?? "", $1.profile) }
    }

    /// Stored as one JSON array in the helper's settings table.
    public static let settingKey = "tunnel_triggers"
}

extension RuleStore {
    /// The stored triggers, or none. A stored value that cannot be decoded
    /// throws: it is not the same as "no triggers".
    public func tunnelTriggers() throws -> [TunnelTrigger] {
        guard let raw = getSetting(TunnelTrigger.settingKey) else { return [] }
        do {
            return try JSONDecoder().decode([TunnelTrigger].self, from: Data(raw.utf8))
        } catch {
            throw ProfileValidationError.invalidTunnelTrigger("the stored triggers could not be read: \(error.localizedDescription)")
        }
    }

    /// Adds a trigger, replacing the one with the same condition (a condition
    /// selects one profile). The profile must exist and must not be Always.
    public func setTunnelTrigger(_ trigger: TunnelTrigger) throws -> [TunnelTrigger] {
        guard trigger.profile != Profile.alwaysName else {
            throw ProfileValidationError.invalidTunnelTrigger("Always applies in every profile and cannot be activated")
        }
        guard profile(named: trigger.profile) != nil else {
            throw ProfileValidationError.invalidTunnelTrigger("there is no profile named \(trigger.profile)")
        }
        var triggers = try tunnelTriggers().filter { $0.id != trigger.id }
        triggers.append(trigger)
        try saveTunnelTriggers(triggers)
        return triggers
    }

    public func removeTunnelTrigger(id: String) throws -> [TunnelTrigger] {
        let triggers = try tunnelTriggers().filter { $0.id != id }
        try saveTunnelTriggers(triggers)
        return triggers
    }

    func saveTunnelTriggers(_ triggers: [TunnelTrigger]) throws {
        let sorted = triggers.sorted { $0.id < $1.id }
        try setSetting(TunnelTrigger.settingKey, String(decoding: try JSONEncoder().encode(sorted), as: UTF8.self))
    }
}
