import Foundation

/// Opt-in: which profile is active while a full tunnel (Cloudflare WARP)
/// carries this Mac's traffic, and which while it does not. Off by default;
/// with it off, nothing about the tunnel changes the active profile.
///
/// A side left nil leaves that side to the gateway bindings, exactly as
/// without this setting, so "use Work while WARP is up" works without also
/// deciding what happens when it is down.
public struct TunnelProfileSwitch: Codable, Equatable, Sendable {
    public var enabled: Bool
    public var connectedProfile: String?
    public var disconnectedProfile: String?

    public init(enabled: Bool, connectedProfile: String?, disconnectedProfile: String?) {
        self.enabled = enabled
        self.connectedProfile = connectedProfile
        self.disconnectedProfile = disconnectedProfile
    }

    public static let off = TunnelProfileSwitch(enabled: false, connectedProfile: nil, disconnectedProfile: nil)

    /// Stored as one JSON value in the helper's settings table, so the two
    /// profile names and the switch can never be read half-updated.
    public static let settingKey = "tunnel_profile_switch"

    /// The profile this setting asks for in a tunnel state, or nil when it
    /// asks for nothing (off, or that side unset).
    public func target(tunnelUp: Bool) -> String? {
        guard enabled else { return nil }
        let name = tunnelUp ? connectedProfile : disconnectedProfile
        guard let name, !name.isEmpty else { return nil }
        return name
    }

    public var isConfigured: Bool { target(tunnelUp: true) != nil || target(tunnelUp: false) != nil }
}

extension RuleStore {
    /// The stored setting, or `.off` when none was ever saved. A stored value
    /// that cannot be decoded throws: it is not the same as "off", and the
    /// caller decides what an unreadable setting means.
    public func tunnelProfileSwitch() throws -> TunnelProfileSwitch {
        guard let raw = getSetting(TunnelProfileSwitch.settingKey) else { return .off }
        guard let data = raw.data(using: .utf8) else {
            throw ProfileValidationError.invalidTunnelProfileSwitch("the stored value is not text")
        }
        do {
            return try JSONDecoder().decode(TunnelProfileSwitch.self, from: data)
        } catch {
            throw ProfileValidationError.invalidTunnelProfileSwitch("the stored value could not be read: \(error.localizedDescription)")
        }
    }

    /// Saves the setting after checking that every named profile exists, so
    /// a typo is refused now rather than failing at the next tunnel change.
    /// The Always layer is not a profile one can switch to.
    public func setTunnelProfileSwitch(_ value: TunnelProfileSwitch) throws {
        for name in [value.connectedProfile, value.disconnectedProfile].compactMap({ $0 }) where !name.isEmpty {
            guard name != Profile.alwaysName else {
                throw ProfileValidationError.invalidTunnelProfileSwitch("Always applies in every profile and cannot be switched to")
            }
            guard profile(named: name) != nil else {
                throw ProfileValidationError.invalidTunnelProfileSwitch("there is no profile named \(name)")
            }
        }
        let data = try JSONEncoder().encode(value)
        try setSetting(TunnelProfileSwitch.settingKey, String(decoding: data, as: UTF8.self))
    }
}
