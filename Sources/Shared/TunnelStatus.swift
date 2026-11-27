import Foundation

/// Which VPN tunnels carry this Mac's traffic right now. Decided from what
/// macOS itself routes by, never from a VPN client's own status: a client
/// can report "connected" in a mode that opens no tunnel at all.
///
/// A tunnel service is a network service in the dynamic store whose address
/// entry names a tunnel interface (`utun*`, `ipsec*`, `ppp*`) with a routable
/// address, or that has a `VPN` entry. Services are identified by their
/// service id, never by the interface number, which changes from one
/// connection to the next.
///
/// A service counts as connected when it "owns the default route":
///  1. its address entry names an interface,
///  2. that interface exists, is up, and has a routable address,
///  3. the kernel routes every IPv4 probe address through that interface,
///     and every IPv6 probe address that has a route at all.
///
/// Several unrelated probe addresses are used, so a split-tunnel VPN that
/// happens to route one of them does not count. A split-tunnel VPN never
/// owns the default route and never counts as connected: these triggers are
/// about whether general traffic goes through a tunnel.
///
/// A tunnel interface that owns the default route but belongs to no service
/// (a tunnel set up by a command-line tool) counts for "any VPN" only, as
/// `unlistedTunnelID`. It still has to pass every condition above, so an
/// idle or address-less tunnel interface never counts.
///
/// The decision is pure (`TunnelStatus.evaluate`) over what was read
/// (`TunnelEnvironment`); `TunnelSetDebouncer` decides when it takes effect.
public struct TunnelService: Equatable, Hashable, Sendable, Codable, Identifiable {
    public let id: String
    /// The service's user-visible name, when it set one.
    public let name: String?

    public init(id: String, name: String?) {
        self.id = id
        self.name = name
    }

    /// The name when there is one, else the service id.
    public var displayName: String {
        guard let name = name?.trimmingCharacters(in: .whitespacesAndNewlines), !name.isEmpty else { return id }
        return name
    }
}

/// What one evaluation found.
public struct TunnelReading: Equatable, Sendable {
    /// Every tunnel service present, connected or not, sorted by id.
    public var services: [TunnelService]
    /// The services that own the default route right now, plus
    /// `TunnelStatus.unlistedTunnelID` when a tunnel without a service does.
    public var connected: Set<String>
    /// Set when something could not be read. The debouncer then keeps the
    /// state it had for a short, bounded window, and after it treats the
    /// state as unknown, which is "nothing connected".
    public var failure: String?
    /// Why each present service is not connected, for logs and status.
    public var reasons: [String: TunnelDownReason]

    public init(services: [TunnelService], connected: Set<String>, failure: String? = nil,
                reasons: [String: TunnelDownReason] = [:]) {
        self.services = services
        self.connected = connected
        self.failure = failure
        self.reasons = reasons
    }

    public var anyConnected: Bool { !connected.isEmpty }
}

public enum TunnelDownReason: Equatable, Sendable, CustomStringConvertible {
    case interfaceMissing(String)
    case interfaceDown(String)
    case noAddress(String)
    /// Traffic for a probe address leaves by another interface, or by none.
    case notDefaultRoute(family: TunnelAddressFamily, interface: String?)

    public var description: String {
        switch self {
        case .interfaceMissing(let name): return "interface \(name) does not exist"
        case .interfaceDown(let name): return "interface \(name) is not up"
        case .noAddress(let name): return "interface \(name) has no routable address"
        case .notDefaultRoute(let family, let interface):
            return "\(family) default traffic leaves via \(interface ?? "no interface")"
        }
    }
}

public enum TunnelAddressFamily: String, Equatable, Sendable, CustomStringConvertible {
    case ipv4 = "IPv4"
    case ipv6 = "IPv6"
    public var description: String { rawValue }
}

/// The state of one network interface, as `getifaddrs` reports it.
public struct TunnelInterfaceState: Equatable, Sendable {
    public let isUp: Bool
    public let addresses: [String]

    public init(isUp: Bool, addresses: [String]) {
        self.isUp = isUp
        self.addresses = addresses
    }
}

/// Everything one evaluation reads. Built by `SystemTunnelEnvironmentReader`
/// in the helper; built by hand in tests from captured machine state.
public struct TunnelEnvironment {
    /// Dynamic store contents (`State:/Network/Service/...` and
    /// `Setup:/Network/Service/...`), keyed as the store keys them.
    public var store: [String: Any]
    /// Interface name to its state. An interface missing here does not exist.
    public var interfaces: [String: TunnelInterfaceState]
    /// The interface the kernel would send each IPv4 probe through, in the
    /// order of `TunnelProbe.ipv4`; nil for a probe with no route.
    public var ipv4ProbeRoutes: [String?]
    /// The same for IPv6. All nil means no IPv6 route at all, which is fine:
    /// then nothing can go around a tunnel over IPv6.
    public var ipv6ProbeRoutes: [String?]
    /// Set when a read failed.
    public var readFailure: String?

    public init(store: [String: Any], interfaces: [String: TunnelInterfaceState],
                ipv4ProbeRoutes: [String?], ipv6ProbeRoutes: [String?], readFailure: String? = nil) {
        self.store = store
        self.interfaces = interfaces
        self.ipv4ProbeRoutes = ipv4ProbeRoutes
        self.ipv6ProbeRoutes = ipv6ProbeRoutes
        self.readFailure = readFailure
    }
}

/// The probe addresses whose routes decide which interface owns the default
/// route. A route lookup sends nothing; the addresses only have to be public,
/// unrelated to each other, and outside any range a VPN deliberately
/// excludes.
public struct TunnelProbe: Equatable, Sendable {
    public let ipv4: [String]
    public let ipv6: [String]

    public init(ipv4: [String], ipv6: [String]) {
        precondition(!ipv4.isEmpty, "at least one IPv4 probe is needed")
        self.ipv4 = ipv4
        self.ipv6 = ipv6
    }

    /// Well-known public anycast resolver addresses in unrelated networks.
    public static let standard = TunnelProbe(
        ipv4: ["1.1.1.1", "8.8.8.8", "208.67.222.222"],
        ipv6: ["2606:4700:4700::1111", "2001:4860:4860::8888"])
}

public enum TunnelStatus {
    /// Dynamic store patterns that describe every service's addresses, VPN
    /// state and name: what the reader copies and the monitor watches.
    public static let storePatterns = [
        "State:/Network/Service/[^/]+/IPv4",
        "State:/Network/Service/[^/]+/IPv6",
        "State:/Network/Service/[^/]+/VPN",
        "Setup:/Network/Service/[^/]+",
    ]
    public static let globalPatterns = ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6"]

    /// Stands for a tunnel interface that owns the default route but belongs
    /// to no service. Not a valid dynamic store service id, so no service
    /// can be confused with it; never listed, never chosen in a trigger.
    public static let unlistedTunnelID = "<unlisted tunnel>"

    /// Interface name prefixes macOS uses for tunnels.
    public static let tunnelInterfacePrefixes = ["utun", "ipsec", "ppp"]

    /// The tunnel services in a store snapshot, each with the interface its
    /// address entry names, if any.
    public static func tunnelServices(in store: [String: Any]) -> [(service: TunnelService, interface: String?)] {
        var ids = Set<String>()
        for key in store.keys {
            guard let (id, suffix) = serviceKey(key) else { continue }
            switch suffix {
            case "VPN": ids.insert(id)
            case "IPv4", "IPv6":
                // macOS keeps link-local-only system tunnels (Continuity,
                // iCloud services) as services too; a VPN has a routable
                // address or a VPN entry.
                if let name = interfaceName(store[key]), isTunnelInterface(name),
                   let addresses = (store[key] as? [String: Any])?["Addresses"] as? [String],
                   addresses.contains(where: isRoutable) { ids.insert(id) }
            default: break
            }
        }
        return ids.sorted().map { id in
            let base = "State:/Network/Service/\(id)"
            let setup = store["Setup:/Network/Service/\(id)"] as? [String: Any]
            let interface = interfaceName(store["\(base)/IPv4"]) ?? interfaceName(store["\(base)/IPv6"])
            return (TunnelService(id: id, name: setup?["UserDefinedName"] as? String), interface)
        }
    }

    public static func isTunnelInterface(_ name: String) -> Bool {
        tunnelInterfacePrefixes.contains { prefix in
            name.hasPrefix(prefix) && name.count > prefix.count && name.dropFirst(prefix.count).allSatisfy(\.isNumber)
        }
    }

    /// Pure. A read failure is passed on with nothing connected; the
    /// debouncer decides what that means.
    public static func evaluate(_ env: TunnelEnvironment) -> TunnelReading {
        let found = tunnelServices(in: env.store)
        let services = found.map(\.service)
        if let failure = env.readFailure {
            return TunnelReading(services: services, connected: [], failure: failure)
        }
        var connected = Set<String>()
        var reasons: [String: TunnelDownReason] = [:]
        for (service, interface) in found {
            guard let interface else { continue }   // a VPN entry with no tunnel up
            if let reason = downReason(interface: interface, env: env) {
                reasons[service.id] = reason
            } else {
                connected.insert(service.id)
            }
        }
        // A tunnel interface owning the default route that no service names.
        let named = Set(found.compactMap(\.interface))
        let unlisted = env.interfaces.keys.contains { name in
            isTunnelInterface(name) && !named.contains(name) && downReason(interface: name, env: env) == nil
        }
        if unlisted { connected.insert(unlistedTunnelID) }
        return TunnelReading(services: services, connected: connected, reasons: reasons)
    }

    private static func downReason(interface: String, env: TunnelEnvironment) -> TunnelDownReason? {
        guard let state = env.interfaces[interface] else { return .interfaceMissing(interface) }
        guard state.isUp else { return .interfaceDown(interface) }
        guard state.addresses.contains(where: isRoutable) else { return .noAddress(interface) }
        if env.ipv4ProbeRoutes.isEmpty { return .notDefaultRoute(family: .ipv4, interface: nil) }
        if let elsewhere = env.ipv4ProbeRoutes.first(where: { $0 != interface }) {
            return .notDefaultRoute(family: .ipv4, interface: elsewhere)
        }
        if let elsewhere = env.ipv6ProbeRoutes.compactMap({ $0 }).first(where: { $0 != interface }) {
            return .notDefaultRoute(family: .ipv6, interface: elsewhere)
        }
        return nil
    }

    /// Not link-local, loopback or unspecified: an address the tunnel can
    /// carry traffic from.
    public static func isRoutable(_ address: String) -> Bool {
        let bare = address.split(separator: "%", maxSplits: 1).first.map(String.init) ?? address
        guard let bytes = CIDR.bytes(bare) else { return false }
        if bytes.count == 4 { return bytes[0] != 127 && bytes[0] != 0 && !(bytes[0] == 169 && bytes[1] == 254) }
        let linkLocal = bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80
        let loopbackOrUnspecified = bytes.dropLast().allSatisfy { $0 == 0 } && (bytes.last == 1 || bytes.last == 0)
        return !linkLocal && !loopbackOrUnspecified
    }

    private static func serviceKey(_ key: String) -> (String, String)? {
        let prefix = "State:/Network/Service/"
        guard key.hasPrefix(prefix) else { return nil }
        let parts = key.dropFirst(prefix.count).split(separator: "/")
        guard parts.count == 2 else { return nil }
        return (String(parts[0]), String(parts[1]))
    }

    private static func interfaceName(_ value: Any?) -> String? {
        guard let entry = value as? [String: Any],
              let name = entry["InterfaceName"] as? String, !name.isEmpty else { return nil }
        return name
    }
}

/// The settled set of connected tunnel services, which other code acts on.
///
/// Asymmetric on purpose: a service that stops owning the default route
/// leaves the set on the first reading that says so, because traffic is
/// already going around it; a service joins only after it has owned the
/// route for `upHold` seconds across at least `upReadings` readings, because
/// tunnels publish their interface and route shortly before they are usable,
/// and flap while reconnecting.
///
/// A reading that failed keeps the set for at most `failureGrace` seconds
/// (retried every `failureRetry`); past that the state is unknown, which is
/// "nothing connected". A stuck "connected" is the worse failure for a
/// profile that is meant to tighten when the tunnel goes.
///
/// Times are monotonic seconds (system uptime), never wall-clock dates.
public struct TunnelSetDebouncer: Sendable {
    public let upHold: TimeInterval
    public let upReadings: Int
    public let failureGrace: TimeInterval
    public let failureRetry: TimeInterval

    public private(set) var connected: Set<String> = []
    private var pending: [String: (since: TimeInterval, readings: Int)] = [:]
    private var failingSince: TimeInterval?
    private var lastFailureAt: TimeInterval?

    public init(upHold: TimeInterval = 3, upReadings: Int = 2,
                failureGrace: TimeInterval = 2, failureRetry: TimeInterval = 0.5) {
        precondition(upHold >= 0 && upReadings >= 1 && failureGrace >= 0 && failureRetry > 0)
        self.upHold = upHold
        self.upReadings = upReadings
        self.failureGrace = failureGrace
        self.failureRetry = failureRetry
    }

    /// Feeds one reading. Returns the new set when it changed.
    public mutating func observe(_ reading: TunnelReading, at now: TimeInterval) -> Set<String>? {
        let before = connected
        if reading.failure != nil {
            let since = failingSince ?? now
            failingSince = since
            lastFailureAt = now
            pending.removeAll()
            if now - since >= failureGrace { connected = [] }
            return connected == before ? nil : connected
        }
        failingSince = nil
        lastFailureAt = nil
        let seen = reading.connected
        connected.formIntersection(seen)
        pending = pending.filter { seen.contains($0.key) }
        for id in seen where !connected.contains(id) {
            var entry = pending[id] ?? (now, 0)
            entry.readings += 1
            if entry.readings >= upReadings, now - entry.since >= upHold {
                connected.insert(id)
                pending[id] = nil
            } else {
                pending[id] = entry
            }
        }
        return connected == before ? nil : connected
    }

    /// When the next reading should be taken: a pending service's hold end,
    /// or the retry of a failed read. Monotonic seconds.
    public var nextDeadline: TimeInterval? {
        var deadlines = pending.values.map { $0.since + upHold }
        // Retried quickly only inside the grace; a read that keeps failing is
        // left to the monitor's slow poll, so it is not retried in a loop.
        if let lastFailureAt, let failingSince, lastFailureAt - failingSince < failureGrace {
            deadlines.append(lastFailureAt + failureRetry)
        }
        return deadlines.min()
    }

    /// True while a service is inside its hold or a failure inside its grace.
    public var isUnsettled: Bool { !pending.isEmpty || failingSince != nil }

    public mutating func reset() {
        connected = []
        pending.removeAll()
        failingSince = nil
        lastFailureAt = nil
    }
}

/// Address literal parsing without sockets.
public enum CIDR {
    static func bytes(_ literal: String) -> [UInt8]? {
        var v4 = in_addr()
        if literal.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            return withUnsafeBytes(of: &v4) { Array($0) }
        }
        var v6 = in6_addr()
        if literal.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
            return withUnsafeBytes(of: &v6) { Array($0) }
        }
        return nil
    }
}
