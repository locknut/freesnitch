import Foundation

/// Which VPN tunnels carry this Mac's traffic right now. Decided from what
/// macOS itself routes by, never from a VPN client's own status: a client
/// can report "connected" in a mode that opens no tunnel at all.
///
/// A tunnel service is a network service in the dynamic store whose address
/// entry names a tunnel interface (`utun*`, `ipsec*`, `ppp*`), or that has a
/// `VPN` entry. Services are identified by their service id, never by the
/// interface number, which changes from one connection to the next.
///
/// A service counts as connected when it "owns the default route":
///  1. its address entry names an interface,
///  2. that interface exists, is up, and has a routable address,
///  3. the kernel's route lookup for a public probe address (IPv4, and IPv6
///     when the Mac has an IPv6 route at all) leaves through that interface.
///
/// A split-tunnel VPN, which routes only some networks, never owns the
/// default route and so never counts as connected here. That is deliberate:
/// these triggers are about whether general traffic goes through a tunnel.
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
    /// The services that own the default route right now.
    public var connected: Set<String>
    /// Set when something could not be read. Then `connected` is empty:
    /// an unknown state is never mistaken for a working tunnel.
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
    /// Traffic for the probe address leaves by another interface, or by none.
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
    /// The interface the kernel would send the IPv4 probe through, or nil
    /// when there is no IPv4 route.
    public var ipv4ProbeRoute: String?
    /// The same for IPv6. Nil means no IPv6 route at all, which is fine:
    /// then nothing can go around a tunnel over IPv6.
    public var ipv6ProbeRoute: String?
    /// Set when a read failed.
    public var readFailure: String?

    public init(store: [String: Any], interfaces: [String: TunnelInterfaceState],
                ipv4ProbeRoute: String?, ipv6ProbeRoute: String?, readFailure: String? = nil) {
        self.store = store
        self.interfaces = interfaces
        self.ipv4ProbeRoute = ipv4ProbeRoute
        self.ipv6ProbeRoute = ipv6ProbeRoute
        self.readFailure = readFailure
    }
}

/// The probe addresses whose routes decide which interface owns the default
/// route. A route lookup sends nothing; the address only has to be public and
/// outside any range a VPN deliberately excludes. Configurable for that case.
public struct TunnelProbe: Equatable, Sendable {
    public let ipv4: String
    public let ipv6: String

    public init(ipv4: String, ipv6: String) {
        self.ipv4 = ipv4
        self.ipv6 = ipv6
    }

    /// Two well-known public anycast resolver addresses. Any public address
    /// would do.
    public static let standard = TunnelProbe(ipv4: "1.1.1.1", ipv6: "2606:4700:4700::1111")
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

    /// Interface name prefixes macOS uses for tunnels.
    public static let tunnelInterfacePrefixes = ["utun", "ipsec", "ppp", "tun", "tap"]

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
            name.hasPrefix(prefix) && name.dropFirst(prefix.count).allSatisfy(\.isNumber)
        }
    }

    /// Pure. A read failure leaves nothing connected.
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
        return TunnelReading(services: services, connected: connected, reasons: reasons)
    }

    private static func downReason(interface: String, env: TunnelEnvironment) -> TunnelDownReason? {
        guard let state = env.interfaces[interface] else { return .interfaceMissing(interface) }
        guard state.isUp else { return .interfaceDown(interface) }
        guard state.addresses.contains(where: isRoutable) else { return .noAddress(interface) }
        guard env.ipv4ProbeRoute == interface else {
            return .notDefaultRoute(family: .ipv4, interface: env.ipv4ProbeRoute)
        }
        if let v6 = env.ipv6ProbeRoute, v6 != interface {
            return .notDefaultRoute(family: .ipv6, interface: v6)
        }
        return nil
    }

    /// Not link-local and not loopback: an address the tunnel can carry
    /// traffic from.
    public static func isRoutable(_ address: String) -> Bool {
        let bare = address.split(separator: "%", maxSplits: 1).first.map(String.init) ?? address
        guard let bytes = CIDR.bytes(bare) else { return false }
        if bytes.count == 4 { return bytes[0] != 127 && !(bytes[0] == 169 && bytes[1] == 254) }
        let linkLocal = bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80
        let loopback = bytes.dropLast().allSatisfy { $0 == 0 } && bytes.last == 1
        return !linkLocal && !loopback
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
/// Asymmetric on purpose: a service that stops owning the default route
/// leaves the set on the first reading that says so, because traffic is
/// already going around it; a service joins only after it has owned the
/// route for `upHold` across at least `upReadings` readings, because tunnels
/// publish their interface and route shortly before they are usable, and
/// flap while reconnecting. A failed read empties the set at once.
public struct TunnelSetDebouncer: Sendable {
    public let upHold: TimeInterval
    public let upReadings: Int

    public private(set) var connected: Set<String> = []
    private var pending: [String: (since: Date, readings: Int)] = [:]

    public init(upHold: TimeInterval = 3, upReadings: Int = 2) {
        precondition(upHold >= 0 && upReadings >= 1)
        self.upHold = upHold
        self.upReadings = upReadings
    }

    /// Feeds one reading. Returns the new set when it changed.
    public mutating func observe(_ reading: TunnelReading, at now: Date) -> Set<String>? {
        let seen = reading.failure == nil ? reading.connected : []
        let before = connected
        connected.formIntersection(seen)
        pending = pending.filter { seen.contains($0.key) }
        for id in seen where !connected.contains(id) {
            var entry = pending[id] ?? (now, 0)
            entry.readings += 1
            if entry.readings >= upReadings, now.timeIntervalSince(entry.since) >= upHold {
                connected.insert(id)
                pending[id] = nil
            } else {
                pending[id] = entry
            }
        }
        return connected == before ? nil : connected
    }

    /// When the next pending service could join, so a monitor can read once
    /// more then instead of waiting for its slow poll.
    public var nextDeadline: Date? {
        pending.values.map { $0.since.addingTimeInterval(upHold) }.min()
    }

    /// True while a service that owns the route is still inside its hold.
    public var hasPending: Bool { !pending.isEmpty }
}

/// CIDR membership for IPv4 and IPv6 literals, without sockets.
public enum CIDR {
    public static func contains(_ prefix: String, address: String) -> Bool {
        let parts = prefix.split(separator: "/", maxSplits: 1)
        guard parts.count == 2, let bits = Int(parts[1]),
              let network = bytes(String(parts[0])), let host = bytes(stripZone(address)),
              network.count == host.count, bits >= 0, bits <= network.count * 8 else { return false }
        var remaining = bits
        for index in 0..<network.count where remaining > 0 {
            let take = min(8, remaining)
            let mask: UInt8 = take == 8 ? 0xFF : ~(UInt8(0xFF) >> take)
            if network[index] & mask != host[index] & mask { return false }
            remaining -= take
        }
        return true
    }

    private static func stripZone(_ address: String) -> String {
        address.split(separator: "%", maxSplits: 1).first.map(String.init) ?? address
    }

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
