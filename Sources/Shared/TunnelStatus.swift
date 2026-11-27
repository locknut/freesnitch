import Foundation

/// Whether a full tunnel such as Cloudflare WARP is carrying this Mac's
/// traffic right now. Decided from what macOS itself uses to route, never from
/// the tunnel client's own status text: in WARP's DNS-only mode `warp-cli
/// status` reports "Connected" while no tunnel exists at all.
///
/// The reading is split in two so the decision is pure and testable:
/// `TunnelEnvironment` is what was read (dynamic store keys, interface state,
/// route lookups), and `TunnelStatus.evaluate` turns that into a reading.
/// `TunnelStateDebouncer` then decides when a reading becomes the state other
/// code acts on.
public enum TunnelReading: Equatable, Sendable {
    /// Every condition holds: the tunnel interface exists, is up, carries the
    /// tunnel's address, and default traffic is routed into it.
    case up(interface: String)
    /// The tunnel is not carrying traffic, and the reading says why.
    case down(TunnelDownReason)

    public var isUp: Bool {
        if case .up = self { return true }
        return false
    }
}

public enum TunnelDownReason: Equatable, Sendable, CustomStringConvertible {
    /// No service entry for the tunnel, or one that names no interface.
    case noService
    case interfaceMissing(String)
    case interfaceDown(String)
    /// The interface has no address in the tunnel's range.
    case noTunnelAddress(String)
    /// Traffic for the probe address leaves by another interface (or by none).
    case routedElsewhere(family: TunnelAddressFamily, interface: String?)
    /// Something could not be read. Treated exactly like down: an unknown
    /// state must never be mistaken for a working tunnel.
    case unreadable(String)

    public var description: String {
        switch self {
        case .noService: return "no tunnel service is published"
        case .interfaceMissing(let name): return "tunnel interface \(name) does not exist"
        case .interfaceDown(let name): return "tunnel interface \(name) is not up"
        case .noTunnelAddress(let name): return "tunnel interface \(name) has no tunnel address"
        case .routedElsewhere(let family, let interface):
            return "\(family) traffic is routed via \(interface ?? "no interface"), not the tunnel"
        case .unreadable(let detail): return "tunnel state could not be read: \(detail)"
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
    /// Dynamic store contents, keyed as the store keys them.
    public var store: [String: Any]
    /// Interface name to its state. An interface missing here does not exist.
    public var interfaces: [String: TunnelInterfaceState]
    /// The interface the kernel would send the IPv4 probe address through,
    /// or nil when there is no IPv4 route at all.
    public var ipv4ProbeRoute: String?
    /// The same for the IPv6 probe. Nil means no IPv6 route, which is fine:
    /// then nothing can leak around the tunnel over IPv6.
    public var ipv6ProbeRoute: String?
    /// Set when a read failed. Any failure makes the whole reading down.
    public var readFailure: String?

    public init(store: [String: Any],
                interfaces: [String: TunnelInterfaceState],
                ipv4ProbeRoute: String?,
                ipv6ProbeRoute: String?,
                readFailure: String? = nil) {
        self.store = store
        self.interfaces = interfaces
        self.ipv4ProbeRoute = ipv4ProbeRoute
        self.ipv6ProbeRoute = ipv6ProbeRoute
        self.readFailure = readFailure
    }
}

/// Which tunnel to look for. Only Cloudflare WARP is described today; the
/// shape leaves room for another client that publishes its own service.
public struct TunnelDefinition: Equatable, Sendable {
    public let displayName: String
    /// The dynamic store service id the client publishes.
    public let serviceID: String
    /// Addresses the client gives its tunnel interface, as CIDR prefixes.
    public let ipv4Prefixes: [String]
    public let ipv6Prefixes: [String]
    /// Public addresses whose route decides where default traffic goes. A
    /// route lookup sends nothing; the address only has to be outside any
    /// split-tunnel exclude range.
    public let ipv4Probe: String
    public let ipv6Probe: String

    public init(displayName: String, serviceID: String, ipv4Prefixes: [String], ipv6Prefixes: [String],
                ipv4Probe: String, ipv6Probe: String) {
        self.displayName = displayName
        self.serviceID = serviceID
        self.ipv4Prefixes = ipv4Prefixes
        self.ipv6Prefixes = ipv6Prefixes
        self.ipv4Probe = ipv4Probe
        self.ipv6Probe = ipv6Probe
    }

    /// Cloudflare WARP as its macOS client publishes itself: a
    /// `CloudflareWARP` service (with no `VPN` entry, so `VPNStatus` alone
    /// never saw it), a utun interface in 100.96.0.0/12, and a scoped default
    /// route into that interface while `PrimaryInterface` stays the physical
    /// one.
    public static let cloudflareWARP = TunnelDefinition(
        displayName: "Cloudflare WARP",
        serviceID: "CloudflareWARP",
        ipv4Prefixes: ["100.96.0.0/12"],
        ipv6Prefixes: ["2606:4700:cf1::/48"],
        ipv4Probe: "1.1.1.1",
        ipv6Probe: "2606:4700:4700::1111"
    )

    public func with(ipv4Probe: String? = nil, ipv6Probe: String? = nil) -> TunnelDefinition {
        TunnelDefinition(displayName: displayName, serviceID: serviceID,
                         ipv4Prefixes: ipv4Prefixes, ipv6Prefixes: ipv6Prefixes,
                         ipv4Probe: ipv4Probe ?? self.ipv4Probe, ipv6Probe: ipv6Probe ?? self.ipv6Probe)
    }

    /// The dynamic store patterns a monitor has to watch for this tunnel.
    public var storePatterns: [String] {
        ["State:/Network/Service/\(serviceID)/.*", "State:/Network/Global/IPv4", "State:/Network/Global/IPv6"]
    }
}

public enum TunnelStatus {
    /// Pure. Four conditions, all required; the first that fails is reported.
    public static func evaluate(_ env: TunnelEnvironment, tunnel: TunnelDefinition = .cloudflareWARP) -> TunnelReading {
        if let failure = env.readFailure { return .down(.unreadable(failure)) }
        let base = "State:/Network/Service/\(tunnel.serviceID)"
        // 1. The service is published and names its interface.
        let interface = interfaceName(env.store["\(base)/IPv4"]) ?? interfaceName(env.store["\(base)/IPv6"])
        guard let interface else { return .down(.noService) }
        // 2. The interface exists and is up.
        guard let state = env.interfaces[interface] else { return .down(.interfaceMissing(interface)) }
        guard state.isUp else { return .down(.interfaceDown(interface)) }
        // 3. It carries the tunnel's address, so a reused utun name belonging
        //    to something else does not count.
        let inRange = state.addresses.contains { address in
            (tunnel.ipv4Prefixes + tunnel.ipv6Prefixes).contains { CIDR.contains($0, address: address) }
        }
        guard inRange else { return .down(.noTunnelAddress(interface)) }
        // 4. Default traffic goes into it. PrimaryInterface is no use here:
        //    WARP leaves it on the physical interface and adds a scoped
        //    default route instead.
        guard env.ipv4ProbeRoute == interface else {
            return .down(.routedElsewhere(family: .ipv4, interface: env.ipv4ProbeRoute))
        }
        if let v6 = env.ipv6ProbeRoute, v6 != interface {
            return .down(.routedElsewhere(family: .ipv6, interface: v6))
        }
        return .up(interface: interface)
    }

    private static func interfaceName(_ value: Any?) -> String? {
        guard let entry = value as? [String: Any],
              let name = entry["InterfaceName"] as? String, !name.isEmpty else { return nil }
        return name
    }
}

/// Turns readings into the state other code acts on. Asymmetric on purpose:
/// losing the tunnel takes effect on the first down reading, because traffic
/// is already leaving outside it; getting it back takes effect only after the
/// up reading has held for `upHold` across at least `upReadings` readings,
/// because WARP publishes its interface and route about a second before it
/// reports Connected, and flaps while reconnecting.
public struct TunnelStateDebouncer: Sendable {
    public let upHold: TimeInterval
    public let upReadings: Int

    /// The state in force. Starts down: nothing is known until a reading
    /// says otherwise.
    public private(set) var isUp = false
    private var upSince: Date?
    private var consecutiveUp = 0

    public init(upHold: TimeInterval = 3, upReadings: Int = 2) {
        precondition(upHold >= 0 && upReadings >= 1)
        self.upHold = upHold
        self.upReadings = upReadings
    }

    /// Feeds one reading. Returns the new state when it changed, nil when it
    /// did not.
    public mutating func observe(_ reading: TunnelReading, at now: Date) -> Bool? {
        guard reading.isUp else {
            upSince = nil
            consecutiveUp = 0
            if isUp { isUp = false; return false }
            return nil
        }
        if upSince == nil { upSince = now }
        consecutiveUp += 1
        guard !isUp, consecutiveUp >= upReadings, let since = upSince,
              now.timeIntervalSince(since) >= upHold else { return nil }
        isUp = true
        return true
    }

    /// When a pending up would be confirmed, so a monitor can schedule one
    /// more reading then instead of waiting for its slow poll.
    public var pendingUpDeadline: Date? {
        guard !isUp, let upSince else { return nil }
        return upSince.addingTimeInterval(upHold)
    }
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
