import Darwin
import Foundation
import SystemConfiguration

/// Reads a `TunnelEnvironment` from the running system. A seam so the monitor
/// can be driven by captured states in tests.
public protocol TunnelEnvironmentReading: Sendable {
    func read(probe: TunnelProbe) -> TunnelEnvironment
}

/// The live reader: the dynamic store, `getifaddrs`, and one routing-socket
/// lookup per address family. No subprocess and no privilege: every call here
/// works for an ordinary user, which is also how the test harness checks it.
public struct SystemTunnelEnvironmentReader: TunnelEnvironmentReading {
    public init() {}

    public func read(probe: TunnelProbe) -> TunnelEnvironment {
        var failures: [String] = []
        var store: [String: Any] = [:]
        if let session = SCDynamicStoreCreate(nil, "FreeSnitchTunnelReader" as CFString, nil, nil) {
            store = (SCDynamicStoreCopyMultiple(session, nil, TunnelStatus.storePatterns as CFArray) as? [String: Any]) ?? [:]
        } else {
            failures.append("dynamic store: \(String(cString: SCErrorString(SCError())))")
        }
        let interfaces: [String: TunnelInterfaceState]
        do { interfaces = try Self.interfaces() } catch {
            interfaces = [:]
            failures.append("interfaces: \(error)")
        }
        var v4: String?
        var v6: String?
        do { v4 = try Self.routeInterface(to: probe.ipv4) } catch { failures.append("IPv4 route: \(error)") }
        do { v6 = try Self.routeInterface(to: probe.ipv6) } catch { failures.append("IPv6 route: \(error)") }
        return TunnelEnvironment(store: store, interfaces: interfaces, ipv4ProbeRoute: v4, ipv6ProbeRoute: v6,
                                 readFailure: failures.isEmpty ? nil : failures.joined(separator: "; "))
    }

    public struct ReadError: Error, CustomStringConvertible {
        public let description: String
    }

    static func interfaces() throws -> [String: TunnelInterfaceState] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else {
            throw ReadError(description: "getifaddrs failed: \(String(cString: strerror(errno)))")
        }
        defer { freeifaddrs(head) }
        var flags: [String: Bool] = [:]
        var addresses: [String: [String]] = [:]
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            let name = String(cString: entry.pointee.ifa_name)
            let raw = Int32(entry.pointee.ifa_flags)
            flags[name] = (raw & IFF_UP) != 0 && (raw & IFF_RUNNING) != 0
            if let sa = entry.pointee.ifa_addr,
               sa.pointee.sa_family == UInt8(AF_INET) || sa.pointee.sa_family == UInt8(AF_INET6) {
                var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(sa, socklen_t(sa.pointee.sa_len), &host, socklen_t(host.count),
                               nil, 0, NI_NUMERICHOST) == 0 {
                    addresses[name, default: []].append(String(cString: host))
                }
            }
            cursor = entry.pointee.ifa_next
        }
        return flags.reduce(into: [:]) { result, item in
            result[item.key] = TunnelInterfaceState(isUp: item.value, addresses: addresses[item.key] ?? [])
        }
    }

    /// The interface the kernel would send `address` through, as `route get`
    /// prints it. Nil when there is no route; throws when the lookup itself
    /// fails, which the caller treats as unknown, never as "no route".
    static func routeInterface(to address: String) throws -> String? {
        guard let destination = CIDR.bytes(address) else {
            throw ReadError(description: "\(address) is not an address literal")
        }
        let fd = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC)
        guard fd >= 0 else { throw ReadError(description: "routing socket: \(String(cString: strerror(errno)))") }
        defer { close(fd) }
        var timeout = timeval(tv_sec: 1, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        let headerSize = MemoryLayout<rt_msghdr>.size
        var sockaddrBytes: [UInt8]
        if destination.count == 4 {
            var sin = sockaddr_in()
            sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            sin.sin_family = sa_family_t(AF_INET)
            withUnsafeMutableBytes(of: &sin.sin_addr) { $0.copyBytes(from: destination) }
            sockaddrBytes = withUnsafeBytes(of: &sin) { Array($0) }
        } else {
            var sin6 = sockaddr_in6()
            sin6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            sin6.sin6_family = sa_family_t(AF_INET6)
            withUnsafeMutableBytes(of: &sin6.sin6_addr) { $0.copyBytes(from: destination) }
            sockaddrBytes = withUnsafeBytes(of: &sin6) { Array($0) }
        }
        let seq = Int32.random(in: 1...Int32.max)
        var header = rt_msghdr()
        header.rtm_msglen = UInt16(headerSize + sockaddrBytes.count)
        header.rtm_version = UInt8(RTM_VERSION)
        header.rtm_type = UInt8(RTM_GET)
        header.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_HOST | RTF_STATIC
        header.rtm_addrs = RTA_DST
        header.rtm_pid = getpid()
        header.rtm_seq = seq
        var message = withUnsafeBytes(of: &header) { Array($0) }
        message.append(contentsOf: sockaddrBytes)

        let written = message.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        if written < 0 {
            // The kernel answers a lookup with no matching route this way.
            if errno == ESRCH || errno == ENETUNREACH { return nil }
            throw ReadError(description: "route lookup for \(address): \(String(cString: strerror(errno)))")
        }
        var buffer = [UInt8](repeating: 0, count: 2048)
        let pid = getpid()
        // Other processes' routing messages arrive on the same socket; only
        // the answer to this request counts.
        for _ in 0..<64 {
            let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
            guard count >= headerSize else {
                throw ReadError(description: "route lookup for \(address): no answer")
            }
            let reply = buffer.withUnsafeBytes { $0.load(as: rt_msghdr.self) }
            guard reply.rtm_type == UInt8(RTM_GET), reply.rtm_pid == pid, reply.rtm_seq == seq else { continue }
            if reply.rtm_errno != 0 {
                if reply.rtm_errno == ESRCH { return nil }
                throw ReadError(description: "route lookup for \(address): \(String(cString: strerror(reply.rtm_errno)))")
            }
            var name = [CChar](repeating: 0, count: Int(IF_NAMESIZE) + 1)
            guard reply.rtm_index > 0, if_indextoname(UInt32(reply.rtm_index), &name) != nil else { return nil }
            return String(cString: name)
        }
        throw ReadError(description: "route lookup for \(address): answer never arrived")
    }
}

/// Watches the tunnel services from the helper (or any process with a
/// dispatch queue; it needs no run loop and no GUI) and reports every change
/// of the debounced set of connected services. Dynamic store notifications
/// drive it, a slow poll covers a missed one, and a pending service is read
/// again when its hold ends instead of waiting for the poll.
public final class TunnelMonitor: @unchecked Sendable {
    public let probe: TunnelProbe
    private let reader: TunnelEnvironmentReading
    private let queue: DispatchQueue
    private let pollInterval: TimeInterval
    private let now: @Sendable () -> Date
    private var debouncer: TunnelSetDebouncer
    private var store: SCDynamicStore?
    private var pollTimer: DispatchSourceTimer?
    private var holdTimer: DispatchSourceTimer?
    private var delivered: Set<String>?
    private var lastReading: TunnelReading?

    /// Called on the monitor's queue with the settled set of connected
    /// services and the reading that settled it. The first call reports the
    /// starting state.
    public var onChange: ((TunnelState) -> Void)?

    public init(probe: TunnelProbe = .standard,
                reader: TunnelEnvironmentReading = SystemTunnelEnvironmentReader(),
                debouncer: TunnelSetDebouncer = TunnelSetDebouncer(),
                pollInterval: TimeInterval = 30,
                queue: DispatchQueue = DispatchQueue(label: "io.isaaclins.freesnitch.tunnel", qos: .utility),
                now: @escaping @Sendable () -> Date = { Date() }) {
        self.probe = probe
        self.reader = reader
        self.debouncer = debouncer
        self.pollInterval = pollInterval
        self.queue = queue
        self.now = now
    }

    /// The settled state, or nil before the first one.
    public var currentState: TunnelState? {
        queue.sync { delivered.map { TunnelState(connected: $0, services: lastReading?.services ?? []) } }
    }
    public var currentReading: TunnelReading? { queue.sync { lastReading } }

    public func start() {
        queue.async { [self] in
            guard store == nil else { return }
            var context = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
                                                retain: nil, release: nil, copyDescription: nil)
            let callback: SCDynamicStoreCallBack = { _, _, info in
                guard let info else { return }
                Unmanaged<TunnelMonitor>.fromOpaque(info).takeUnretainedValue().evaluateLocked()
            }
            if let created = SCDynamicStoreCreate(nil, "FreeSnitchTunnelMonitor" as CFString, callback, &context) {
                let patterns = TunnelStatus.storePatterns + TunnelStatus.globalPatterns
                if SCDynamicStoreSetNotificationKeys(created, nil, patterns as CFArray),
                   SCDynamicStoreSetDispatchQueue(created, queue) {
                    store = created
                } else {
                    PSLog.error(PSLog.helper, "tunnel change notifications unavailable; polling every \(Int(pollInterval)) s")
                }
            }
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now() + pollInterval, repeating: pollInterval, leeway: .seconds(1))
            timer.setEventHandler { [weak self] in self?.evaluateLocked() }
            timer.resume()
            pollTimer = timer
            evaluateLocked()
        }
    }

    public func stop() {
        queue.sync {
            if let store { SCDynamicStoreSetDispatchQueue(store, nil) }
            store = nil
            pollTimer?.cancel(); pollTimer = nil
            holdTimer?.cancel(); holdTimer = nil
        }
    }

    /// Reads and decides once, now. The monitor calls it on every
    /// notification; tests call it directly.
    public func evaluate() { queue.sync { evaluateLocked() } }

    private func evaluateLocked() {
        let reading = TunnelStatus.evaluate(reader.read(probe: probe))
        let servicesChanged = lastReading?.services != reading.services
        lastReading = reading
        _ = debouncer.observe(reading, at: now())
        let state = debouncer.connected
        scheduleHoldCheckLocked()
        // At start, a tunnel still inside its hold is not yet a state:
        // reporting "none connected" first would switch profiles twice on
        // every helper start while a tunnel is up.
        if delivered == nil, debouncer.hasPending { return }
        // A service appearing or disappearing is reported too, so the list
        // offered in the app stays current.
        guard delivered != state || servicesChanged else { return }
        delivered = state
        onChange?(TunnelState(connected: state, services: reading.services))
    }

    private func scheduleHoldCheckLocked() {
        holdTimer?.cancel(); holdTimer = nil
        guard let deadline = debouncer.nextDeadline else { return }
        let delay = max(0, deadline.timeIntervalSince(now())) + 0.1
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + delay)
        timer.setEventHandler { [weak self] in self?.evaluateLocked() }
        timer.resume()
        holdTimer = timer
    }
}

/// The settled tunnel state other code acts on.
public struct TunnelState: Equatable, Sendable {
    /// Service ids that own the default route, after debouncing.
    public let connected: Set<String>
    /// Every tunnel service present, for choosing one in the app.
    public let services: [TunnelService]

    public init(connected: Set<String>, services: [TunnelService]) {
        self.connected = connected
        self.services = services
    }

    public var anyConnected: Bool { !connected.isEmpty }
}
