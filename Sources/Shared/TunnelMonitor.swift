import Darwin
import Foundation
import SystemConfiguration

/// Reads a `TunnelEnvironment` from the running system. A seam so the monitor
/// can be driven by captured states in tests.
public protocol TunnelEnvironmentReading: Sendable {
    func read(probe: TunnelProbe) -> TunnelEnvironment
}

/// The live reader: the dynamic store, `getifaddrs`, and the kernel's route
/// choice for each probe address. No subprocess and no privilege: every call
/// here works for an ordinary user, which is also how the test harness
/// checks it.
///
/// The route choice is read by connecting an unbound UDP socket to the probe
/// address (which sends nothing) and asking which local address the kernel
/// picked; the interface holding that address is the one traffic would leave
/// by. Unlike a routing socket, this involves no channel other processes can
/// write to, so no other process can make a lookup fail.
public final class SystemTunnelEnvironmentReader: TunnelEnvironmentReading, @unchecked Sendable {
    private let lock = NSLock()
    private var session: SCDynamicStore?

    public init() {}

    public func read(probe: TunnelProbe) -> TunnelEnvironment {
        var failures: [String] = []
        var store: [String: Any] = [:]
        if let session = dynamicStore() {
            store = (SCDynamicStoreCopyMultiple(session, nil, TunnelStatus.storePatterns as CFArray) as? [String: Any]) ?? [:]
        } else {
            failures.append("dynamic store: \(String(cString: SCErrorString(SCError())))")
        }
        let interfaces: [String: TunnelInterfaceState]
        do { interfaces = try Self.interfaces() } catch {
            interfaces = [:]
            failures.append("interfaces: \(error)")
        }
        let owners = Self.addressOwners(interfaces)
        func routes(_ addresses: [String]) -> [String?] {
            addresses.map { address in
                do { return try Self.routeInterface(to: address, owners: owners) } catch {
                    failures.append("route to \(address): \(error)")
                    return nil
                }
            }
        }
        let v4 = routes(probe.ipv4)
        let v6 = routes(probe.ipv6)
        return TunnelEnvironment(store: store, interfaces: interfaces, ipv4ProbeRoutes: v4, ipv6ProbeRoutes: v6,
                                 readFailure: failures.isEmpty ? nil : failures.joined(separator: "; "))
    }

    /// One session for the reader's lifetime instead of one per reading.
    private func dynamicStore() -> SCDynamicStore? {
        lock.lock()
        defer { lock.unlock() }
        if session == nil { session = SCDynamicStoreCreate(nil, "FreeSnitchTunnelReader" as CFString, nil, nil) }
        return session
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
               sa.pointee.sa_family == UInt8(AF_INET) || sa.pointee.sa_family == UInt8(AF_INET6),
               let text = numericHost(sa) {
                addresses[name, default: []].append(text)
            }
            cursor = entry.pointee.ifa_next
        }
        return flags.reduce(into: [:]) { result, item in
            result[item.key] = TunnelInterfaceState(isUp: item.value, addresses: addresses[item.key] ?? [])
        }
    }

    /// Address (without a zone) to the interface that holds it.
    static func addressOwners(_ interfaces: [String: TunnelInterfaceState]) -> [String: String] {
        var owners: [String: String] = [:]
        for (name, state) in interfaces.sorted(by: { $0.key < $1.key }) {
            for address in state.addresses {
                let bare = address.split(separator: "%", maxSplits: 1).first.map(String.init) ?? address
                if owners[bare] == nil { owners[bare] = name }
            }
        }
        return owners
    }

    private static func numericHost(_ sa: UnsafePointer<sockaddr>) -> String? {
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(sa, socklen_t(sa.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else {
            return nil
        }
        return String(cString: host)
    }

    /// The interface the kernel would send `address` through. Nil when there
    /// is no route. Throws when the lookup itself fails, which the caller
    /// treats as unknown, never as "no route".
    static func routeInterface(to address: String, owners: [String: String]) throws -> String? {
        guard let destination = CIDR.bytes(address) else {
            throw ReadError(description: "\(address) is not an address literal")
        }
        let family = destination.count == 4 ? AF_INET : AF_INET6
        let fd = socket(family, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { throw ReadError(description: "socket: \(String(cString: strerror(errno)))") }
        defer { close(fd) }

        var storage = sockaddr_storage()
        let length: socklen_t
        if family == AF_INET {
            var sin = sockaddr_in()
            sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            sin.sin_family = sa_family_t(AF_INET)
            sin.sin_port = in_port_t(53).bigEndian
            withUnsafeMutableBytes(of: &sin.sin_addr) { $0.copyBytes(from: destination) }
            withUnsafeMutableBytes(of: &storage) { raw in withUnsafeBytes(of: &sin) { raw.copyMemory(from: $0) } }
            length = socklen_t(MemoryLayout<sockaddr_in>.size)
        } else {
            var sin6 = sockaddr_in6()
            sin6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            sin6.sin6_family = sa_family_t(AF_INET6)
            sin6.sin6_port = in_port_t(53).bigEndian
            withUnsafeMutableBytes(of: &sin6.sin6_addr) { $0.copyBytes(from: destination) }
            withUnsafeMutableBytes(of: &storage) { raw in withUnsafeBytes(of: &sin6) { raw.copyMemory(from: $0) } }
            length = socklen_t(MemoryLayout<sockaddr_in6>.size)
        }
        // A UDP connect only picks the route and the local address; no packet
        // is sent.
        let connected = withUnsafePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, length) }
        }
        if connected != 0 {
            switch errno {
            case ENETUNREACH, EHOSTUNREACH, EADDRNOTAVAIL, ENETDOWN:
                return nil
            default:
                throw ReadError(description: "connect: \(String(cString: strerror(errno)))")
            }
        }
        var local = sockaddr_storage()
        var localLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let named = withUnsafeMutablePointer(to: &local) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &localLength) }
        }
        guard named == 0 else { throw ReadError(description: "getsockname: \(String(cString: strerror(errno)))") }
        let text = withUnsafePointer(to: &local) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { numericHost($0) }
        }
        guard let text else { throw ReadError(description: "the local address could not be read") }
        let bare = text.split(separator: "%", maxSplits: 1).first.map(String.init) ?? text
        guard let owner = owners[bare] else {
            // The address changed between reading the interfaces and the
            // lookup; the next reading settles it.
            throw ReadError(description: "no interface holds the local address \(bare)")
        }
        return owner
    }
}

/// Watches the tunnel services from the helper (or any process with a
/// dispatch queue; it needs no run loop and no GUI) and reports every change
/// of the settled set of connected services. Dynamic store notifications
/// drive it, bursts of them are coalesced, a slow poll covers a missed one,
/// and a pending change is read again when its hold or retry time ends.
public final class TunnelMonitor: @unchecked Sendable {
    public let probe: TunnelProbe
    private let reader: TunnelEnvironmentReading
    private let queue: DispatchQueue
    private let pollInterval: TimeInterval
    private let now: @Sendable () -> TimeInterval
    private var debouncer: TunnelSetDebouncer
    private var store: SCDynamicStore?
    /// Retained by the monitor while watching; holds the monitor weakly, so a
    /// notification after the monitor is gone does nothing.
    private var callbackBox: Unmanaged<CallbackBox>?
    private var pollTimer: DispatchSourceTimer?
    private var recheckTimer: DispatchSourceTimer?
    private var evaluationScheduled = false
    private var running = false
    private var delivered: Set<String>?
    private var lastReading: TunnelReading?
    private var lastLoggedFailure: String?

    private final class CallbackBox {
        weak var monitor: TunnelMonitor?
        init(_ monitor: TunnelMonitor) { self.monitor = monitor }
    }

    /// Called on the monitor's queue with the settled state. The first call
    /// reports the starting state.
    public var onChange: ((TunnelState) -> Void)?

    /// `now` is a monotonic clock in seconds: a wall-clock step must never
    /// stretch or skip a hold.
    public init(probe: TunnelProbe = .standard,
                reader: TunnelEnvironmentReading = SystemTunnelEnvironmentReader(),
                debouncer: TunnelSetDebouncer = TunnelSetDebouncer(),
                pollInterval: TimeInterval = 30,
                queue: DispatchQueue = DispatchQueue(label: "io.isaaclins.freesnitch.tunnel", qos: .utility),
                now: @escaping @Sendable () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.probe = probe
        self.reader = reader
        self.debouncer = debouncer
        self.pollInterval = pollInterval
        self.queue = queue
        self.now = now
    }

    deinit {
        if let store { SCDynamicStoreSetDispatchQueue(store, nil) }
        callbackBox?.release()
        pollTimer?.cancel()
        recheckTimer?.cancel()
    }

    /// The settled state, or nil before the first one.
    public var currentState: TunnelState? {
        queue.sync { delivered.map { TunnelState(connected: $0, services: lastReading?.services ?? []) } }
    }

    public var isRunning: Bool { queue.sync { running } }

    public func start() {
        queue.async { [self] in
            guard !running else { return }
            running = true
            let box = Unmanaged.passRetained(CallbackBox(self))
            var context = SCDynamicStoreContext(version: 0, info: box.toOpaque(),
                                                retain: nil, release: nil, copyDescription: nil)
            let callback: SCDynamicStoreCallBack = { _, _, info in
                guard let info else { return }
                Unmanaged<CallbackBox>.fromOpaque(info).takeUnretainedValue().monitor?.scheduleEvaluationLocked()
            }
            if let created = SCDynamicStoreCreate(nil, "FreeSnitchTunnelMonitor" as CFString, callback, &context),
               SCDynamicStoreSetNotificationKeys(created, nil, (TunnelStatus.storePatterns + TunnelStatus.globalPatterns) as CFArray),
               SCDynamicStoreSetDispatchQueue(created, queue) {
                store = created
                callbackBox = box
            } else {
                box.release()
                PSLog.error(PSLog.helper, "VPN change notifications unavailable; polling every \(Int(pollInterval)) s")
            }
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now() + pollInterval, repeating: pollInterval, leeway: .seconds(1))
            timer.setEventHandler { [weak self] in self?.evaluateLocked() }
            timer.resume()
            pollTimer = timer
            evaluateLocked()
        }
    }

    /// Stops watching. Nothing queued before this re-arms a timer after it.
    /// The settled state is forgotten, so a later `start` reports afresh.
    public func stop() {
        queue.sync {
            running = false
            if let store { SCDynamicStoreSetDispatchQueue(store, nil) }
            store = nil
            callbackBox?.release(); callbackBox = nil
            pollTimer?.cancel(); pollTimer = nil
            recheckTimer?.cancel(); recheckTimer = nil
            evaluationScheduled = false
            delivered = nil
            lastReading = nil
            debouncer.reset()
        }
    }

    /// Reads and decides once, now. Tests call it directly.
    public func evaluate() { queue.sync { evaluateLocked(force: true) } }

    /// A burst of store notifications (a tunnel coming up writes several
    /// keys) becomes one reading.
    private func scheduleEvaluationLocked() {
        guard running, !evaluationScheduled else { return }
        evaluationScheduled = true
        queue.asyncAfter(deadline: .now() + 0.2) { [weak self] in
            guard let self else { return }
            self.evaluationScheduled = false
            self.evaluateLocked()
        }
    }

    private func evaluateLocked(force: Bool = false) {
        guard running || force else { return }
        let reading = TunnelStatus.evaluate(reader.read(probe: probe))
        // Logged once per distinct failure, not on every retry.
        if reading.failure != lastLoggedFailure {
            if let failure = reading.failure {
                PSLog.error(PSLog.helper, "VPN state could not be read: \(failure)")
            } else if lastLoggedFailure != nil {
                PSLog.info(PSLog.helper, "VPN state can be read again.")
            }
            lastLoggedFailure = reading.failure
        }
        let servicesChanged = lastReading?.services != reading.services
        lastReading = reading
        _ = debouncer.observe(reading, at: now())
        let state = debouncer.connected
        scheduleRecheckLocked()
        // At start, a tunnel still inside its hold, or a read still inside
        // its retry window, is not yet a state: reporting "none connected"
        // first would switch profiles twice on every helper start.
        if delivered == nil, debouncer.isUnsettled { return }
        guard delivered != state || servicesChanged else { return }
        delivered = state
        onChange?(TunnelState(connected: state, services: reading.services))
    }

    private func scheduleRecheckLocked() {
        recheckTimer?.cancel(); recheckTimer = nil
        guard running, let deadline = debouncer.nextDeadline else { return }
        let delay = max(0, deadline - now()) + 0.1
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + delay)
        timer.setEventHandler { [weak self] in self?.evaluateLocked() }
        timer.resume()
        recheckTimer = timer
    }
}

/// The settled VPN state other code acts on.
public struct TunnelState: Equatable, Sendable {
    /// Service ids that own the default route, after debouncing. May contain
    /// `TunnelStatus.unlistedTunnelID` (see there), which only "any VPN"
    /// triggers see.
    public let connected: Set<String>
    /// Every tunnel service present, for choosing one in the app.
    public let services: [TunnelService]

    public init(connected: Set<String>, services: [TunnelService]) {
        self.connected = connected
        self.services = services
    }

    public var anyConnected: Bool { !connected.isEmpty }
}
