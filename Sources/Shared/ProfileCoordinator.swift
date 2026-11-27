import Foundation

/// Owns which profile is active, how a switch becomes visible, and how it is
/// undone.
///
/// Two invariants are structural rather than documented hopes:
///
/// 1. A switch changes only the policy that future flows are judged against.
///    There is no method here that enumerates, inspects, or drops established
///    flows, and none may be added: `handleNewFlow` in the network extension is
///    the only consumer of a policy change.
/// 2. Automatic switching happens only for a binding the user created with
///    `bindCurrentNetwork(toProfile:)`, or for the opt-in tunnel setting
///    (`TunnelProfileSwitch`). An unknown gateway leaves the active profile
///    exactly where it is.
///
/// While the tunnel setting names a profile for the current tunnel state, it
/// takes precedence over gateway bindings: being inside the organisation's
/// tunnel says more about where traffic goes than which router is nearby.
public final class ProfileCoordinator: @unchecked Sendable {
    public enum SwitchReason: String, Sendable {
        case user
        case network
        case undo
        /// A full tunnel (Cloudflare WARP) came up or went down.
        case tunnel
    }

    public struct SwitchResult: Sendable {
        public let reason: SwitchReason
        public let notice: ProfileSwitchNotice
        public let policy: ProfilePolicy
        public let previousProfile: String?

        public init(reason: SwitchReason,
                    notice: ProfileSwitchNotice,
                    policy: ProfilePolicy,
                    previousProfile: String?) {
            self.reason = reason
            self.notice = notice
            self.policy = policy
            self.previousProfile = previousProfile
        }
    }

    private let store: RuleStore
    private let watcher: GatewayMACWatcher
    private let lock = NSLock()
    private var undoTarget: String?
    private var switchHandler: ((SwitchResult) -> Void)?
    private var pendingHandler: ((PendingNetworkSwitch?) -> Void)?
    private var lastObservedGatewayMAC: String?
    private var pending: PendingNetworkSwitch?
    /// The gateway whose automatic switch is settled: applied, not needed, or
    /// decided by the user picking a profile while on it. A delivery for this
    /// gateway, however late it arrives, does nothing; a different gateway
    /// still switches. Only read and written while `switchSerial` is held.
    /// Nil until the first gateway is handled; "" stands for no gateway.
    private var settledGatewayMAC: String?
    /// Serializes every switch, automatic and manual, so an automatic one
    /// that has already read its binding can't land after a pick the user
    /// made meanwhile. Recursive because a network switch calls `activate`.
    private let switchSerial = NSRecursiveLock()
    /// The debounced tunnel state last delivered, nil before the first one.
    /// Only read and written while `switchSerial` is held.
    private var tunnelUp: Bool?
    /// The tunnel state whose switch is settled: applied, not needed, or
    /// decided by the user picking a profile while in it. Mirrors
    /// `settledGatewayMAC`.
    private var settledTunnelUp: Bool?
    /// The tunnel switch still owed because activating its profile failed.
    private var pendingTunnel: (up: Bool, profile: String)?
    /// Where the tunnel setting is read from. The store by default; the
    /// helper replaces it when an MDM-managed value takes precedence.
    public var tunnelSwitchSettings: () throws -> TunnelProfileSwitch
    /// Runs inside a network switch, after its binding was read and before it
    /// is applied. Only the profiles harness sets it, to replay a manual pick
    /// arriving at exactly that moment.
    var networkSwitchHookForTesting: (() -> Void)?

    public init(store: RuleStore, watcher: GatewayMACWatcher = GatewayMACWatcher()) {
        self.store = store
        self.watcher = watcher
        self.tunnelSwitchSettings = { try store.tunnelProfileSwitch() }
    }

    /// Wiring point for the helper and the GUI: called after the active policy
    /// has already been committed, so a receiver only has to publish it.
    public var onSwitch: ((SwitchResult) -> Void)? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return switchHandler
        }
        set {
            lock.lock()
            switchHandler = newValue
            lock.unlock()
        }
    }

    /// Called when an automatic switch fails, when the failure changes, and
    /// when it clears. Not called again for every retry of the same failure.
    public var onPendingNetworkSwitchChanged: ((PendingNetworkSwitch?) -> Void)? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return pendingHandler
        }
        set {
            lock.lock()
            pendingHandler = newValue
            lock.unlock()
        }
    }

    /// The automatic switch this network is still owed, because activating
    /// its bound profile failed. Nil when nothing is outstanding (#269).
    public var pendingNetworkSwitch: PendingNetworkSwitch? {
        lock.lock()
        defer { lock.unlock() }
        return pending
    }

    /// Why the gateway could not be read, when it could not.
    public var gatewayReadProblem: ProfileProblem? {
        watcher.lastReadProblem
    }

    public var activeProfileName: String {
        store.activeProfileName()
    }

    public func profiles() -> [Profile] {
        store.allProfiles()
    }

    public func currentPolicy() throws -> ProfilePolicy {
        try store.activeProfilePolicy()
    }

    /// The gateway MAC last read by the watcher, or a fresh read when nothing
    /// has been observed yet. Never a Wi-Fi name and never a location.
    public var currentGatewayMAC: String? {
        lock.lock()
        let cached = lastObservedGatewayMAC
        lock.unlock()
        if let cached { return cached }
        return refreshGatewayMAC()
    }

    /// Forces a read of the default gateway. Used by anything that acts on the
    /// network the user is on right now, so a stale cached reading can never
    /// be bound to a profile.
    @discardableResult
    public func refreshGatewayMAC() -> String? {
        let current = watcher.refresh()
        lock.lock()
        lastObservedGatewayMAC = current
        lock.unlock()
        return current
    }

    public var canUndo: Bool {
        lock.lock()
        defer { lock.unlock() }
        return undoTarget != nil
    }

    // MARK: - switching

    @discardableResult
    public func activate(profileName: String, reason: SwitchReason = .user) throws -> SwitchResult {
        switchSerial.lock()
        defer { switchSerial.unlock() }
        let previousName = store.activeProfileName()
        let previousPolicy = try? store.profilePolicy(named: previousName)
        let activated = try store.setActiveProfile(name: profileName)
        let policy = try store.profilePolicy(named: activated.name)

        let changed = previousName != activated.name
        lock.lock()
        switch reason {
        case .undo:
            undoTarget = nil
        case .user, .network, .tunnel:
            undoTarget = changed ? previousName : undoTarget
        }
        let canUndoNow = undoTarget != nil
        let handler = switchHandler
        lock.unlock()

        let notice = ProfileSwitchNotice(
            activeProfile: activated.name,
            activeRuleCount: policy.activeRuleCount,
            pausedProfile: changed ? previousName : nil,
            // Always rules are never paused by a switch. Only the previous
            // profile's own layer stops applying.
            pausedRuleCount: changed ? (previousPolicy?.activeProfileRuleCount ?? 0) : 0,
            canUndo: canUndoNow
        )
        let result = SwitchResult(reason: reason,
                                  notice: notice,
                                  policy: policy,
                                  previousProfile: changed ? previousName : nil)
        handler?(result)
        // The user's own choice settles the network they are on: a retry for
        // it, even one already on its way, must not undo what they picked.
        if reason != .network && reason != .tunnel {
            lock.lock()
            let current = lastObservedGatewayMAC ?? ""
            lock.unlock()
            settledGatewayMAC = current
            // The same for the tunnel: the user's pick holds until the tunnel
            // really changes state.
            settledTunnelUp = tunnelUp
            pendingTunnel = nil
        }
        if reason != .network, let pendingSwitch = pendingNetworkSwitch {
            watcher.dropUndeliveredChange(for: pendingSwitch.gatewayMAC)
            setPending(nil)
        }
        return result
    }

    /// Reverses the most recent switch. Returns nil when there is nothing to
    /// undo, which is also what the notice reports through `canUndo`.
    @discardableResult
    public func undoLastSwitch() throws -> SwitchResult? {
        lock.lock()
        let target = undoTarget
        undoTarget = nil
        lock.unlock()
        guard let target else { return nil }
        return try activate(profileName: target, reason: .undo)
    }

    // MARK: - networks

    /// Explicit "use this here". This is the only way a binding is ever
    /// created; observing a network never writes one.
    @discardableResult
    public func bindCurrentNetwork(toProfile profileName: String) throws -> ProfileNetworkBinding {
        guard let mac = refreshGatewayMAC() else {
            throw ProfileValidationError.invalidGatewayMAC("no default gateway MAC is currently visible")
        }
        return try store.bindGatewayMAC(mac, toProfile: profileName)
    }

    @discardableResult
    public func bindNetwork(gatewayMAC: String, toProfile profileName: String) throws -> ProfileNetworkBinding {
        try store.bindGatewayMAC(gatewayMAC, toProfile: profileName)
    }

    public func unbindNetwork(gatewayMAC: String) throws {
        try store.unbindGatewayMAC(gatewayMAC)
    }

    public func bindings() -> [ProfileNetworkBinding] {
        store.allNetworkBindings()
    }

    public func binding(forCurrentNetwork: Bool = true) -> ProfileNetworkBinding? {
        guard forCurrentNetwork, let mac = currentGatewayMAC else { return nil }
        return store.networkBinding(forGatewayMAC: mac)
    }

    /// Starts observing the default gateway. Nothing switches unless the
    /// observed gateway MAC already has a user-created binding.
    public func startWatchingNetworks(every interval: TimeInterval = 5) {
        watcher.onChange = { [weak self] mac in
            guard let self else { return true }
            return self.applyObservedGatewayMAC(mac)
        }
        watcher.start(every: interval)
    }

    public func stopWatchingNetworks() {
        watcher.stop()
        watcher.onChange = nil
    }

    /// The watcher's entry point. A failed switch is logged, kept as pending
    /// for the Profiles screen, and reported as not handled, so the watcher
    /// delivers the same gateway again on its next poll until it works. Only
    /// a binding that is really gone, or a pick by the user, ends a retry.
    @discardableResult
    public func applyObservedGatewayMAC(_ rawMAC: String?) -> Bool {
        let mac = rawMAC.flatMap(GatewayMAC.normalized) ?? ""
        switchSerial.lock()
        defer { switchSerial.unlock() }
        // Already settled for this gateway (applied, or the user picked a
        // profile on it): a late or repeated delivery changes nothing.
        if settledGatewayMAC == mac { return true }
        // The tunnel setting owns the active profile right now: remember the
        // gateway (so a later unbound tunnel state can fall back to it) but
        // do not switch for it.
        if tunnelOwnsActiveProfile() {
            lock.lock()
            lastObservedGatewayMAC = rawMAC.flatMap(GatewayMAC.normalized)
            lock.unlock()
            settledGatewayMAC = mac
            return true
        }
        // Another gateway: whatever was settled belonged to the last one, and
        // coming back to it later is a real change again.
        settledGatewayMAC = nil
        var boundProfile: String?
        do {
            let result = try applyNetworkChange(rawMAC, boundProfile: &boundProfile)
            settledGatewayMAC = mac
            if pendingNetworkSwitch != nil {
                if let result {
                    PSLog.notice(PSLog.helper,
                                 "The profile \(result.notice.activeProfile) is now active for gateway \(mac).")
                }
                setPending(nil)
            }
            return true
        } catch {
            lock.lock()
            // When even the binding could not be read, the profile is the
            // one this gateway was already owed, if it is known.
            let known = pending?.gatewayMAC == mac ? pending?.profileName : nil
            let failure = PendingNetworkSwitch(gatewayMAC: mac,
                                               profileName: boundProfile ?? known ?? "",
                                               reason: ProfileProblem(error))
            let changed = pending != failure
            pending = failure
            let handler = pendingHandler
            lock.unlock()
            if changed {
                let target = failure.profileName.isEmpty
                    ? "this network's profile" : "the profile \(failure.profileName)"
                PSLog.error(PSLog.helper,
                            "Could not switch to \(target) for gateway \(mac): "
                            + "\(failure.problem). Retrying on every gateway check until it works.")
                handler?(failure)
            }
            return false
        }
    }

    // MARK: - tunnel

    /// Whether the tunnel setting names a profile for the tunnel state last
    /// delivered. Callers hold `switchSerial`. An unreadable setting owns
    /// nothing, so gateway bindings keep working.
    private func tunnelOwnsActiveProfile() -> Bool {
        guard let tunnelUp, let setting = try? tunnelSwitchSettings() else { return false }
        return setting.target(tunnelUp: tunnelUp) != nil
    }

    /// The monitor's entry point, called with each debounced tunnel state.
    /// Returns false when the switch it asked for failed; the caller retries
    /// with the same state until it returns true or the state changes.
    ///
    /// With the setting off, or with no profile named for this state, the
    /// gateway bindings decide, as they would without a tunnel at all.
    @discardableResult
    public func applyObservedTunnelState(_ up: Bool) -> Bool {
        switchSerial.lock()
        defer { switchSerial.unlock() }
        let changed = tunnelUp != up
        tunnelUp = up
        if changed { settledTunnelUp = nil }
        if settledTunnelUp == up { return true }
        let setting: TunnelProfileSwitch
        do {
            setting = try tunnelSwitchSettings()
        } catch {
            PSLog.error(PSLog.helper, "The tunnel profile setting could not be read: \(error.localizedDescription). "
                        + "Network bindings decide the profile until it can be read.")
            return true
        }
        guard let target = setting.target(tunnelUp: up) else {
            settledTunnelUp = up
            pendingTunnel = nil
            // Nothing is asked for this state, so the gateway decides again:
            // the gateway seen last is applied as if it had just been seen.
            if changed, setting.enabled {
                settledGatewayMAC = nil
                lock.lock()
                let mac = lastObservedGatewayMAC
                lock.unlock()
                var bound: String?
                _ = try? applyNetworkChange(mac, boundProfile: &bound)
                settledGatewayMAC = mac ?? ""
            }
            return true
        }
        do {
            if target != store.activeProfileName() {
                let result = try activate(profileName: target, reason: .tunnel)
                PSLog.notice(PSLog.helper, "The profile \(result.notice.activeProfile) is now active because "
                             + "\(TunnelDefinition.cloudflareWARP.displayName) is \(up ? "connected" : "not connected").")
            }
            settledTunnelUp = up
            pendingTunnel = nil
            // A gateway settled while the tunnel owned the profile is decided
            // again once the tunnel lets go of it.
            settledGatewayMAC = nil
            return true
        } catch {
            let first = pendingTunnel.map { $0.up != up || $0.profile != target } ?? true
            pendingTunnel = (up, target)
            if first {
                PSLog.error(PSLog.helper, "Could not switch to the profile \(target) for the tunnel state "
                            + "(\(up ? "connected" : "not connected")): \(error.localizedDescription). Retrying until it works.")
            }
            return false
        }
    }

    /// The tunnel switch still owed, for status output.
    public var pendingTunnelSwitch: (up: Bool, profile: String)? {
        switchSerial.lock()
        defer { switchSerial.unlock() }
        return pendingTunnel
    }

    private func setPending(_ value: PendingNetworkSwitch?) {
        lock.lock()
        let changed = pending != value
        pending = value
        let handler = pendingHandler
        lock.unlock()
        if changed { handler?(value) }
    }

    /// Applies a network change. Returns nil when the gateway is unknown, so a
    /// new network can never silently impose a profile the user never chose.
    @discardableResult
    public func handleGatewayMACChange(_ rawMAC: String?) throws -> SwitchResult? {
        var boundProfile: String?
        return try applyNetworkChange(rawMAC, boundProfile: &boundProfile)
    }

    /// Sets `boundProfile` as soon as the binding is known, so a caller whose
    /// switch then fails still knows which profile it was for. A binding that
    /// cannot be read throws: it is not the same as no binding.
    private func applyNetworkChange(_ rawMAC: String?, boundProfile: inout String?) throws -> SwitchResult? {
        let mac = rawMAC.flatMap(GatewayMAC.normalized)
        lock.lock()
        lastObservedGatewayMAC = mac
        lock.unlock()
        guard let mac, let binding = try store.lookUpNetworkBinding(forGatewayMAC: mac) else { return nil }
        boundProfile = binding.profileName
        networkSwitchHookForTesting?()
        guard binding.profileName != store.activeProfileName() else { return nil }
        return try activate(profileName: binding.profileName, reason: .network)
    }
}
