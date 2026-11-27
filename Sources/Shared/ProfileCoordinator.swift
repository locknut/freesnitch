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
///    `bindCurrentNetwork(toProfile:)`, or for a VPN trigger the user created
///    (`TunnelTrigger`). An unknown gateway leaves the active profile exactly
///    where it is.
///
/// While a VPN trigger matches, it takes precedence over gateway bindings:
/// whether traffic goes through a tunnel says more about where it goes than
/// which router is nearby.
public final class ProfileCoordinator: @unchecked Sendable {
    public enum SwitchReason: String, Sendable {
        case user
        case network
        case undo
        /// A VPN trigger matched (a tunnel came up or went down).
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
    /// The settled set of connected VPN services last delivered, nil before
    /// the first one. Only read and written while `switchSerial` is held.
    private var tunnelConnected: Set<String>?
    /// The winning trigger whose switch is settled (applied, or overridden
    /// by the user while it won), "" for none. Mirrors `settledGatewayMAC`.
    private var settledTriggerKey: String?
    /// A gateway delivery was set aside because a trigger matched. When no
    /// trigger matches any more, that gateway is applied after all, whether
    /// or not the trigger's own switch ever succeeded.
    private var gatewayDeferred = false
    /// The user picked a profile while the current trigger result held. When
    /// no trigger matches any more, their pick stays; only a new gateway or
    /// another winning trigger replaces it.
    private var userOverride = false
    /// Handing the profile back to the gateway failed; retried with the
    /// next VPN state delivery (the helper redelivers while this is set).
    private var gatewayHandBackOwed = false
    /// The trigger whose switch is still owed because activating failed.
    private var pendingTunnel: TunnelTrigger?
    /// Where the triggers are read from. The store by default; the helper
    /// replaces it when MDM manages them.
    public var tunnelTriggers: () throws -> [TunnelTrigger]
    /// Runs inside a network switch, after its binding was read and before it
    /// is applied. Only the profiles harness sets it, to replay a manual pick
    /// arriving at exactly that moment.
    var networkSwitchHookForTesting: (() -> Void)?

    public init(store: RuleStore, watcher: GatewayMACWatcher = GatewayMACWatcher()) {
        self.store = store
        self.watcher = watcher
        self.tunnelTriggers = { try store.tunnelTriggers() }
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
        if reason == .user || reason == .undo, let refusal = userSwitchRefusal?() {
            throw ProfileValidationError.managedByOrganization(refusal)
        }
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
            // The same for VPN triggers: the user's pick holds until another
            // trigger wins, and is not handed to the gateway when none does.
            settledTriggerKey = winningTriggerKey()
            userOverride = settledTriggerKey != nil
            gatewayHandBackOwed = false
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
            gatewayDeferred = true
            // A new network is a real change: the user's pick on the old one
            // no longer applies once the trigger lets go.
            userOverride = false
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

    // MARK: - VPN triggers

    /// The trigger that decides the profile for the VPN state last delivered,
    /// as a key that also changes when its profile does. Nil before the
    /// first state. Callers hold `switchSerial`. An unreadable trigger list
    /// decides nothing, so gateway bindings keep working.
    private func winningTriggerKey() -> String? {
        guard let tunnelConnected else { return nil }
        guard let triggers = try? tunnelTriggers() else { return "" }
        return TunnelTrigger.winner(triggers, connected: tunnelConnected).map { "\($0.id)>\($0.profile)" } ?? ""
    }

    private func tunnelOwnsActiveProfile() -> Bool {
        guard let key = winningTriggerKey() else { return false }
        return !key.isEmpty
    }

    /// The monitor's entry point, called with each settled set of connected
    /// VPN services. Returns false when the switch it asked for failed; the
    /// caller retries with the same state until it returns true or the state
    /// changes (`tunnelRetryOwed`).
    ///
    /// The winning trigger (see `TunnelTrigger.winner`) decides the profile.
    /// When no trigger matches any more, the gateway seen last decides, as it
    /// would without any VPN, unless the user picked a profile meanwhile: a
    /// pick holds until a new gateway or another winning trigger.
    @discardableResult
    public func applyObservedTunnelState(_ connected: Set<String>) -> Bool {
        switchSerial.lock()
        defer { switchSerial.unlock() }
        tunnelConnected = connected
        let triggers: [TunnelTrigger]
        do {
            triggers = try tunnelTriggers()
        } catch {
            PSLog.error(PSLog.helper, "The VPN triggers could not be read: \(error.localizedDescription). "
                        + "Network bindings decide the profile until they can be read.")
            return true
        }
        let winner = TunnelTrigger.winner(triggers, connected: connected)
        let key = winner.map { "\($0.id)>\($0.profile)" } ?? ""
        // Nothing to do when this result is already settled, unless no
        // trigger matches and a gateway was set aside (or a trigger switch
        // was still owed) meanwhile: that still has to be handed back.
        let handBackWaiting = key.isEmpty && (gatewayDeferred || pendingTunnel != nil)
        if settledTriggerKey == key && !gatewayHandBackOwed && !handBackWaiting { return true }
        guard let winner else {
            let triggerHeldIt = !(settledTriggerKey ?? "").isEmpty || gatewayDeferred
                || pendingTunnel != nil || gatewayHandBackOwed
            pendingTunnel = nil
            guard triggerHeldIt, !userOverride else {
                settledTriggerKey = ""
                gatewayDeferred = false
                userOverride = false
                gatewayHandBackOwed = false
                return true
            }
            // Hand the profile back to the gateway seen last, through the
            // gateway path itself, so a failure there is retried like any
            // gateway switch (#269) instead of being swallowed.
            lock.lock()
            let mac = lastObservedGatewayMAC
            lock.unlock()
            settledGatewayMAC = nil
            let handedBack = applyObservedGatewayMAC(mac)
            gatewayHandBackOwed = !handedBack
            if handedBack {
                settledTriggerKey = ""
                gatewayDeferred = false
            }
            return handedBack
        }
        do {
            if winner.profile != store.activeProfileName() {
                let result = try activate(profileName: winner.profile, reason: .tunnel)
                let vpn = winner.service ?? "any VPN"
                PSLog.notice(PSLog.helper, "The profile \(result.notice.activeProfile) is now active because "
                             + "\(vpn) is \(winner.whenConnected ? "connected" : "not connected").")
            }
            settledTriggerKey = key
            pendingTunnel = nil
            userOverride = false
            gatewayHandBackOwed = false
            return true
        } catch {
            let first = pendingTunnel != winner
            pendingTunnel = winner
            if first {
                PSLog.error(PSLog.helper, "Could not switch to the profile \(winner.profile) for a VPN trigger: "
                            + "\(error.localizedDescription). Retrying until it works.")
            }
            return false
        }
    }

    /// True while a VPN trigger switch, or handing the profile back to the
    /// gateway, failed and should be tried again.
    public var tunnelRetryOwed: Bool {
        switchSerial.lock()
        defer { switchSerial.unlock() }
        return pendingTunnel != nil || gatewayHandBackOwed
    }

    /// The trigger whose switch is still owed, for status output.
    public var pendingTunnelSwitch: TunnelTrigger? {
        switchSerial.lock()
        defer { switchSerial.unlock() }
        return pendingTunnel
    }

    /// The settled set of connected VPN services, nil before the first one.
    public var currentTunnelConnected: Set<String>? {
        switchSerial.lock()
        defer { switchSerial.unlock() }
        return tunnelConnected
    }

    /// Consulted before a switch the user asked for (a pick or an undo).
    /// Returns why it is refused, or nil to allow it. The helper sets it when
    /// MDM locks the profile a managed trigger chose.
    public var userSwitchRefusal: (() -> String?)?

    /// Consulted before the user adds or removes a trigger. The helper sets
    /// it when MDM manages the triggers.
    public var triggerEditRefusal: (() -> String?)?

    public func setTunnelTrigger(_ trigger: TunnelTrigger) throws {
        switchSerial.lock()
        defer { switchSerial.unlock() }
        if let refusal = triggerEditRefusal?() { throw ProfileValidationError.managedByOrganization(refusal) }
        _ = try store.setTunnelTrigger(trigger)
        reapplyTunnelStateLocked()
    }

    public func removeTunnelTrigger(id: String) throws {
        switchSerial.lock()
        defer { switchSerial.unlock() }
        if let refusal = triggerEditRefusal?() { throw ProfileValidationError.managedByOrganization(refusal) }
        _ = try store.removeTunnelTrigger(id: id)
        reapplyTunnelStateLocked()
    }

    /// Applies the triggers to the known VPN state again, for when they
    /// changed outside this coordinator (an MDM update).
    public func reapplyTunnelState() {
        switchSerial.lock()
        defer { switchSerial.unlock() }
        reapplyTunnelStateLocked()
    }

    /// A changed trigger list is applied like a new VPN state: only a
    /// different winner switches, so editing an unrelated trigger never
    /// undoes a profile the user picked.
    private func reapplyTunnelStateLocked() {
        guard let connected = tunnelConnected else { return }
        _ = applyObservedTunnelState(connected)
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
