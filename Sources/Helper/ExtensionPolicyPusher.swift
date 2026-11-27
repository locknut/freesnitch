import Foundation

/// Hands the helper's authoritative policy to the network extension directly,
/// over the same XPC service the app uses, so a policy change made in the
/// helper (a VPN trigger) reaches the filter while no app is running. The app
/// keeps relaying policy as before; the extension orders both by (epoch,
/// generation).
///
/// It sends the policy on every change. Between changes it only asks the
/// extension which policy it holds (a small status reply) every
/// `checkInterval`, and sends the policy only when that differs from the
/// helper's, as after an extension restart. A peer that refuses the helper
/// (an extension too old to know it) is retried with a growing delay, so it
/// does not log a refusal every few seconds.
///
/// Only active while `isEnabled` says so: without a helper-driven feature
/// turned on, the helper never connects to the extension.
final class ExtensionPolicyPusher: @unchecked Sendable {
    static let checkInterval: TimeInterval = 15
    static let maximumBackoff: TimeInterval = 600

    typealias PolicyIdentity = (epoch: UInt64, generation: UInt64)

    private let queue = DispatchQueue(label: "io.isaaclins.freesnitch.extension-push", qos: .userInitiated)
    private let snapshot: () throws -> Data
    private let current: () -> PolicyIdentity?
    private let isEnabled: () -> Bool
    private var connection: NSXPCConnection?
    private var timer: DispatchSourceTimer?
    private var lastProblem: String?
    private var failures = 0
    private var notBefore = Date.distantPast

    /// `snapshot` returns the encoded authoritative snapshot, or throws when
    /// the policy cannot be read in full (nothing is sent then). `current`
    /// names the policy that snapshot would carry, without building it.
    init(snapshot: @escaping () throws -> Data,
         current: @escaping () -> PolicyIdentity?,
         isEnabled: @escaping () -> Bool) {
        self.snapshot = snapshot
        self.current = current
        self.isEnabled = isEnabled
    }

    func start() {
        queue.async { [self] in
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now() + 2, repeating: Self.checkInterval, leeway: .seconds(2))
            timer.setEventHandler { [weak self] in self?.checkLocked() }
            timer.resume()
            self.timer = timer
        }
    }

    /// Sends the current policy now, if enabled. Called on every change.
    func push() {
        queue.async { [weak self] in
            guard let self, self.enabledLocked(), Date() >= self.notBefore else { return }
            self.sendLocked()
        }
    }

    private func enabledLocked() -> Bool {
        guard isEnabled() else {
            connection?.invalidate()
            connection = nil
            return false
        }
        return true
    }

    /// Asks which policy the extension holds and sends ours only if it
    /// differs.
    private func checkLocked() {
        guard enabledLocked(), Date() >= notBefore else { return }
        guard let proxy = proxyLocked() else { return }
        proxy.register { [weak self] _, response in
            let status = try? SharedRuleBridge.decodeStatus(response)
            self?.queue.async {
                guard let self else { return }
                self.noteSuccessLocked()
                guard let ours = self.current() else { return }
                if let status, status.isReady, status.epoch == ours.epoch, status.generation == ours.generation { return }
                self.sendLocked()
            }
        }
    }

    private func sendLocked() {
        let data: Data
        do { data = try snapshot() } catch {
            note("the policy could not be read, so none was sent: \(error.localizedDescription)")
            return
        }
        guard let proxy = proxyLocked() else { return }
        proxy.updateSnapshot(snapshotJSON: data) { [weak self] response in
            let status = try? SharedRuleBridge.decodeStatus(response)
            self?.queue.async {
                guard let self else { return }
                self.noteSuccessLocked()
                if let status, status.isReady {
                    self.clearProblem()
                } else if status?.rejection == .olderGeneration {
                    // The app delivered a newer policy meanwhile; the next
                    // check compares again.
                    return
                } else {
                    self.note("the extension did not accept the policy: \(status?.message ?? "unreadable acknowledgement")")
                }
            }
        }
    }

    private func proxyLocked() -> ProviderCommunication? {
        let conn = connection ?? makeConnection()
        guard let proxy = conn.remoteObjectProxyWithErrorHandler({ [weak self] error in
            // Usually: no extension running (filter off, not installed), or
            // an extension that does not accept the helper yet.
            self?.queue.async { self?.failedLocked(conn, "not reachable: \(error.localizedDescription)") }
        }) as? ProviderCommunication else {
            note("the XPC proxy could not be created")
            return nil
        }
        return proxy
    }

    private func makeConnection() -> NSXPCConnection {
        let conn = NSXPCConnection(machServiceName: AppConstants.ipcMachServiceName, options: [.privileged])
        conn.exportedInterface = NSXPCInterface(with: AppCommunication.self)
        conn.exportedObject = HelperAppCommunication()
        conn.remoteObjectInterface = NSXPCInterface(with: ProviderCommunication.self)
        conn.invalidationHandler = { [weak self, weak conn] in
            self?.queue.async { self?.dropConnection(conn) }
        }
        conn.interruptionHandler = { [weak self, weak conn] in
            // The extension process went away. Its replacement starts without
            // a live policy; check it as soon as it can answer.
            self?.queue.asyncAfter(deadline: .now() + 1) {
                self?.dropConnection(conn)
                self?.checkLocked()
            }
        }
        conn.resume()
        connection = conn
        return conn
    }

    private func dropConnection(_ conn: NSXPCConnection?) {
        if let conn, conn === connection {
            connection = nil
            conn.invalidate()
        }
    }

    private func failedLocked(_ conn: NSXPCConnection, _ problem: String) {
        dropConnection(conn)
        failures += 1
        let delay = min(Self.maximumBackoff, Self.checkInterval * pow(2, Double(min(failures - 1, 10))))
        notBefore = Date().addingTimeInterval(delay)
        note(problem + " (next attempt in \(Int(delay)) s)")
    }

    private func noteSuccessLocked() {
        failures = 0
        notBefore = .distantPast
    }

    /// Logged once per distinct problem, not on every attempt.
    private func note(_ problem: String) {
        let key = problem.components(separatedBy: " (next attempt").first ?? problem
        guard key != lastProblem else { return }
        lastProblem = key
        PSLog.info(PSLog.helper, "Policy delivery to the network extension: \(problem)")
    }

    private func clearProblem() {
        if lastProblem != nil {
            PSLog.info(PSLog.helper, "Policy delivery to the network extension works again.")
        }
        lastProblem = nil
    }
}

/// The extension never makes the helper its alert connection, so this is
/// never asked. If it ever were, the answer is the extension's own default
/// for an unanswered flow.
private final class HelperAppCommunication: NSObject, AppCommunication {
    func promptUser(flowJSON: Data, responseHandler: @escaping (Bool, Bool) -> Void) {
        responseHandler(true, false)
    }
}
