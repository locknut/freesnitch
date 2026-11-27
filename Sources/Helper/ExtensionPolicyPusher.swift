import Foundation

/// Hands the helper's authoritative policy to the network extension directly,
/// over the same XPC service the app uses, so a policy change made in the
/// helper (a tunnel switch, an MDM update) reaches the filter while no app is
/// running. The app keeps relaying policy as before; the extension orders
/// both by (epoch, generation), so whichever arrives second is idempotent or
/// ignored.
///
/// Only active while `isEnabled` says so: without a helper-driven feature
/// turned on, nothing changes from how FreeSnitch delivered policy before.
final class ExtensionPolicyPusher: @unchecked Sendable {
    /// Re-sent this often while enabled, so an extension that restarted (and
    /// came back with no live policy) has the current one within this time.
    static let resendInterval: TimeInterval = 15

    private let queue = DispatchQueue(label: "io.isaaclins.freesnitch.extension-push", qos: .userInitiated)
    private let snapshot: () throws -> Data
    private let isEnabled: () -> Bool
    private var connection: NSXPCConnection?
    private var timer: DispatchSourceTimer?
    private var lastProblem: String?

    /// `snapshot` returns the encoded authoritative snapshot, or throws when
    /// the policy cannot be read in full (nothing is sent then).
    init(snapshot: @escaping () throws -> Data, isEnabled: @escaping () -> Bool) {
        self.snapshot = snapshot
        self.isEnabled = isEnabled
    }

    func start() {
        queue.async { [self] in
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now() + 2, repeating: Self.resendInterval, leeway: .seconds(2))
            timer.setEventHandler { [weak self] in self?.pushLocked() }
            timer.resume()
            self.timer = timer
        }
    }

    /// Sends the current policy now, if enabled.
    func push() {
        queue.async { [weak self] in self?.pushLocked() }
    }

    private func pushLocked() {
        guard isEnabled() else {
            connection?.invalidate()
            connection = nil
            return
        }
        let data: Data
        do { data = try snapshot() } catch {
            note("the policy could not be read, so none was sent: \(error.localizedDescription)")
            return
        }
        let conn = connection ?? makeConnection()
        guard let proxy = conn.remoteObjectProxyWithErrorHandler({ [weak self] error in
            // Usually: no extension running (filter off, or not installed).
            self?.queue.async { self?.dropConnection(conn, "not reachable: \(error.localizedDescription)") }
        }) as? ProviderCommunication else {
            note("the XPC proxy could not be created")
            return
        }
        proxy.updateSnapshot(snapshotJSON: data) { [weak self] response in
            let status = try? SharedRuleBridge.decodeStatus(response)
            self?.queue.async {
                if let status, status.isReady {
                    self?.clearProblem()
                } else {
                    self?.note("the extension did not accept the policy: \(status?.message ?? "unreadable acknowledgement")")
                }
            }
        }
    }

    private func makeConnection() -> NSXPCConnection {
        let conn = NSXPCConnection(machServiceName: AppConstants.ipcMachServiceName, options: [.privileged])
        conn.exportedInterface = NSXPCInterface(with: AppCommunication.self)
        conn.exportedObject = HelperAppCommunication()
        conn.remoteObjectInterface = NSXPCInterface(with: ProviderCommunication.self)
        conn.invalidationHandler = { [weak self, weak conn] in
            self?.queue.async { self?.dropConnection(conn, nil) }
        }
        conn.interruptionHandler = { [weak self, weak conn] in
            // The extension process went away. Its replacement starts with no
            // live policy, so it gets one as soon as it answers.
            self?.queue.asyncAfter(deadline: .now() + 1) {
                self?.dropConnection(conn, nil)
                self?.pushLocked()
            }
        }
        conn.resume()
        connection = conn
        return conn
    }

    private func dropConnection(_ conn: NSXPCConnection?, _ problem: String?) {
        if let conn, conn === connection {
            connection = nil
            conn.invalidate()
        }
        if let problem { note(problem) }
    }

    /// Logged once per distinct problem, not on every resend.
    private func note(_ problem: String) {
        guard problem != lastProblem else { return }
        lastProblem = problem
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
