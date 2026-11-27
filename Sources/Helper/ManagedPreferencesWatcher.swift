import CryptoKit
import Foundation

/// Watches the MDM-managed preference file and reports each new, valid
/// version. macOS replaces the file when a profile is installed, changed or
/// removed; the directory is watched for that, and a slow poll covers a
/// missed event (or a directory that does not exist until the first profile).
final class ManagedPreferencesWatcher: @unchecked Sendable {
    static let pollInterval: TimeInterval = 60

    private let path: String
    private let queue = DispatchQueue(label: "io.isaaclins.freesnitch.managed-preferences", qos: .utility)
    private var directorySource: DispatchSourceFileSystemObject?
    private var timer: DispatchSourceTimer?
    private var lastDigest: String?
    private var lastProblem: String?

    /// Called on the watcher's queue with the managed preferences now in
    /// force, `.none` once the file is gone. Not called for an unchanged file,
    /// nor for one that cannot be parsed (what was applied last stays).
    var onChange: ((ManagedPreferences) -> Void)?

    init(path: String = ManagedPreferences.defaultPath) {
        self.path = path
    }

    func start() {
        queue.async { [self] in
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now() + Self.pollInterval, repeating: Self.pollInterval, leeway: .seconds(5))
            timer.setEventHandler { [weak self] in self?.check() }
            timer.resume()
            self.timer = timer
            watchDirectory()
            check()
        }
    }

    /// Reads now; for the helper's start and for tests.
    func checkNow() { queue.sync { check() } }

    private func watchDirectory() {
        guard directorySource == nil else { return }
        let directory = (path as NSString).deletingLastPathComponent
        let fd = open(directory, O_EVTONLY)
        guard fd >= 0 else { return }   // not there yet: the poll covers it
        let source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd,
                                                               eventMask: [.write, .rename, .delete, .link],
                                                               queue: queue)
        source.setEventHandler { [weak self] in
            // Profiles are written in more than one step; read once it settles.
            self?.queue.asyncAfter(deadline: .now() + 1) { self?.check() }
        }
        source.setCancelHandler { close(fd) }
        source.resume()
        directorySource = source
    }

    private func check() {
        watchDirectory()
        let data = FileManager.default.contents(atPath: path)
        let digest = data.map { SHA256.hash(data: $0).map { String(format: "%02x", $0) }.joined() } ?? "absent"
        guard digest != lastDigest else { return }
        do {
            let prefs = try ManagedPreferences.read(path: path) ?? .none
            lastDigest = digest
            lastProblem = nil
            PSLog.info(PSLog.helper, data == nil ? "No managed preferences are installed."
                       : "Managed preferences loaded: \(prefs.rules.count) rules, \(prefs.profiles.count) profiles, "
                       + "VPN triggers \(prefs.tunnelTriggers.map { "\($0.count) managed" } ?? "not managed"), "
                       + "settings \(prefs.lockSettings ? "locked" : "not locked").")
            onChange?(prefs)
        } catch {
            let problem = error.localizedDescription
            if problem != lastProblem {
                lastProblem = problem
                PSLog.error(PSLog.helper, "\(problem). The managed settings applied before stay in force.")
            }
        }
    }
}
