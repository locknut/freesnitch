#!/usr/bin/env bash
# Checks how FreeSnitch decides which VPN tunnels carry this Mac's traffic
# ("own the default route") and when that decision takes effect. Fixtures:
#  - a full-tunnel client that publishes a service with a tunnel interface
#    but no VPN entry, captured from a Mac running Cloudflare WARP (WARP+DoH,
#    MASQUE) connected, disconnected, connecting, and in its DNS-only mode;
#  - synthetic: a split-tunnel VPN, two VPNs at once, an IKEv2 (ipsec)
#    service, a VPN entry with no tunnel up.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-tunnel-status.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# The detector is generic: no client is named in its code paths.
for file in TunnelStatus.swift TunnelMonitor.swift TunnelTrigger.swift; do
  if grep -Eiq 'warp|cloudflare|tailscale|wireguard' "$ROOT/Sources/Shared/$file"; then
    echo "tunnel status verification: FAIL: $file names a VPN client" >&2
    exit 1
  fi
done
echo "tunnel status verification: PASS: no VPN client is named in the detector or triggers"

cat > "$TMP/verify.swift" <<'SWIFT'
import Foundation

@main
struct Verify {
    static var failures = 0

    static func check(_ name: String, _ condition: Bool) {
        print("tunnel status harness: \(condition ? "PASS" : "FAIL"): \(name)")
        if !condition { failures += 1 }
    }

    static let ethernet = "AEB8D22C-4DD1-481F-9531-A5FEA222FE51"
    static let warp = "CloudflareWARP"
    static let warpBase = "State:/Network/Service/CloudflareWARP"
    static let corp = "5F1D7C2A-0000-4000-8000-00000000C0DE"
    static let ikev2 = "9A8B7C6D-0000-4000-8000-0000000001E2"

    static func physical() -> [String: Any] {
        [
            "State:/Network/Service/\(ethernet)/IPv4": ["InterfaceName": "en0", "Addresses": ["192.168.96.20"], "Router": "192.168.96.1"],
            "Setup:/Network/Service/\(ethernet)": ["UserDefinedName": "Ethernet"],
        ]
    }

    /// Captured with WARP connected.
    static func warpStore() -> [String: Any] {
        var store = physical()
        store["\(warpBase)/IPv4"] = ["Addresses": ["100.96.0.7"], "InterfaceName": "utun0", "Router": "100.96.0.7", "ServerAddress": "127.0.0.1"]
        store["\(warpBase)/IPv6"] = ["Addresses": ["2606:4700:cf1:1000::3"], "InterfaceName": "utun0"]
        store["\(warpBase)/DNS"] = ["ServerAddresses": ["127.0.2.2", "127.0.2.3"]]
        return store
    }

    static let en0 = TunnelInterfaceState(isUp: true, addresses: ["192.168.96.20", "fe80::1%en0"])
    static let utun0 = TunnelInterfaceState(isUp: true, addresses: ["100.96.0.7", "fe80::588a:ec2f:a907:b0ee%utun0", "2606:4700:cf1:1000::3"])
    /// iCloud Private Relay and similar: link-local only, no service entry.
    static let appleUtun = TunnelInterfaceState(isUp: true, addresses: ["fe80::1%utun1"])

    static func connected() -> TunnelEnvironment {
        TunnelEnvironment(store: warpStore(), interfaces: ["en0": en0, "utun0": utun0, "utun1": appleUtun],
                          ipv4ProbeRoute: "utun0", ipv6ProbeRoute: "utun0")
    }

    static func main() {
        // 1. The captured full-tunnel client.
        let up = TunnelStatus.evaluate(connected())
        check("a service with a tunnel interface and no VPN entry is a tunnel service",
              up.services == [TunnelService(id: warp, name: nil)])
        check("the service id names it when it set no name", up.services.first?.displayName == "CloudflareWARP")
        check("connected: it owns the default route although PrimaryInterface stays en0", up.connected == [warp])
        check("the physical service is not a tunnel service", !up.services.contains { $0.id == ethernet })
        var withSystemTunnel = connected()
        withSystemTunnel.store["State:/Network/Service/4DAA5319-454E-423E-92BE-08397A803896/IPv6"] =
            ["Addresses": ["fe80::fa3c:ff39:8a64:888e%utun1"], "InterfaceName": "utun1", "Router": "fe80::"]
        check("a link-local-only system tunnel service (as macOS publishes) is not a VPN",
              TunnelStatus.evaluate(withSystemTunnel).services.map(\.id) == [warp])

        let disconnected = TunnelEnvironment(store: physical(), interfaces: ["en0": en0, "utun1": appleUtun],
                                             ipv4ProbeRoute: "en0", ipv6ProbeRoute: nil)
        let down = TunnelStatus.evaluate(disconnected)
        check("disconnected: no tunnel service at all", down.services.isEmpty && down.connected.isEmpty)
        check("DNS-only mode (client reports connected, no tunnel) reads the same", !down.anyConnected)

        var connectingStore = warpStore()
        connectingStore[VPNStatus.globalDNSKey] = ["ServerAddresses": ["1.1.1.1"]]
        let connecting = TunnelEnvironment(store: connectingStore, interfaces: ["en0": en0, "utun0": utun0],
                                           ipv4ProbeRoute: "utun0", ipv6ProbeRoute: "utun0")
        check("connecting already owns the route (the debouncer holds it back)", TunnelStatus.evaluate(connecting).connected == [warp])

        // 2. Each condition on its own.
        var stale = connected(); stale.interfaces["utun0"] = nil
        check("keys left behind without the interface: not connected",
              TunnelStatus.evaluate(stale).reasons[warp] == .interfaceMissing("utun0"))
        var downIf = connected(); downIf.interfaces["utun0"] = TunnelInterfaceState(isUp: false, addresses: ["100.96.0.7"])
        check("an interface that is not up: not connected", TunnelStatus.evaluate(downIf).reasons[warp] == .interfaceDown("utun0"))
        var linkLocal = connected(); linkLocal.interfaces["utun0"] = TunnelInterfaceState(isUp: true, addresses: ["fe80::1%utun0"])
        check("only a link-local address: not connected", TunnelStatus.evaluate(linkLocal).reasons[warp] == .noAddress("utun0"))
        var v6Leak = connected(); v6Leak.ipv6ProbeRoute = "en0"
        check("IPv6 default traffic around the tunnel: not connected",
              TunnelStatus.evaluate(v6Leak).reasons[warp] == .notDefaultRoute(family: .ipv6, interface: "en0"))
        var noV6 = connected(); noV6.ipv6ProbeRoute = nil
        check("no IPv6 route at all is fine", TunnelStatus.evaluate(noV6).connected == [warp])
        var noV4 = connected(); noV4.ipv4ProbeRoute = nil
        check("no IPv4 route: not connected", TunnelStatus.evaluate(noV4).reasons[warp] == .notDefaultRoute(family: .ipv4, interface: nil))
        var unreadable = connected(); unreadable.readFailure = "IPv4 route: no answer"
        let failed = TunnelStatus.evaluate(unreadable)
        check("an unreadable state connects nothing", failed.connected.isEmpty && failed.failure != nil)

        // 3. A split-tunnel VPN routes some networks only: it never owns the
        //    default route, so it is present but not connected.
        var splitStore = physical()
        splitStore["State:/Network/Service/\(corp)/VPN"] = ["Status": 1]
        splitStore["State:/Network/Service/\(corp)/IPv4"] = ["InterfaceName": "utun5", "Addresses": ["10.8.0.2"]]
        splitStore["Setup:/Network/Service/\(corp)"] = ["UserDefinedName": "Corp"]
        let split = TunnelStatus.evaluate(TunnelEnvironment(
            store: splitStore, interfaces: ["en0": en0, "utun5": TunnelInterfaceState(isUp: true, addresses: ["10.8.0.2"])],
            ipv4ProbeRoute: "en0", ipv6ProbeRoute: nil))
        check("a split-tunnel VPN is listed by its name", split.services == [TunnelService(id: corp, name: "Corp")])
        check("but is not connected for full-tunnel purposes",
              split.connected.isEmpty && split.reasons[corp] == .notDefaultRoute(family: .ipv4, interface: "en0"))

        // 4. Two VPNs at once: a full tunnel and a split one.
        var both = warpStore()
        for (key, value) in splitStore where key.contains(corp) { both[key] = value }
        let two = TunnelStatus.evaluate(TunnelEnvironment(
            store: both, interfaces: ["en0": en0, "utun0": utun0, "utun5": TunnelInterfaceState(isUp: true, addresses: ["10.8.0.2"])],
            ipv4ProbeRoute: "utun0", ipv6ProbeRoute: "utun0"))
        check("both are listed, in id order", two.services.map(\.id) == [corp, warp].sorted())
        check("only the one that owns the default route is connected", two.connected == [warp])

        // 5. IKEv2 (ipsec interface) full tunnel, and a VPN entry with no tunnel up.
        var ikeStore = physical()
        ikeStore["State:/Network/Service/\(ikev2)/VPN"] = ["Status": 1]
        ikeStore["State:/Network/Service/\(ikev2)/IPv4"] = ["InterfaceName": "ipsec0", "Addresses": ["172.16.4.9"]]
        ikeStore["Setup:/Network/Service/\(ikev2)"] = ["UserDefinedName": "Head office"]
        let ike = TunnelStatus.evaluate(TunnelEnvironment(
            store: ikeStore, interfaces: ["en0": en0, "ipsec0": TunnelInterfaceState(isUp: true, addresses: ["172.16.4.9"])],
            ipv4ProbeRoute: "ipsec0", ipv6ProbeRoute: nil))
        check("an IKEv2 full tunnel is connected", ike.connected == [ikev2])
        var idle = physical()
        idle["State:/Network/Service/\(ikev2)/VPN"] = ["Status": 0]
        idle["Setup:/Network/Service/\(ikev2)"] = ["UserDefinedName": "Head office"]
        let idleReading = TunnelStatus.evaluate(TunnelEnvironment(store: idle, interfaces: ["en0": en0],
                                                                  ipv4ProbeRoute: "en0", ipv6ProbeRoute: nil))
        check("a configured VPN that is not up is listed but not connected",
              idleReading.services.map(\.id) == [ikev2] && idleReading.connected.isEmpty)
        check("tunnel interface names are recognised",
              TunnelStatus.isTunnelInterface("utun12") && TunnelStatus.isTunnelInterface("ipsec0")
              && TunnelStatus.isTunnelInterface("ppp0") && !TunnelStatus.isTunnelInterface("en0")
              && !TunnelStatus.isTunnelInterface("utunnel"))

        // 6. Debouncing the connected set: removal at once, joining after a hold.
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        func reading(_ ids: Set<String>) -> TunnelReading { TunnelReading(services: [], connected: ids) }
        var d = TunnelSetDebouncer(upHold: 3, upReadings: 2)
        check("starts with nothing", d.connected.isEmpty && d.observe(reading([]), at: t0) == nil)
        check("a first reading does not join", d.observe(reading([warp]), at: t0) == nil && d.nextDeadline == t0.addingTimeInterval(3))
        check("a second inside the hold does not join", d.observe(reading([warp]), at: t0.addingTimeInterval(1)) == nil)
        check("joins once held", d.observe(reading([warp]), at: t0.addingTimeInterval(3)) == [warp])
        check("a second VPN waits on its own hold", d.observe(reading([warp, corp]), at: t0.addingTimeInterval(4)) == nil)
        check("one leaving takes effect at once", d.observe(reading([corp]), at: t0.addingTimeInterval(4.5)) == [])
        check("the other's hold continues", d.observe(reading([corp]), at: t0.addingTimeInterval(7)) == [corp])
        check("a failed read empties the set at once",
              d.observe(TunnelReading(services: [], connected: [corp], failure: "x"), at: t0.addingTimeInterval(8)) == [])
        var single = TunnelSetDebouncer(upHold: 3, upReadings: 2)
        _ = single.observe(reading([warp]), at: t0)
        check("one reading is never enough however long ago", single.observe(reading([warp]), at: t0.addingTimeInterval(60)) == [warp])

        // 7. The monitor's first report.
        final class Replay: TunnelEnvironmentReading, @unchecked Sendable {
            var next: TunnelEnvironment
            init(_ env: TunnelEnvironment) { next = env }
            func read(probe: TunnelProbe) -> TunnelEnvironment { next }
        }
        final class Clock: @unchecked Sendable { var now: Date; init(_ d: Date) { now = d } }
        let clock = Clock(t0)
        let replay = Replay(connected())
        let monitor = TunnelMonitor(reader: replay, pollInterval: 3600, now: { clock.now })
        var reports: [Set<String>] = []
        monitor.onChange = { reports.append($0.connected) }
        monitor.evaluate()
        check("a tunnel up at start reports nothing during its hold", reports.isEmpty && monitor.currentState == nil)
        clock.now = t0.addingTimeInterval(3.2)
        monitor.evaluate()
        check("and reports it once held", reports == [[warp]] && monitor.currentState?.services.map(\.id) == [warp])
        replay.next = disconnected
        clock.now = t0.addingTimeInterval(10)
        monitor.evaluate()
        check("a disconnect is reported at once", reports == [[warp], []])
        monitor.evaluate()
        check("an unchanged state is not reported again", reports.count == 2)
        let downStart = TunnelMonitor(reader: Replay(disconnected), pollInterval: 3600, now: { clock.now })
        var downReports: [Set<String>] = []
        downStart.onChange = { downReports.append($0.connected) }
        downStart.evaluate()
        check("nothing up at start is reported at once", downReports == [[]])

        // 8. Routable addresses and CIDR.
        check("link-local and loopback are not routable",
              !TunnelStatus.isRoutable("fe80::1%utun0") && !TunnelStatus.isRoutable("127.0.0.1")
              && !TunnelStatus.isRoutable("169.254.1.1") && !TunnelStatus.isRoutable("::1"))
        check("CGNAT and global addresses are", TunnelStatus.isRoutable("100.96.0.7") && TunnelStatus.isRoutable("2606:4700:cf1:1000::3"))
        check("CIDR matches at the prefix boundary",
              CIDR.contains("100.96.0.0/12", address: "100.111.255.255") && !CIDR.contains("100.96.0.0/12", address: "100.112.0.1"))

        // 9. The VPN banner lists a tunnel service without a VPN entry, by id.
        let vpns = VPNStatus.connectedVPNs(in: warpStore())
        check("the VPN banner lists it", vpns.count == 1 && vpns.first?.interface == "utun0" && vpns.first?.displayName == "CloudflareWARP")
        check("and a disconnected one is not listed", VPNStatus.connectedVPNs(in: physical()).isEmpty)

        // 10. The live reader works unprivileged on this Mac.
        let live = SystemTunnelEnvironmentReader().read(probe: .standard)
        let liveReading = TunnelStatus.evaluate(live)
        print("tunnel status harness: this Mac: services \(liveReading.services.map(\.displayName)), connected \(liveReading.connected.sorted())")
        check("the live reader reads the store, interfaces and routes without failing", live.readFailure == nil)
        check("the live reader finds a route for the IPv4 probe", live.ipv4ProbeRoute != nil)

        if failures > 0 { print("tunnel status harness: \(failures) FAILURES"); exit(1) }
        print("tunnel status harness: PASS (all checks)")
    }
}
SWIFT

xcrun swiftc -O -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 -parse-as-library \
  -o "$TMP/run" "$ROOT"/Sources/Shared/*.swift "$TMP/verify.swift"
"$TMP/run"
