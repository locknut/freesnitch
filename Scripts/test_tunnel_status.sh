#!/usr/bin/env bash
# Checks how FreeSnitch decides whether a full tunnel (Cloudflare WARP) is
# carrying this Mac's traffic, and when that decision takes effect. The store
# contents, interface state and route lookups are the ones a Mac with the
# WARP client (WARP+DoH, MASQUE) showed in each state: connected,
# disconnected, connecting, and DNS-only mode.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/freesnitch-tunnel-status.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

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
    static let warpBase = "State:/Network/Service/CloudflareWARP"

    /// The physical service, present in every state.
    static func physical() -> [String: Any] {
        [
            "State:/Network/Service/\(ethernet)/IPv4": ["InterfaceName": "en0", "Addresses": ["192.168.96.20"], "Router": "192.168.96.1"],
            "State:/Network/Global/IPv4": ["PrimaryInterface": "en0", "PrimaryService": ethernet, "Router": "192.168.96.1"],
        ]
    }

    /// WARP connected, as scutil showed it.
    static func connectedStore() -> [String: Any] {
        var store = physical()
        store[warpBase] = [String: Any]()
        store["\(warpBase)/IPv4"] = ["Addresses": ["100.96.0.7"], "InterfaceName": "utun0",
                                     "Router": "100.96.0.7", "ServerAddress": "127.0.0.1"]
        store["\(warpBase)/IPv6"] = ["Addresses": ["2606:4700:cf1:1000::3"], "InterfaceName": "utun0"]
        store["\(warpBase)/DNS"] = ["ServerAddresses": ["127.0.2.2", "127.0.2.3"]]
        store[VPNStatus.globalDNSKey] = ["ServerAddresses": ["127.0.2.2", "127.0.2.3"],
                                         "SearchDomains": ["h1.home.arpa"],
                                         "__CONFIGURATION_ID__": "Default: \(ethernet) 0"]
        return store
    }

    static let interfacesUp: [String: TunnelInterfaceState] = [
        "en0": TunnelInterfaceState(isUp: true, addresses: ["192.168.96.20"]),
        "utun0": TunnelInterfaceState(isUp: true, addresses: ["100.96.0.7", "fe80::588a:ec2f:a907:b0ee%utun0", "2606:4700:cf1:1000::3"]),
        // Apple's own tunnels (iCloud Private Relay and friends).
        "utun1": TunnelInterfaceState(isUp: true, addresses: ["fe80::1%utun1"]),
    ]
    static let interfacesWithoutWARP: [String: TunnelInterfaceState] = [
        "en0": TunnelInterfaceState(isUp: true, addresses: ["192.168.96.20"]),
        "utun1": TunnelInterfaceState(isUp: true, addresses: ["fe80::1%utun1"]),
    ]

    static func connected() -> TunnelEnvironment {
        TunnelEnvironment(store: connectedStore(), interfaces: interfacesUp, ipv4ProbeRoute: "utun0", ipv6ProbeRoute: "utun0")
    }

    static func main() {
        // 1. Connected: all four conditions hold, although PrimaryInterface
        //    is still en0 (WARP adds a scoped default route instead).
        check("connected WARP reads up on its tunnel interface",
              TunnelStatus.evaluate(connected()) == .up(interface: "utun0"))

        // 2. Disconnected: the service keys and utun0 are gone, traffic uses en0.
        let disconnected = TunnelEnvironment(store: physical(), interfaces: interfacesWithoutWARP,
                                             ipv4ProbeRoute: "en0", ipv6ProbeRoute: nil)
        check("disconnected WARP reads down: no service", TunnelStatus.evaluate(disconnected) == .down(.noService))

        // 3. DNS-only mode: warp-cli says Connected, but there is no tunnel.
        var dnsOnlyStore = physical()
        dnsOnlyStore[VPNStatus.globalDNSKey] = ["ServerAddresses": ["127.0.2.2", "127.0.2.3"], "__CONFIGURATION_ID__": "Default: \(ethernet) 0"]
        let dnsOnly = TunnelEnvironment(store: dnsOnlyStore, interfaces: interfacesWithoutWARP,
                                        ipv4ProbeRoute: "en0", ipv6ProbeRoute: nil)
        check("DNS-only mode reads down although the client says connected", TunnelStatus.evaluate(dnsOnly) == .down(.noService))

        // 4. Connecting: the keys, interface and route appear about a second
        //    before the client reports Connected (global DNS not switched yet).
        var connectingStore = connectedStore()
        connectingStore[VPNStatus.globalDNSKey] = ["ServerAddresses": ["1.1.1.1"], "__CONFIGURATION_ID__": "Default: \(ethernet) 0"]
        let connecting = TunnelEnvironment(store: connectingStore, interfaces: interfacesUp, ipv4ProbeRoute: "utun0", ipv6ProbeRoute: "utun0")
        check("connecting already reads up (the debouncer holds it back)", TunnelStatus.evaluate(connecting).isUp)

        // 5. Each condition on its own.
        var stale = connected()
        stale.interfaces["utun0"] = nil
        check("keys left behind without the interface read down",
              TunnelStatus.evaluate(stale) == .down(.interfaceMissing("utun0")))
        var downIf = connected()
        downIf.interfaces["utun0"] = TunnelInterfaceState(isUp: false, addresses: ["100.96.0.7"])
        check("an interface that is not up reads down", TunnelStatus.evaluate(downIf) == .down(.interfaceDown("utun0")))
        var reused = connected()
        reused.interfaces["utun0"] = TunnelInterfaceState(isUp: true, addresses: ["10.8.0.2", "fe80::1%utun0"])
        check("a utun without a WARP address reads down", TunnelStatus.evaluate(reused) == .down(.noTunnelAddress("utun0")))
        var v6Only = connected()
        v6Only.interfaces["utun0"] = TunnelInterfaceState(isUp: true, addresses: ["2606:4700:cf1:1000::3"])
        check("a WARP IPv6 address alone satisfies the address condition", TunnelStatus.evaluate(v6Only).isUp)
        var bypass = connected()
        bypass.ipv4ProbeRoute = "en0"
        check("IPv4 routed around the tunnel reads down",
              TunnelStatus.evaluate(bypass) == .down(.routedElsewhere(family: .ipv4, interface: "en0")))
        var noRoute = connected()
        noRoute.ipv4ProbeRoute = nil
        check("no IPv4 route at all reads down",
              TunnelStatus.evaluate(noRoute) == .down(.routedElsewhere(family: .ipv4, interface: nil)))
        var v6Leak = connected()
        v6Leak.ipv6ProbeRoute = "en0"
        check("IPv6 routed around the tunnel reads down",
              TunnelStatus.evaluate(v6Leak) == .down(.routedElsewhere(family: .ipv6, interface: "en0")))
        var noV6 = connected()
        noV6.ipv6ProbeRoute = nil
        check("no IPv6 route is fine: nothing can leak over IPv6", TunnelStatus.evaluate(noV6).isUp)
        var unreadable = connected()
        unreadable.readFailure = "IPv4 route: no answer"
        check("an unreadable state is down, never up",
              TunnelStatus.evaluate(unreadable) == .down(.unreadable("IPv4 route: no answer")))
        var onlyIPv6Key = connected()
        onlyIPv6Key.store["\(warpBase)/IPv4"] = nil
        check("the IPv6 service entry alone names the interface", TunnelStatus.evaluate(onlyIPv6Key).isUp)

        // 6. Debouncing: down at once, up only after holding.
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        var debouncer = TunnelStateDebouncer(upHold: 3, upReadings: 2)
        check("starts down", debouncer.isUp == false)
        check("a first down reading changes nothing", debouncer.observe(.down(.noService), at: t0) == nil)
        check("a first up reading is not yet up", debouncer.observe(.up(interface: "utun0"), at: t0) == nil)
        check("a pending up has a deadline at the hold time", debouncer.pendingUpDeadline == t0.addingTimeInterval(3))
        check("a second up reading inside the hold is not yet up",
              debouncer.observe(.up(interface: "utun0"), at: t0.addingTimeInterval(1)) == nil)
        check("up after the hold has passed", debouncer.observe(.up(interface: "utun0"), at: t0.addingTimeInterval(3)) == true)
        check("no deadline once up", debouncer.pendingUpDeadline == nil)
        check("staying up changes nothing", debouncer.observe(.up(interface: "utun0"), at: t0.addingTimeInterval(4)) == nil)
        check("one down reading takes effect at once",
              debouncer.observe(.down(.routedElsewhere(family: .ipv4, interface: "en0")), at: t0.addingTimeInterval(4.1)) == false)
        check("a flap back up restarts the hold",
              debouncer.observe(.up(interface: "utun0"), at: t0.addingTimeInterval(4.5)) == nil)
        check("a down inside the hold cancels it", debouncer.observe(.down(.noService), at: t0.addingTimeInterval(5)) == nil)
        check("an up after the cancelled hold waits again",
              debouncer.observe(.up(interface: "utun0"), at: t0.addingTimeInterval(7.6)) == nil
              && debouncer.observe(.up(interface: "utun0"), at: t0.addingTimeInterval(8)) == nil)
        check("and comes up once its own hold has passed",
              debouncer.observe(.up(interface: "utun0"), at: t0.addingTimeInterval(10.6)) == true)
        var single = TunnelStateDebouncer(upHold: 3, upReadings: 2)
        _ = single.observe(.up(interface: "utun0"), at: t0)
        check("one reading is never enough, however long ago it was",
              single.isUp == false && single.observe(.up(interface: "utun0"), at: t0.addingTimeInterval(60)) == true)

        // 7. The monitor's first report: never a "down" while an up is
        //    still inside its hold, so a helper start doesn't switch twice.
        final class Replay: TunnelEnvironmentReading, @unchecked Sendable {
            var next: TunnelEnvironment
            init(_ env: TunnelEnvironment) { next = env }
            func read(for tunnel: TunnelDefinition) -> TunnelEnvironment { next }
        }
        final class Clock: @unchecked Sendable { var now: Date; init(_ d: Date) { now = d } }
        let clock = Clock(t0)
        let replay = Replay(connected())
        let monitor = TunnelMonitor(reader: replay, pollInterval: 3600, now: { clock.now })
        var reports: [Bool] = []
        monitor.onChange = { state, _ in reports.append(state) }
        monitor.evaluate()
        check("an up tunnel at start reports nothing during its hold", reports.isEmpty && monitor.currentState == nil)
        clock.now = t0.addingTimeInterval(3.2)
        monitor.evaluate()
        check("and reports up once it has held", reports == [true])
        replay.next = disconnected
        clock.now = t0.addingTimeInterval(10)
        monitor.evaluate()
        check("a disconnect is reported at once", reports == [true, false])
        monitor.evaluate()
        check("an unchanged state is not reported again", reports == [true, false])
        let downStart = TunnelMonitor(reader: Replay(disconnected), pollInterval: 3600, now: { clock.now })
        var downReports: [Bool] = []
        downStart.onChange = { state, _ in downReports.append(state) }
        downStart.evaluate()
        check("a down tunnel at start is reported at once", downReports == [false])

        // 8. CIDR matching.
        check("100.96.0.7 is in 100.96.0.0/12", CIDR.contains("100.96.0.0/12", address: "100.96.0.7"))
        check("100.111.255.255 is in 100.96.0.0/12", CIDR.contains("100.96.0.0/12", address: "100.111.255.255"))
        check("100.112.0.1 is not", !CIDR.contains("100.96.0.0/12", address: "100.112.0.1"))
        check("100.64.0.1 (other CGNAT) is not", !CIDR.contains("100.96.0.0/12", address: "100.64.0.1"))
        check("a zoned link-local IPv6 address is not in WARP's range",
              !CIDR.contains("2606:4700:cf1::/48", address: "fe80::588a:ec2f:a907:b0ee%utun0"))
        check("WARP's IPv6 address is", CIDR.contains("2606:4700:cf1::/48", address: "2606:4700:cf1:1000::3"))
        check("an IPv4 prefix never matches an IPv6 address", !CIDR.contains("0.0.0.0/0", address: "::1"))
        check("a malformed prefix matches nothing", !CIDR.contains("100.96.0.0", address: "100.96.0.7"))

        // 9. The VPN banner now sees WARP, which has no VPN entry.
        let vpns = VPNStatus.connectedVPNs(in: connectedStore())
        check("WARP is listed as a connected VPN", vpns.count == 1 && vpns.first?.interface == "utun0")
        check("named Cloudflare WARP", vpns.first?.displayName == "Cloudflare WARP" && vpns.first.map(VPNStatus.isCloudflareWARP) == true)
        check("and it handles every lookup", vpns.first?.handlesAllLookups == true)
        let line = VPNStatus.dnsSummary(vpns, routesThroughProxy: false) ?? ""
        check("the DNS line does not tell the user to turn WARP's DNS off",
              line.hasPrefix("Cloudflare WARP is handling DNS right now") && !line.contains("turn off the VPN's own DNS"))
        check("disconnected WARP is not listed", VPNStatus.connectedVPNs(in: physical()).isEmpty)

        // 10. The live reader works unprivileged on this Mac. Its reading
        //     depends on whether WARP is installed and connected here, so
        //     only the absence of read failures is required.
        let live = SystemTunnelEnvironmentReader().read(for: .cloudflareWARP)
        print("tunnel status harness: this Mac reads \(TunnelStatus.evaluate(live))")
        check("the live reader reads the store, interfaces and routes without failing", live.readFailure == nil)
        check("the live reader finds a route for the IPv4 probe", live.ipv4ProbeRoute != nil)

        if failures > 0 {
            print("tunnel status harness: \(failures) FAILURES")
            exit(1)
        }
        print("tunnel status harness: PASS (all checks)")
    }
}
SWIFT

xcrun swiftc -O -sdk "$(xcrun --show-sdk-path)" -target arm64-apple-macos13.0 -parse-as-library \
  -o "$TMP/run" "$ROOT"/Sources/Shared/*.swift "$TMP/verify.swift"
"$TMP/run"
