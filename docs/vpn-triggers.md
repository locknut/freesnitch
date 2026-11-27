# VPN triggers

In **Profiles**, under a profile's networks, choose a condition and press **Add**:

> Activate this profile when **any VPN is connected** / **no VPN is connected** / **<VPN service> is connected** / **<VPN service> is not connected**

This works like "use this here". A network binding activates a profile on a network; a VPN trigger activates one while a VPN tunnel does, or does not, carry this Mac's traffic. Each condition selects one profile. A trigger is renamed and deleted together with its profile.

**What "connected" means.** The privileged helper watches the system's network state (the SystemConfiguration dynamic store) and asks the kernel where traffic would go, never the VPN app. A VPN service counts as connected while it owns the default route, which takes three things:

1. **Its service names an interface.** The service's address entry names a tunnel interface (`utun`, `ipsec`, `ppp`) that has a routable address.
2. **The interface is up.**
3. **Default traffic goes through it.** The kernel routes every IPv4 probe address through that interface: 1.1.1.1, 8.8.8.8 and 208.67.222.222. It must also route every IPv6 probe address that has a route at all: 2606:4700:4700::1111 and 2001:4860:4860::8888.

The route choice is read by connecting an unbound UDP socket, which sends no packets, so no other process can disturb the reading. Some VPN clients publish their tunnel without a VPN entry; they are found too. Services are identified by their service id, never by `utun` number. The list also includes VPNs seen earlier, shown as "not connected", because some clients remove their service when they disconnect.

**Tunnels with no service.** A tunnel interface that passes all three conditions but belongs to no service counts for "any VPN" and "no VPN" only. Such tunnels are typically set up by command-line tools such as `wg-quick` or `openvpn`. An idle tunnel, or one without an address, does not count.

**Split tunnels.** A split-tunnel VPN, which routes only some networks, never counts as connected, even when one probe address happens to fall inside its routes. These triggers answer "does general traffic go through a tunnel?", not "is some VPN running?".

**Timing.**

- **Losing a VPN takes effect at once.** Traffic is already going around the tunnel by then.
- **A VPN must hold for about 3 seconds before it counts as connected.** It also needs at least two readings. Tunnels publish their route shortly before they are usable, and they flap while reconnecting.
- **Failed readings keep the last state for at most 2 seconds**, retried every half second. After that, nothing counts as connected.
- **A monotonic clock is used**, so changing the system time never stretches a wait.

**Which trigger wins.** A trigger for a named VPN beats one for any VPN, and a connected condition beats a not-connected one. Two named VPNs connected at once are decided by service id. While a trigger matches, it decides the profile instead of network bindings. A "no VPN is connected" trigger therefore decides the profile whenever no VPN is up.

**When no trigger matches any more**, the network seen last decides, as it would without any VPN. A profile you pick by hand holds until another trigger wins or you join a different network. A failed switch, including handing back to the network's profile, is retried every 5 seconds, and the Profiles screen says so.

**With the app closed.** While any VPN trigger exists, the helper delivers the active policy to the network extension itself on every change. Between changes it asks every 15 seconds which policy the extension holds, and sends its own only when they differ, as after an extension restart.

- **Startup policy:** only policy the app delivers is what the extension remembers for its next start, because only the app saves that policy.
- **No triggers, no watching:** without any trigger, the helper neither watches VPNs nor contacts the extension.
