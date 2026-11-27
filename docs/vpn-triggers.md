# VPN triggers

In **Profiles**, under a profile's networks:

> Activate when **[any VPN | a VPN service]** is **[connected | not connected]**

This is a sibling of "use this here". A network binding activates a profile on a network; a VPN trigger activates one while a VPN tunnel does, or does not, carry this Mac's traffic.

**What "connected" means.** The privileged helper watches the system's network state (the dynamic store, `scutil`) and the kernel's routing table, never the VPN app's own status. A VPN service counts as connected while it owns the default route, which takes three things:

1. **Its service names an interface.** The service's address entry names a tunnel interface (`utun`, `ipsec`, `ppp`).
2. **The interface is usable.** It exists, is up, and has a routable address.
3. **Default traffic goes through it.** The kernel's route lookup for a public probe address goes out through that interface. This is checked for IPv4, and for IPv6 when the Mac has an IPv6 route.

Some VPN clients publish their tunnel without a VPN entry, and they are found all the same. Services are identified by their service id, never by the `utun` number, which changes on every connection.

**Timing.**

- **Losing a VPN takes effect at once.** Traffic is already going around the tunnel by then.
- **A VPN must hold for about 3 seconds before it counts as connected.** Tunnels publish their route shortly before they are usable, and they flap while reconnecting.
- **An unreadable state counts as nothing connected.**

**Which trigger wins.** A trigger for a named VPN beats one for any VPN, and a connected condition beats a not-connected one. While a trigger matches, it takes precedence over network bindings. When none matches, network bindings decide.

**Manual picks.** If you pick a profile by hand, it holds until a different trigger wins.

**Limitation: split tunnels.** A split-tunnel VPN, which routes only some networks, never owns the default route, so it never counts as connected. These triggers answer "does general traffic go through a tunnel?", not "is some VPN running?".

**With the app closed.** While any VPN trigger exists, the helper delivers the active policy to the network extension itself, every 15 seconds and on every change. A trigger therefore takes effect even when the FreeSnitch app is not running.

