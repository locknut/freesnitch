# VPN triggers, managed settings and fail-closed

Three opt-in features for Macs that are managed or that live on a VPN. Each is off until you turn it on, and FreeSnitch behaves exactly as before without it.

## VPN triggers

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

## Managed settings (MDM)

The helper reads `/Library/Managed Preferences/io.isaaclins.freesnitch.plist`, which a configuration profile for the preference domain `io.isaaclins.freesnitch` writes. Keys:

| Key | Type | Meaning |
|---|---|---|
| `Profiles` | array of `{Name, Mode}` | Profiles to create (Mode: `alert`, `silentAllow`, `silentDeny`) |
| `Rules` | array of entries | Rules above every user rule; see the entry keys below. `Action` (`allow` / `deny`, default allow), `Profile` (default Always) |
| `NetworkBindings` | array of `{GatewayMAC, Profile}` | Network bindings |
| `VPNTriggers` | array of `{Profile, When, Service?}` | `When` is `connected` or `disconnected`; leave out `Service` for any VPN |
| `LockSettings` | bool | A profile chosen by a managed trigger cannot be overridden by hand |
| `HelperDeliversPolicy` | bool | The helper delivers policy to the extension even without triggers |

**Precedence and locking.**

- **Managed values come first.** Managed rules, triggers and profiles take precedence over the user's own.
- **Managed values can't be edited in the app.** The app shows them as managed and refuses to change or delete them.
- **All or nothing.** The file is read all or nothing. One invalid entry refuses the whole file, and the settings applied before stay in force.

**Rule entry keys.** These are shared with the fail-closed recovery list:

- `Host`: an exact name, or `*.example.com` for a domain and its subdomains.
- `Address`: an IP address or a CIDR range.
- `Port`: a port number.
- `BundleID` with `TeamID`: an app by its signed identity. An allow rule needs both, because a bundle id alone is only a claim.
- `Path`: an absolute path to an app or executable.
- `Comment`: free text.

## Fail-closed

FreeSnitch fails open while its network extension holds no policy, for example just after install or before the helper or app has delivered one. A managed fleet can turn that around with a `com.apple.webcontent-filter` payload. Put `io.isaaclins.freesnitch.failClosed` in its `VendorConfig` dictionary:

```xml
<key>io.isaaclins.freesnitch.failClosed</key>
<dict>
  <key>Enabled</key><true/>
  <key>RecoveryEntries</key>
  <array>
    <dict><key>Host</key><string>*.example-remote-support.com</string></dict>
    <dict><key>BundleID</key><string>com.example.Support</string><key>TeamID</key><string>ABCDE12345</string></dict>
  </array>
</dict>
```

**What gets through while no policy is in force:**

- **Built in:** Apple's MDM client, push, time, revocation and captive portal services.
- **Your recovery entries.**
- **DNS** to the configured resolvers.

Everything else is denied. A real policy replaces the recovery policy as soon as one arrives. A malformed value keeps fail-closed on, with the built-in list only.

**Fail-closed only covers "no policy".** To restrict traffic while a VPN is down, use a VPN trigger: activate a strict profile, with the same allow rules, when the VPN is not connected.
