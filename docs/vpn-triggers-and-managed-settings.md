# VPN triggers, managed settings and fail-closed

Three opt-in features for Macs that are managed or that live on a VPN. Each is off until you turn it on, and FreeSnitch behaves exactly as before without it.

## VPN triggers

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

Everything else is denied. A real policy replaces the recovery policy as soon as one arrives. A malformed value keeps fail-closed on, with the built-in list only. With `MaximumPolicyAge` (seconds, at least 60), a policy that neither the app nor the helper has delivered or confirmed within that time counts as no policy. The helper confirms the policy with a check-in every 15 seconds while it delivers policy.

**Fail-closed only covers "no policy".** To restrict traffic while a VPN is down, use a VPN trigger: activate a strict profile, with the same allow rules, when the VPN is not connected.
