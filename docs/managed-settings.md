# Managed settings (MDM)

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

