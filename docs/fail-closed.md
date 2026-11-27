# Fail-closed (opt-in)

FreeSnitch fails open while its network extension holds no policy: just after install, before the app or helper has delivered one, or after a saved policy was refused. That keeps a missing app from becoming a network outage. A managed fleet may need the opposite.

## Turning it on

Add `io.isaaclins.freesnitch.failClosed` to the `VendorConfig` dictionary of the `com.apple.webcontent-filter` payload that enables FreeSnitch's filter. The extension then reads it at its first flow, before any app or helper is running:

```xml
<key>io.isaaclins.freesnitch.failClosed</key>
<dict>
  <key>Enabled</key><true/>
  <key>MaximumPolicyAge</key><integer>120</integer>   <!-- optional, seconds, at least 60 -->
  <key>RecoveryEntries</key>
  <array>
    <dict><key>Host</key><string>*.example-remote-support.com</string></dict>
    <dict><key>Port</key><integer>5938</integer></dict>
    <dict><key>Address</key><string>198.51.100.0/24</string></dict>
    <dict><key>BundleID</key><string>com.example.Support</string><key>TeamID</key><string>ABCDE12345</string></dict>
    <dict><key>Path</key><string>/Applications/Example Support.app</string></dict>
  </array>
</dict>
```

## What gets through while no policy is in force

- **Built in:** Apple's MDM client, push (APNs), time, certificate revocation, the captive portal check, and the Captive Network Assistant. These are pinned to their system paths, which SIP protects.
- **Your recovery entries.** The fields of one entry must all match. An allow entry by `BundleID` needs the `TeamID` that signs the app, because a bundle id alone is only a claim.
- **DNS** to the configured resolvers, so recovery hosts resolve.
- **The existing exemptions:** DHCP, loopback, and FreeSnitch's own traffic, as always.

Everything else is denied with Silent Deny, which never asks.

**Leaving the recovery policy.** A real policy replaces it as soon as one arrives.

**Malformed values.** A malformed value keeps fail-closed on, with the built-in list only. Entries that would match everything, a bundle id without its team, and relative paths are refused.

## MaximumPolicyAge

With `MaximumPolicyAge`, a policy that has not been delivered again within that many seconds counts as no policy. That's useful where something resends the policy regularly. Without a regular resend, leave it unset: the app sends policy only when it changes, so the policy would expire.

## What fail-closed does not change

These fail-open paths are unchanged, by design:

- **Unanswered asks are allowed.** A flow in Alert mode with no app connected, or one whose alert times out after 60 s, is allowed. Use Silent Allow or Silent Deny profiles on unattended Macs.
- **Unattributable flows are allowed.** Non-socket flows, flows from FreeSnitch itself, and loopback are allowed.
- **A stopped filter enforces nothing.** If the filter itself is turned off, nothing is enforced. Under MDM, the content filter payload keeps users from turning it off.
