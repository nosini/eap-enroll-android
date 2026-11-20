# Enrollment and renewal: the app's side

Updated 2026-11-20. The app gets its certificates from an enrollment
server instead of manual signing, and renews them before they expire. The
client is built, tested against the server on a computer
([end-to-end test](../e2e/README.md)) and on a phone against a test server
([phone tests](#phone-tests)); the test on the real network is still open.

The server is a separate project, eap-enroll-server. Its
`docs/protocol.md` is the reference for the requests; this file describes
what the app does with them.

## Credentials on the phone

1. **Wi-Fi certificate**: CN = username, from the network's EAP CA. Its key
   is an EC P-384 key generated in software for each certificate and handed
   to Wi-Fi in a network suggestion (phase 0). After that the app can't use
   the key, and it keeps no copy.
2. **Device credential**: a client certificate for the enrollment server
   only. Its key is an EC P-256 key in the app's Android Keystore
   (non-exportable, StrongBox if the phone has it, otherwise the TEE) and
   never leaves it. RADIUS never trusts it.

The device credential is how the app authenticates renewals: the Wi-Fi key
is no longer available to the app, and the app holds no CA credentials or
reusable secrets.

The device key allows the digests SHA-256 (for the CSR) and NONE: the
platform TLS stack (Conscrypt) hashes the handshake itself and signs the
digest with `NONEwithECDSA`.

### Key attestation

The server can require Android hardware key attestation for the device
key, proving that it was generated in the phone's TEE or StrongBox. The
setup link doesn't say whether it does, so the app always attests: it
generates every device key with an attestation challenge and sends the
key's attestation chain in a `Key-Attestation` header (standard base64 of
the concatenated DER certificates, leaf first). A server that doesn't
require attestation ignores the header.

- Setup: the challenge is SHA-256 of the one-time code as sent in
  `Authorization: Bearer`.
- Renewal: SHA-256 of the DER of the device credential the request is
  authenticated with. The challenge is fixed when the key is generated,
  which is why every renewal uses a new key.
- Order of attempts: StrongBox with attestation, TEE with attestation, then
  without attestation (StrongBox, TEE). Attestation can fail for a while,
  for example before the phone has remotely provisioned attestation keys. A
  server that requires attestation then refuses the request (400,
  `bad_attestation`) and the app tries again later; a refused attestation
  doesn't use up the one-time code.
- The app's status shows where the key is and whether it is attested.

## Setup

The administrator runs `eap-enroll code` on the server, which prints a
setup link, shown as a QR code:

```
eapenroll://setup?ca=<SHA-256 hex>&code=<one-time code>&url=https://enroll.example.org:8443&v=1
```

- Scanning the QR code with the camera opens the link in the app (the app
  handles `eapenroll://setup`). The link only fills in the form; enrolling
  needs a tap on "Set up with this link", so a link opened from elsewhere
  can't enroll the phone by itself.
- The link can also be pasted.
- The app trusts only the CA with that fingerprint for the server, taken
  from the server's own chain; no trust on first use. The code is never
  logged.

Then the app:

1. generates the device key (with an attestation for the code) and sends a
   CSR for it with the code (`device/simpleenroll`);
2. fetches the Wi-Fi profile (`wifi/profile`: SSID, RADIUS server name and
   CA certificates), so no network settings have to be typed in;
3. gets the first Wi-Fi certificate (`wifi/simpleenroll`) and installs it
   as a network suggestion with identity = the certificate's CN.

Only the WPA2/WPA3 choice stays a setting in the app, because the profile
doesn't say whether the network is WPA3-Enterprise only (see
[Proposals for the server](#proposals-for-the-server)).

## Renewal

A daily background job (the platform JobScheduler, persisted across
restarts, needs a network) does whatever is due:

- At 2/3 of the Wi-Fi certificate's lifetime (40 of 60 days): a new key,
  a new certificate, and the suggestion is replaced. Adding a suggestion
  with the same SSID and security type replaces the old one and its key in
  Wi-Fi's keystore (AOSP `WifiNetworkSuggestionsManager.add()`).
- At 2/3 of the device credential's lifetime: a new Keystore key (attested
  for the current credential) and `device/simplereenroll`. The app then
  uses the new credential once (`wifi/profile`), which makes the server
  revoke the old one, and deletes the old key.
- A failed request is retried by the next daily run, and a run started
  from the app is retried with backoff.
- 401 means the server no longer accepts the device credential (a new
  setup link is needed); 403 means the device or user is disabled. Both
  stop renewal until the app is set up again.
- A notification warns when less than a sixth of a certificate's lifetime
  is left (10 of 60 days) and renewal hasn't worked, and when the server
  refused the phone. On Android 13 and later this needs the notification
  permission.

## Confirming a new Wi-Fi certificate

The server keeps older Wi-Fi certificates valid until the app confirms
(`wifi/confirm`) that the new one works; then it revokes them. The app
confirms only after Wi-Fi has connected through its suggestion after the
new certificate was installed:

- The suggestion is built with `setIsAppInteractionRequired(true)`, so
  Wi-Fi sends the app `ACTION_WIFI_NETWORK_SUGGESTION_POST_CONNECTION`
  after each connection through it.
- Wi-Fi sends that broadcast only if the app may read scan results at that
  moment: precise location granted and location on. With "Allow only while
  using the app" that means while the app is open; with "Allow all the
  time" also in the background (AOSP
  `WifiNetworkSuggestionsManager.handleConnectionSuccess()` checks the
  location app-op).
- Updating a suggestion doesn't reconnect: Wi-Fi keeps the current
  connection and only clears its cached keys (AOSP
  `ClientModeImpl.onNetworkUpdated()`). The new certificate is used on the
  next connection. So a broadcast in the first 10 seconds after the update
  isn't counted.
- Without location permission, or if the phone never reconnects while the
  app may hear it, nothing is confirmed and the older certificates simply
  expire. Turning Wi-Fi off and on (quick settings) with the app open
  confirms at once.

A connection through the server proves nothing: the phone may reach it
over mobile data or a VPN.

Known gap: if Wi-Fi fails to import a new key, `addNetworkSuggestions()`
still returns success and keeps the old suggestion (AOSP logs
`Enterprise network install failure`). The app can't tell, and a later
connection with the old certificate would confirm the new one. The old
certificate is then revoked and the phone needs a renewal over another
network. This hasn't happened in testing; the import worked in phase 0.

## Requirements on the server

All met by eap-enroll-server:

- It decides the certificate subject (the username for the device),
  lifetime and profile, and ignores the CSR's subject and extensions.
- One-time codes are single-use and expire after minutes.
- The device credential comes from a CA that RADIUS doesn't trust.
- Disabling a device stops it from getting certificates at once, and
  revokes the device's Wi-Fi certificates.
- It accepts EC P-384 Wi-Fi keys and EC P-256 or P-384 device keys.
- It can require hardware key attestation for device keys
  (`key_attestation`), checked offline against Google's attestation roots.

## Proposals for the server

- `wifi/profile` could say whether the network is WPA3-Enterprise only
  (for example `"security": "wpa3-enterprise"` or `"wpa2-enterprise"`).
  Until then the app has a local setting for it.

## Phone tests

### 2026-11-20: against a test server over `adb reverse`

Pixel 10 Pro XL, Android 17 (API 37), StrongBox present. The server was
the [end-to-end harness](../e2e/README.md) on a computer, reached through
`adb reverse`, so the Wi-Fi certificates came from a throwaway CA and the
suggested network ("Example Net ") doesn't exist.

Worked:

- The device key was generated in StrongBox (EC P-256), and the server
  accepted TLS client authentication with it: `wifi/simpleenroll` only
  answers a client presenting the device credential.
- Setup from the link, the Wi-Fi profile, and installing the first and a
  second Wi-Fi certificate as a network suggestion.
- The daily job, started by hand (`cmd jobscheduler run -f`), ran and
  found nothing due.

Found and fixed on the way:

- On this phone the network is a runtime permission ("Network"), and an
  update that adds `INTERNET` doesn't get it. Sockets then fail with
  `SocketException: socket failed: EPERM`; the app now says the network
  permission is missing.
- JobScheduler refuses jobs with a network constraint without
  `ACCESS_NETWORK_STATE`.
- Reopening the app from recents filled in the (used) setup link again.

### Still to test

On the real network, once the server is deployed:

- That the RADIUS server accepts the enrolled certificate and the phone
  connects through the suggestion.
- That replacing the suggestion keeps Wi-Fi working and the next connection
  uses the new key.
- That the post-connection broadcast arrives with "while using the app"
  location while the app is open, and with "all the time" in the
  background, and that the confirmation revokes the old certificate.
- That the camera app opens `eapenroll://` links from a QR code.
- That the daily job runs on its own.
