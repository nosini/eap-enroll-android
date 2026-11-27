# Enrollment and renewal: the app's side

Updated 2026-11-21. The app gets its certificates from an enrollment
server instead of manual signing, and renews them before they expire. The
client is built, tested against the server on a computer
([end-to-end test](../e2e/README.md)) and on a phone against a test server
([phone tests](#phone-tests)), and on the real network since 2026-11-20.

The server is a separate project, eap-enroll-server. Its
`docs/protocol.md` is the reference for the requests; this file describes
what the app does with them.

## Credentials on the phone

1. **Wi-Fi certificate**: CN = username, from the network's EAP CA. Its key
   is an EC P-384 key generated in software for each certificate and handed
   to Wi-Fi in a network suggestion (see [key handover](key-handover.md)).
   After that the app can't use the key, and it keeps no copy.
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
  needs a tap on "Set up", so a link opened from elsewhere
  can't enroll the phone by itself.
- The link can also be pasted.
- The app trusts only the CA with that fingerprint for the server, taken
  from the server's own chain; no trust on first use. The code is never
  logged.
- Connections to the server are TLS 1.3 only. The pinned CA must be
  within its validity period, and the server's own certificate must not
  be a CA certificate. The server's certificate must name the host from
  the link (subject alternative names only, a wildcard for one label at
  most). The app checks this within the handshake, so a server with
  another name under the same CA never sees the device credential.
- Setup never offers the device credential, even when the phone is
  already enrolled: the server checks a client certificate in the TLS
  handshake, and an expired one would fail the handshake before the code
  is looked at.

Then the app:

1. generates the device key (with an attestation for the code) and sends a
   CSR for it with the code (`device/simpleenroll`);
2. fetches the Wi-Fi profile (`wifi/profile`: SSID, RADIUS server name and
   CA certificates), so no network settings have to be typed in;
3. gets the first Wi-Fi certificate (`wifi/simpleenroll`) and installs it
   as a network suggestion with identity = the certificate's CN.

If the first step fails, the app says whether the same link can be tried
again. The server checks the code first, then the request and the key
attestation, and only then uses the code up:

| Answer to `device/simpleenroll` | The link |
| --- | --- |
| 401 (`bad_code`, `code_used`, `code_expired`) | Not valid; a new one is needed. |
| 400, 413, 403 `attestation_refused`, 502 `attestation_status_unavailable` | Not used up; can be tried again. |
| 403 `user_disabled`, 429 | Used up; a new one is needed. |
| Other 5xx | May have been used up: try again, and a 401 then means it was. |

Only the WPA2/WPA3 choice is made in the app, because the profile
doesn't say whether the network is WPA3-Enterprise only (see
[Proposals for the server](#proposals-for-the-server)). It is chosen at
setup and stored with the enrollment, so every renewal uses it; manual
setup has its own switch, which doesn't affect it.

## Renewal

A daily background job (the platform JobScheduler, persisted across
restarts, needs a network) does whatever is due:

- At 2/3 of the Wi-Fi certificate's lifetime (40 of 60 days): a new key,
  a new certificate, and the suggestion is replaced. Adding a suggestion
  with the same SSID and security type replaces the old one and its key in
  Wi-Fi's keystore (AOSP `WifiNetworkSuggestionsManager.add()`).
- At 2/3 of the device credential's lifetime: a new Keystore key (attested
  for the current credential) and `device/simplereenroll`. The app stores
  the new credential and then uses it once (`wifi/profile`), which makes
  the server revoke the old one, and deletes the old key. A server
  without a Wi-Fi profile answers `wifi/profile` with 404 before
  authenticating, so that doesn't count; the app then confirms the
  current, already confirmed Wi-Fi certificate again instead. If there is
  none, the old key stays until a later request gets through.
- If the renewal fails, its answer is lost or storing the new credential
  fails, the app keeps the current one, deletes the new key, and the next
  check renews again with the same credential (and another new key). The
  server retires a credential it issued but never saw used, so only the
  credential from an answer that actually arrived is ever stored and used.
- A renewal that fails over the new key's attestation (`400
  bad_attestation`, `403 attestation_refused`, `502
  attestation_status_unavailable`), or because the phone can't make the
  new key, doesn't hold up the Wi-Fi certificate. The current credential
  still works and `wifi/simpleenroll` isn't attested, so a Wi-Fi
  certificate that is due is renewed in the same check.
- Once the new credential is stored, the old one is never used again: the
  server treats a replaced credential that comes back as copied, disables
  the device and revokes its certificates. So:
  - All requests run one at a time under one lock; nothing else runs
    during a renewal.
  - Each credential gets its own HTTP client with its own TLS context
    (and session cache). Right after storing the new credential the app
    closes the old client: its TLS sessions are invalidated and it
    refuses further requests.
  - Every request sends `Connection: close`, so no connection opened with
    the old certificate stays in the platform's connection pool.
  - Should a request still come over a connection opened with a replaced
    credential, the server answers `401 credential_superseded` and leaves
    the device enabled. The app then closes its client and runs the check
    once more from the stored state with a new client for the current
    credential; a second `credential_superseded` is retried later.
- The device credential is offered only on the requests that need it
  (`wifi/*`, `device/simplereenroll`), never on `cacerts` or
  `device/simpleenroll`.
- The app checks the device credential's expiry itself before using it.
  The server refuses an expired one in the TLS handshake, which would
  otherwise look like a network error and be retried forever; an expired
  credential needs a new setup link.
- The same goes for a stored enrollment the app can't read and for a
  device credential whose key is gone from the Keystore: the app stops
  and asks for a new setup link. A setup replaces the stored state, even
  an unreadable one, and deletes all other device keys. Every check also
  deletes device keys left behind by a setup or renewal that was
  interrupted before its state was stored.
- A failed request is retried by the next daily run, and a run started
  from the app, after a connection or after the server's wait is retried
  with backoff.
- When the app stops (a new setup link is needed, or the device or the
  account is disabled), it cancels its background jobs, so neither checks
  nor the notification come back every day. A check by the user that gets
  through, or a new setup, schedules them again. Every check that ends with
  no problem also makes sure the daily job is scheduled, so a check that
  cleared a problem while no activity was open isn't left without it.
- A Wi-Fi certificate that Android refuses to install is left to the
  daily check, since the server has issued it and requesting another soon
  would most likely only add another unconfirmed certificate. Before
  requesting one, the app checks that it may add networks: Wi-Fi refuses
  suggestions while the user has turned off the app's "Wi-Fi control"
  (Settings > Apps > Special app access) and, from Android 13, while an
  administrator forbids adding networks.
- "Renew certificate" refuses while the current certificate
  isn't confirmed yet (and isn't due). Unconfirmed certificates stay valid,
  and the server allows only a few valid ones per phone (5 on
  eap-enroll-server); past that it refuses renewals, the automatic ones
  included, until older certificates expire.

What the app does with the server's refusals. The server names the reason
in an `Enroll-Error` response header; without it, a 403 counts as a
disabled device.

| Answer | App |
| --- | --- |
| 401 | The server doesn't accept the device credential (unknown or revoked): stops; needs a new setup link. |
| 401 `credential_superseded` | The connection was opened with a replaced credential: reconnects with the current one and retries once; if that gets it again, retried later. |
| (no request) | The device credential has expired: stops without contacting the server; needs a new setup link. |
| 403 `device_disabled`, `credential_reuse` | The device is disabled: stops; needs a new setup link. |
| 403 `user_disabled` | The account is disabled: stops background checks. "Check now" tries again, since the account can be enabled again: it asks for `wifi/profile` first, and counts the account as enabled once the server has answered an authenticated request past its account check, even if the rest of the check fails. That includes a renewed device credential (the server issued it) and a confirmation that retires the previous credential when the server has no profile. Until then, a check that fails before getting through schedules nothing, and the app says so: the background checks stay stopped until the user asks again. |
| 403 `attestation_refused` | Only on device credential requests (for example an OS the server doesn't accept, or a security patch level that is too old). At setup the app shows it; at renewal the current credential still works, so the app keeps it and the daily check tries again with a new key, which passes once the phone is updated. |
| 429 | Stores the time from `Retry-After` (15 minutes without one, or with a zero or negative one; at most a day) and sends nothing before it, not even for a check started by the user. A one-off job runs when the wait is over. |
| 400 `bad_attestation`, 5xx, network errors | Retried soon, with backoff. |
| 400 `bad_csr`, 413 `body_too_large`, other 4xx | The request itself is wrong, so a retry soon would fail the same way: the daily check tries again. |

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
  isn't counted. The app measures those 10 seconds on the phone's
  monotonic clock (`elapsedRealtime`), so a clock change doesn't make a
  connection count too soon or hold back a real one. The state also keeps
  the boot count: a broadcast from another boot counts only if that boot
  is later than the install's, since the connection then came after the
  install; an earlier boot doesn't count. Without both (a state stored
  before they were kept, or a phone that won't say), the wall clock
  decides.
- Without location permission, or if the phone never reconnects while the
  app may hear it, nothing is confirmed and the older certificates simply
  expire. Turning Wi-Fi off and on (quick settings) with the app open
  confirms within a minute or so, or at once with "Check now".
- The broadcast itself only reads the suggestion and hands its SSID, wall
  time, elapsed time and boot count to a one-off job, which doesn't need a
  network.
  The job passes the connection to the enroller, which records it under
  its lock only if it is for the stored network and the enrollment isn't
  stopped; a broadcast that arrives while a check holds the lock therefore
  doesn't make the receiver wait, and the check and the recording can't
  interleave. The confirmation itself runs as a background
  job at least 30 seconds later (53 seconds on the test phone;
  JobScheduler treats the delay as a minimum). Right after Wi-Fi
  connects, the network (and an always-on VPN) is still switching over:
  during tests, a confirmation sent at once stalled in its TLS handshake
  until the server gave up after 10 seconds.

A connection through the server proves nothing: the phone may reach it
over mobile data or a VPN.

If the server answers `400` with one of these reasons, the certificate
isn't a current Wi-Fi certificate of this phone (`expired_serial`, `revoked_serial` or
`unknown_serial`), for example because it expired before the phone got to
confirm it. Confirming it again can't work, so the check doesn't stop
there: it requests a new Wi-Fi certificate right away, whether or not the
old one is due. The confirmation stays pending until the new certificate
is installed, so if that renewal fails, the next check does the same.
Network errors and `5xx` are retried as before; other answers are left to
the daily check, since a `400` without one of these reasons means the
request itself was wrong.

Known gap: if Wi-Fi fails to import a new key, `addNetworkSuggestions()`
still returns success and keeps the old suggestion (AOSP logs
`Enterprise network install failure`). The app can't tell, and a later
connection with the old certificate would confirm the new one. The old
certificate is then revoked and the phone needs a renewal over another
network. This hasn't happened in testing; the import worked in the key
handover test.

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
  It accepts `SelfSigned` verified boot (such as GrapheneOS) only for OS
  keys it has pinned, and it can refuse a phone whose security patch
  level is older than a set age.
- Refusal answers name their reason in an `Enroll-Error` response header
  (`user_disabled`, `device_disabled`, `credential_reuse`,
  `attestation_refused`, ...), so the app can tell them apart.

## Proposals for the server

- `wifi/profile` could say whether the network is WPA3-Enterprise only
  (for example `"security": "wpa3-enterprise"` or `"wpa2-enterprise"`).
  Until then the app has a local setting for it.
- Register `GET wifi/profile` behind `authenticated()` even when no
  profile is configured, and answer 404 after authenticating. Today the
  route doesn't exist then, so the 404 comes before authentication: it
  doesn't retire a superseded device credential, and it can't tell a
  phone whether its account is enabled again. The app works around it
  with a repeated `wifi/confirm`, which needs a confirmed Wi-Fi
  certificate.

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

### 2026-11-20: key attestation required

The harness with `-attestation-roots` (eap-enroll-server's
`deploy/attestation-roots.pem`) and `-device-ttl 1h`, still over
`adb reverse`, on the same phone running GrapheneOS (verified boot state
SelfSigned, its own boot key). Worked:

- The device key was generated in StrongBox with an attestation the
  server verified offline against Google's roots, at setup and at a
  renewal; `enroll_device` and `reenroll_device` logged
  `attestation_security_level: StrongBox` and
  `attestation_device_locked: true`.
- The renewal came due within the hour: the phone's clock was moved
  forward to just past 2/3 of the credential's lifetime, and "Check and
  renew now" made a new attested key. The server issued the new
  credential and revoked the old one as superseded. The expiry warning
  the clock jump raised on the old credential ("renewing it failed: not
  tried yet") cleared on the next check.

### 2026-11-20: on the real network

The same phone (GrapheneOS) against the deployed eap-enroll-server, with
key attestation required, and the network's FreeRADIUS. Worked:

- Setup from a one-time code: the device key in StrongBox with
  attestation, then the first Wi-Fi certificate. FreeRADIUS logged the
  login through the app's suggestion.
- The post-connection broadcast with "while using the app" location:
  turning Wi-Fi off and on with the app open confirmed the certificate.
- A manual renewal ("Get a new Wi-Fi certificate now") after the current
  certificate had been revoked by hand: the new certificate was installed
  in the suggestion, the phone reconnected, the app confirmed it, and the
  server revoked the older one as superseded.
- The same in the background: a renewal over a VPN that reaches the
  server, then the app left with the home button and Wi-Fi turned off and
  on. With "all the time" location the app confirmed the new certificate
  without being opened, and the server revoked the older one.

Found on the way:

- A VPN app in tunnel mode accepts the app's connection itself; if its
  routing doesn't reach the server, it closes the connection and setup
  fails with `SSLHandshakeException: connection closed` while the server
  logs nothing. Either let the VPN reach the server or exclude this app
  from it.
- GrapheneOS Camera reads the setup QR code and shows the `eapenroll://`
  link, but doesn't offer to open it in the app; paste the link into the
  app's setup field instead. Other camera or QR apps are untested.
- A Wi-Fi certificate revoked outside the server (for example by hand in
  OpenBao) still counts as valid there; the app recovers with a renewal as
  long as it can reach the server, through the old connection or another
  network.

### Still to test

- That the daily job runs on its own and a renewal comes due without help
  (the first at about two thirds of 60 days).
- A device credential renewal with the changes of 2026-11-21 (client
  closed at the switch, `Connection: close`, no credential on `cacerts`
  and `device/simpleenroll`). Tested so far against the server on a
  computer, where Java's `HttpsURLConnection` stands in for Android's.
