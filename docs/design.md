# Design

First draft, 2026-11-20. Phase 0 has been tested and works; see
[phase 0 results](phase0-results.md). The later phases are untested plans.

## Goal

On an unmanaged Android 12+ phone:

1. generate the EAP-TLS key on the phone; it never leaves the phone and
   ends up in hardware-backed storage;
2. get a certificate for it from the network's private CA;
3. use it for Wi-Fi without importing a PKCS#12 file;
4. later, renew it before it expires, without losing Wi-Fi in between.

Not in scope: device management (MDM), a general-purpose EST client for the
Play Store, and writing an EST or SCEP server (see
[Server side](#server-side)).

Generating the key in hardware isn't possible on an unmanaged phone: Wi-Fi
only takes a hardware key from KeyChain when a device or profile owner has
granted it to Wi-Fi. See [phase 0 results](phase0-results.md) for the
details and the managed alternatives.

## Network settings

The app isn't tied to one network. These are set in the app:

- SSID
- EAP identity (the username)
- RADIUS server domain, matched against the server certificate
- CA certificate(s) for validating the RADIUS server, imported as PEM
- later, the enrollment (EST) endpoint

A plain input screen is enough for phase 0. Real values never go into
tracked source, resources or tests; tests use names like
`radius.example.org`.

## Test setup

Tested with FreeRADIUS and client certificates from an OpenBao PKI. That
setup looks like this:

| Item | Value |
| --- | --- |
| Server domain | the RADIUS server certificate name |
| Trust anchor | one private root CA for both server and client certificates |
| Client issuing CA | an EAP intermediate under that root |
| TLS versions | 1.2 and 1.3 |
| Client key type | EC P-384 |
| Client certificate | CN = FreeRADIUS username, no SANs (SANs in the CSR are ignored) |
| Client certificate lifetime | 2 years |
| Revocation | OpenBao CRL, fetched by FreeRADIUS every hour; a user removed from the users file is locked out once it's redeployed |

FreeRADIUS checks two things after authentication: the EAP identity
(`User-Name`) picks the user and VLAN from the users file, and the
certificate CN has to match that identity (case-insensitive).

What that means for the app:

- No anonymous outer identity. With `anonymous` as outer identity both the
  VLAN lookup and the CN check fail, so leave Android's "anonymous
  identity" empty or set it to the username.
- The CN is the username, not a device ID. A user can have several devices,
  each with its own key and certificate under the same CN. Each phone still
  gets its own certificate, so a lost one can be revoked by serial number.
- P-384 is what's issued today. StrongBox often only does P-256, so check
  what the test phone supports. P-256 is fine for the proof of concept if
  the CA's client role accepts it.

## Phase 0

One question first: does Wi-Fi accept a key the app generated and handed
over, and does the connection work? Nothing else is worth building if it
doesn't.

Signing stays manual in this phase. The app exports a CSR (as a file or as
text), it's signed on the CA, and the app imports the certificate.

### Flow

1. Generate an EC key pair in software (`KeyPairGenerator` without the
   Android Keystore provider), P-384 or P-256.
2. Encrypt the PKCS#8 private key with AES-GCM under a non-exportable
   Android Keystore key and store only the ciphertext. The plaintext key is
   never written to disk.
3. Build a PKCS#10 CSR with CN = the EAP identity and export it.
4. Import the signed certificate (PEM, leaf first, optionally followed by
   the issuing CA). Check that its public key matches the stored key.
5. Add the network as a `WifiNetworkSuggestion`: EAP-TLS, the CA
   certificate(s) and server domain from the settings, identity = username,
   no anonymous identity, and the key and chain through
   `WifiEnterpriseConfig.setClientKeyEntryWithCertificateChain()`. Wi-Fi
   imports the key into its own Android Keystore.
6. Once Wi-Fi has accepted the suggestion, delete the encrypted key and the
   Android Keystore wrapping key.
7. Connect and note the result.

Also try `Settings.ACTION_WIFI_ADD_NETWORKS` with the same suggestion. It
would save the network as a normal saved network, which survives
uninstalling the app, but it's unclear whether Settings handles enterprise
networks there.

Open questions for the phone test:

- Does the suggestion connect, and does the user-approval prompt for
  suggestions appear?
- Are P-384 keys accepted by the Wi-Fi keystore and `wpa_supplicant`?
- Does removing the suggestion remove the key from the Wi-Fi keystore?

### Results

Results go in `docs/phase0-results.md`: what worked, what didn't (with the
exact exception or `logcat` lines; filter on `WifiService`,
`wpa_supplicant`, `WifiKeyStore`, `EapEnroll`), the device details, and the
FreeRADIUS log lines for the test login (the reject reason is in
`Module-Failure-Message`).

If Wi-Fi doesn't accept the key, the fallback is the system certificate
installer (`KeyChain.createInstallIntent()` with a PKCS#12 made on the
phone), which needs the user to pick "Wi-Fi" and add the network by hand.

## Later phases (only once phase 0 works)

Built as described in [enrollment](enrollment.md), which has the details
and what changed on the way.

1. Enrollment: the app sends its CSR to a server and gets the certificate
   back. The first enrollment is authorized with a short-lived, single-use
   code (a QR code, for example), never a reusable OpenBao token. The
   server decides the CN, lifetime and role and ignores what the app asks
   for.
2. Renewal: a background job (JobScheduler) that starts well before expiry (around 2/3 of
   the lifetime) and retries daily. The app can't use the Wi-Fi key after
   handing it over, so every renewal is a new key: new key, new
   certificate, replace the suggestion, check that it connects. The old
   certificate is revoked only after the new one has been used for a
   successful Wi-Fi login.
3. Renewal authentication: the app keeps a separate key in its own Android
   Keystore (non-exportable, StrongBox if available) with its own
   certificate from the enrollment server, used for mutual TLS to that
   server only. Wi-Fi never sees it.
4. An expiry warning in the app, since Android doesn't guarantee when
   background work runs.

Certificate lifetimes stay long (months, not days). A phone with an expired
certificate can only renew over another network, and revocation is already
covered by the CRL and the users file.

## Server side

No EST or SCEP server gets written in this project. Options, in order:

1. Manual signing, as in phase 0, for as long as that's enough.
2. A small enrollment service in front of the CA, built and run as part
   of the network's infrastructure, not in this repository.
   [Enrollment](enrollment.md) describes the app's side and what it needs
   from that service.

The app should speak standard EST (`/.well-known/est/simpleenroll`,
`simplereenroll`, `cacerts`) against a configurable endpoint, so the
server can be swapped. An endpoint that hands out Wi-Fi credentials is new
attack surface; the current flow needs an administrator password for every
certificate.

## Security requirements

- The Wi-Fi private key never leaves the device. It exists in the app's
  memory only while generating the CSR and handing it to Wi-Fi; at rest
  it's encrypted under a non-exportable Android Keystore key.
- Server validation is strict: only the configured CA certificate(s) are
  trusted and the configured server domain has to match. The app won't save
  a network without both. No trust on first use, no "don't validate".
- The app holds no OpenBao credentials and no long-lived secrets other
  than its key.
- The enrollment endpoint, once there is one, is a separate trust domain
  from Wi-Fi: a stolen Wi-Fi certificate can at most renew itself.
- Logs never contain keys or enrollment codes.

## References

- Android: `KeyChain`, `DevicePolicyManager` (credential management app
  methods), `AppUriAuthenticationPolicy`, `WifiEnterpriseConfig`,
  `WifiNetworkSuggestion`, `Settings.ACTION_WIFI_ADD_NETWORKS`, Android
  Keystore and StrongBox.
- RFC 7030 (EST).
