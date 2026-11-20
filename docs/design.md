# Design

First draft, 2026-11-20. None of this has been tested yet.

## Goal

On an unmanaged Android 12+ phone:

1. generate the EAP-TLS key on the device, non-exportable, preferably in
   hardware (StrongBox or TEE);
2. get a certificate for it from the network's private CA;
3. use it for Wi-Fi without importing a PKCS#12 file;
4. later, renew it before it expires, without losing Wi-Fi in between.

Not in scope: device management (MDM), a general-purpose EST client for the
Play Store, and writing an EST or SCEP server (see
[Server side](#server-side)).

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

One question first: can a normal app on an unmanaged phone use a key it
generated itself for EAP-TLS? Nothing else is worth building if it can't.

Signing stays manual in this phase. The app exports a CSR (as a file or as
text), it's signed on the CA, and the app imports the certificate.

Try the paths below in order. For each, note whether it worked, plus the
Android version, phone model and security patch level.

### Path A: credential management app (KeyChain)

1. Ask the user to make the app the credential management app with
   `KeyChain.createManageCredentialsIntent(AppUriAuthenticationPolicy)`.
   The policy maps apps/URIs to aliases; find out whether it needs, or can
   have, an entry for Wi-Fi.
2. Generate the key with `DevicePolicyManager.generateKeyPair()` (EC,
   StrongBox if available), build the CSR in the app and export it.
3. Attach the signed certificate and chain with
   `DevicePolicyManager.setKeyPairCertificate()`.
4. Add the network as a `WifiNetworkSuggestion` (and, separately, through
   `Settings.ACTION_WIFI_ADD_NETWORKS`) with
   `WifiEnterpriseConfig.setClientKeyPairAlias(alias)`, EAP method TLS, and
   the CA certificate, server domain and identity from the settings.
5. Connect and note the result.

Open questions:

- `DevicePolicyManager.grantKeyPairToWifiAuth()` is documented for device
  owners, profile owners and delegated apps. Can a credential management
  app on an unmanaged phone call it, or does Wi-Fi accept its keys without
  it? This is the most likely blocker.
- Does `setClientKeyPairAlias()` work for suggestions and
  `ACTION_WIFI_ADD_NETWORKS`, or only for networks a device owner adds?

### Path B: the app's own Android Keystore key

1. Generate a non-exportable key in the app's `AndroidKeyStore`.
2. Pass it to `WifiEnterpriseConfig.setClientKeyEntryWithCertificateChain()`
   in a `WifiNetworkSuggestion`.

Open question: this method may copy the key into the Wi-Fi keystore, which
a non-exportable key won't allow. If it only works with an exportable key,
write that down and stop there, because an exportable key defeats the
purpose.

### Path C: KeyChain without a credential management app

`KeyChain.choosePrivateKeyAlias()` plus the system Wi-Fi settings, with a
certificate the user installed. That's roughly the current manual flow, so
it's a baseline to compare with, not a goal.

### Results

Results go in `docs/phase0-results.md`: what worked, what didn't (with the
exact exception or `logcat` lines; filter on `WifiService`,
`wpa_supplicant`, `KeyChain`, `Keystore`), the device details, and the
FreeRADIUS log lines for the test login (the reject reason is in
`Module-Failure-Message`).

If neither A nor B works on a stock phone, the project either stops here
or falls back to keeping manual signing and only automating the import.

## Later phases (only once phase 0 works)

1. Enrollment: the app sends its CSR to a server and gets the certificate
   back. The first enrollment is authorized with a short-lived, single-use
   code (a QR code, for example), never a reusable OpenBao token. The
   server decides the CN, lifetime and role and ignores what the app asks
   for.
2. Renewal: a WorkManager job that starts well before expiry (around 2/3 of
   the lifetime) and retries daily. It authenticates with the current
   certificate over mutual TLS. The new certificate goes on the same key;
   key rotation is a separate step. The old certificate is revoked only
   after the new one has been used for a successful Wi-Fi login.
3. Key rotation: new key, new certificate, update the network, check that
   it connects, then remove the old key.
4. An expiry warning in the app, since Android doesn't guarantee when
   background work runs.

Certificate lifetimes stay long (months, not days). A phone with an expired
certificate can only renew over another network, and revocation is already
covered by the CRL and the users file.

## Server side

No EST or SCEP server gets written in this project. Options, in order:

1. Manual signing, as in phase 0, for as long as that's enough.
2. An existing RFC 7030 server in front of OpenBao, such as
   `mabunixda/est-service` (not reviewed yet), or native EST in OpenBao if
   it ever lands (openbao/openbao issue 1222; check where it stands).

The app should speak standard EST (`/.well-known/est/simpleenroll`,
`simplereenroll`, `cacerts`) against a configurable endpoint, so the
server can be swapped. An endpoint that hands out Wi-Fi credentials is new
attack surface; the current flow needs an administrator password for every
certificate.

## Security requirements

- The private key never leaves the device and is never exportable.
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
