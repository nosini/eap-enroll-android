# Design

EAP Enroll puts an EAP-TLS client certificate on an unmanaged Android 12+
phone without device management or PKCS#12 imports, and renews it
automatically before it expires.

## Goal

On an unmanaged Android 12+ phone:

1. generate the EAP-TLS key on the phone so it never leaves the device and
   ends up in hardware-backed storage;
2. get a certificate for it from the network's private CA;
3. configure Wi-Fi without importing a PKCS#12 file;
4. renew the certificate before it expires, without losing Wi-Fi in
   between.

Not in scope: device management (MDM), a general-purpose EST client for
the Play Store, and running an EST or SCEP server inside this project.

Generating the Wi-Fi key directly in hardware needs a device or profile
owner. In a work profile whose owner app delegates certificate
installation and selection, the app generates the key in the KeyChain and
Wi-Fi uses it by alias. Otherwise the app generates the Wi-Fi key in
software and hands it to Wi-Fi, which imports it into Wi-Fi's own
hardware-backed keystore. See [key handover](key-handover.md) for the
Android platform details.

## Network settings

The app isn't tied to one network. In automatic enrollment, the network's
settings come from the enrollment server's `wifi/profile` endpoint; in
manual setup, they are entered in the app:

- SSID (kept verbatim, including leading or trailing spaces)
- EAP identity (the username)
- RADIUS server domain, matched against the server certificate
- CA certificate(s) for validating the RADIUS server
- WPA3-Enterprise only vs WPA2/WPA3-Enterprise
- enrollment server URL and pinned CA fingerprint (for automatic enrollment)

Real network values never go into tracked source, resources or tests;
tests and docs use placeholders like `radius.example.org`.

## Reference RADIUS and PKI setup

Tested with FreeRADIUS and client certificates from an OpenBao PKI:

| Item | Value |
| --- | --- |
| Server domain | the RADIUS server certificate name |
| Trust anchor | one private root CA for both server and client certificates |
| Client issuing CA | an EAP intermediate under that root |
| TLS versions | 1.2 and 1.3 |
| Client key type | EC P-384 (EC P-256 also supported in manual setup) |
| Client certificate | CN = FreeRADIUS username, no SANs (SANs in the CSR are ignored) |
| Revocation | OpenBao CRL, fetched by FreeRADIUS periodically |

FreeRADIUS checks two things after authentication: the EAP identity
(`User-Name`) selects the user and VLAN from the users file, and the
certificate CN must match that identity (case-insensitive).

What that means for the app:

- No anonymous outer identity. With `anonymous` as outer identity both the
  VLAN lookup and the CN check fail, so Android's anonymous identity is
  left empty.
- The CN is the username, not a device ID. A user can have several
  devices, each with its own key and certificate under the same CN. Each
  phone gets its own certificate, so a lost one can be revoked by serial
  number.

## Key handover to Wi-Fi

In automatic enrollment, the app generates a fresh EC P-384 key for each
certificate. In a work profile whose owner app delegates certificate
installation and selection, the key is generated in the KeyChain,
non-exportable and in the phone's secure hardware (the TEE; StrongBox
usually lacks P-384). The app stores the issued certificate chain with the
key and grants the key to Wi-Fi, which uses it by alias
(`WifiEnterpriseConfig.setClientKeyPairAlias()`). The state records
every alias, from before the key is generated, since the app can't list
KeyChain keys; keys that no suggestion uses are deleted once the current
certificate is confirmed (see [enrollment](enrollment.md)).

Without both delegated scopes, the key is generated in software. The app
hands the key and issued certificate chain directly to Wi-Fi in a
`WifiNetworkSuggestion` via
`WifiEnterpriseConfig.setClientKeyEntryWithCertificateChain()`. The key is
never written to disk and the app keeps no copy. The next Wi-Fi
certificate switches to the KeyChain path once both scopes are delegated,
and back when they are not.

In manual setup, the key must survive while the user has the CSR signed:

1. Generate an EC key pair in software (P-384 or P-256).
2. Encrypt the PKCS#8 private key with AES-GCM under a non-exportable
   Android Keystore key and store only the ciphertext.
3. Build a PKCS#10 CSR with CN = the EAP identity and export it.
4. Import the signed certificate (PEM, leaf first, optionally followed by
   the issuing CA) and verify that its public key matches the stored key.
5. Add the network as a `WifiNetworkSuggestion` or through
   `Settings.ACTION_WIFI_ADD_NETWORKS`. Wi-Fi imports the key into its own
   Android Keystore.
6. Delete the encrypted key and its Android Keystore wrapping key once the
   phone has connected.

Manual setup always uses the software path, with and without delegated
certificate scopes.

## Enrollment and renewal

See [enrollment](enrollment.md) for the full state machine and protocol
handling. In summary:

1. **Setup**: authorized with a short-lived, single-use code (typically
   from a QR code), never a reusable CA token. The server decides the CN,
   lifetime and role and ignores what the app puts in the CSR.
2. **Renewal authentication**: the app generates a separate EC P-256
   device key in its own Android Keystore (non-exportable, StrongBox if
   available, otherwise TEE) with hardware key attestation, and uses its
   device certificate for mutual TLS to the enrollment server only. RADIUS
   never trusts it.
3. **Renewal**: a daily JobScheduler job starts renewing at 2/3 of each
   certificate's lifetime. Every Wi-Fi renewal generates a new key: a
   software key can't be reused after Wi-Fi imports it, and the KeyChain
   path also uses a new key for each certificate. The app installs the new
   certificate in the suggestion and confirms it once Wi-Fi connects with
   it, so the server can revoke older certificates.
4. **Expiry warnings**: a notification warns when less than 1/6 of a
   certificate's lifetime remains and renewal hasn't succeeded, or when
   the server has refused the phone.

Certificate lifetimes stay long (months, not days). A phone with an
expired certificate can only renew over another network, and revocation is
handled by the CRL and the users file.

## Server side

The enrollment server is a separate project,
[eap-enroll-server](https://github.com/nosini/eap-enroll-server), running
in front of OpenBao. The app speaks EST-style endpoints
(`/.well-known/est/...`) against a configurable server URL with a pinned
CA fingerprint. Without an enrollment server, manual setup works with any
CA.

## Security requirements

- The Wi-Fi private key never leaves the device. With delegated
  certificate scopes it is non-exportable in the KeyChain. Otherwise, in
  automatic enrollment it exists in memory only during the request and
  handover; in manual setup it is encrypted at rest under a non-exportable
  Android Keystore key.
- Server validation is strict: only the configured CA certificate(s) are
  trusted and the configured server domain must match. The app won't save
  a network without both. No trust on first use, no "don't validate".
- Connections to the enrollment server use TLS 1.3 only, with a pinned CA
  fingerprint and hostname verification inside the handshake.
- The app holds no CA/OpenBao credentials and no long-lived secrets other
  than its hardware-backed device key.
- The enrollment server and Wi-Fi are separate trust domains: RADIUS never
  trusts the device credential, and a Wi-Fi certificate cannot enroll a
  new device.
- Logs, notifications and exception messages never contain private keys or
  one-time setup codes.

## References

- Android: `KeyChain`, `DevicePolicyManager`, `WifiEnterpriseConfig`,
  `WifiNetworkSuggestion`, `Settings.ACTION_WIFI_ADD_NETWORKS`, Android
  Keystore and StrongBox.
- RFC 7030 (EST).
