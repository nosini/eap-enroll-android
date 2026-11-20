# Enrollment and renewal: the app's side

Draft, 2026-11-20. Covers the later phases of [the design](design.md): the
app gets its certificates from an enrollment server instead of manual
signing, and renews them before they expire. Nothing here is built yet.

This describes what the app does and what it expects from the server. The
server is a separate project and isn't built in this repository.

## Credentials on the phone

1. **Wi-Fi certificate**: CN = username, from the network's EAP CA. Its key
   is generated in software and handed to Wi-Fi in a network suggestion
   (phase 0). After that the app can't use the key.
2. **Device credential**: a client certificate for the enrollment server
   only. Its key is generated in the app's Android Keystore
   (non-exportable, StrongBox if available) and never leaves it. RADIUS
   never trusts it.

The device credential is how the app authenticates renewals: the Wi-Fi key
is no longer available to the app, and the app holds no CA credentials or
reusable secrets.

## Setup

The app needs three things, ideally from a QR code the administrator
shows:

- the enrollment server's URL;
- the SHA-256 fingerprint of the CA that issued the server's TLS
  certificate (the app trusts only that CA for this server; no trust on
  first use);
- a one-time code, valid for minutes.

## Requests

EST (RFC 7030) over HTTPS, with two labels:

| Step | Request | Authentication | Body | Response |
| --- | --- | --- | --- | --- |
| Device credential | `POST /.well-known/est/device/simpleenroll` | `Authorization: Bearer <code>` | CSR for the Keystore key | device certificate (PKCS#7) |
| Wi-Fi certificate | `POST /.well-known/est/wifi/simpleenroll` | mutual TLS, device credential | CSR for a new software key | Wi-Fi certificate (PKCS#7) |
| EAP CA chain | `GET /.well-known/est/wifi/cacerts` | none | | CA certificates (PKCS#7) |
| Device credential renewal | `POST /.well-known/est/device/simplereenroll` | mutual TLS, device credential | CSR, same or new Keystore key | device certificate (PKCS#7) |

The app puts the username in its CSRs only for readability; the server
decides the subject.

`wifi/simpleenroll` is used for renewal too: the app authenticates with the
device credential rather than the certificate being renewed, and the key
always changes. That deviates from EST re-enrollment on purpose.

## Renewal

- A WorkManager job starts at about 2/3 of the Wi-Fi certificate's
  lifetime and retries daily.
- It requests a Wi-Fi certificate for a new key and replaces the network
  suggestion.
- It tells the server which certificate it replaced only after the new one
  was used for a successful connection, so the server can revoke the old
  one. (How the app reports this is still open.)
- The device credential is renewed the same way, before it expires.
- The app warns the user when a certificate is close to expiring and
  renewal keeps failing, because Android doesn't guarantee when background
  work runs.

## Requirements on the server

- It decides the certificate subject (the username for the device),
  lifetime and profile, and ignores the CSR's subject and extensions.
- One-time codes are single-use and expire after minutes.
- The device credential comes from a CA that RADIUS doesn't trust.
- Disabling a device stops it from getting certificates at once, and
  revokes the device's Wi-Fi certificates.
- It accepts EC P-384 keys for both credentials (P-256 if a phone's
  StrongBox can't do P-384).

## Open questions

- Whether the server also provides the Wi-Fi network profile (SSID,
  server CA, domain), so the app needs no manual settings.
- How the app reports that a new certificate works, so the old one can be
  revoked.
- Lifetimes of both credentials.
