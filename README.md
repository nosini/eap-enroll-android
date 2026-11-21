# EAP Enroll

EAP Enroll puts an EAP-TLS client certificate for WPA2/WPA3-Enterprise
Wi-Fi on an Android phone and renews it before it expires. The private key
is made on the phone and goes straight into Android's Wi-Fi keystore: it
is never exported, copied or typed in.

It's meant for personal phones on self-hosted networks. It doesn't
need device management, a work profile or Google Play services.

- One-step setup from a QR code or link from
  [eap-enroll-server](https://github.com/nosini/eap-enroll-server), which
  issues the certificates from an [OpenBao](https://openbao.org) PKI.
- Automatic renewal in the background. Old certificates are revoked once
  the new one has connected.
- The phone authenticates to the server with a key in its secure hardware
  (StrongBox or the TEE), with hardware key attestation.
- A manual mode for any CA: the app makes the key and a certificate
  request (CSR) to be signed by the CA, and imports the certificate.

## Requirements

- Android 12 or later.
- A Wi-Fi network with EAP-TLS (WPA2-Enterprise or WPA3-Enterprise).
- For enrollment and renewal: an eap-enroll-server for the network.
  Without one, use [manual setup](#manual-setup).

Tested on a Pixel 10 Pro XL with GrapheneOS (Android 17). Other phones
should work but haven't been tried.

## Install

Download `eap-enroll-<version>.apk` from the
[releases](https://github.com/nosini/eap-enroll-android/releases) and open
it on the phone, or install it with `adb install`.

Releases are signed with this certificate (check with
`apksigner verify --print-certs`):

    CN=EAP Enroll
    SHA-256 13:F8:8F:4D:76:22:54:BA:A4:32:A9:44:29:E2:85:C2:B0:C0:84:33:E4:28:E3:1C:92:62:9A:4E:14:94:75:05

## Set up

1. Ask the network's administrator for a setup code. They run
   `eap-enroll code` on the server, which shows a QR code with an
   `eapenroll://setup?...` link. The code works once and expires after a
   few minutes. If setup fails, the app says whether the same link can be
   tried again or a new one is needed.
2. Scan the QR code. If the camera app opens the link, EAP Enroll opens
   with it filled in. Otherwise copy the link, open EAP Enroll and tap
   **Paste link**.
3. If the network is WPA3-Enterprise only, turn on **WPA3-Enterprise only
   network**. The server doesn't tell the app this.
4. Tap **Set up**. The app gets its device credential, the network's
   settings and the first Wi-Fi certificate, and adds the network to Wi-Fi.
5. Android asks whether to allow the suggested network. Allow it. The phone
   then connects to the network on its own; Wi-Fi settings show it as
   "Connected via EAP Enroll".
6. The app then lists what's still missing, such as location for
   confirming renewals and notifications for warnings. Both are optional;
   see [Permissions](#permissions).

## Renewal

The app checks once a day whether anything is due. A Wi-Fi certificate is
renewed at two thirds of its lifetime (40 days for a 60-day certificate).
The new certificate is used from the next connection.

After the phone has connected with the new certificate, the app tells the
server, which revokes the older ones. Until then, the older certificates
stay valid until they expire.

The app's own credential for the server is renewed the same way, at two
thirds of its lifetime (for example after eight months of a year). If the phone
misses that, for example because it was off for months, the credential
expires and the phone needs a new setup link.

The main screen shows whether everything is in order and the details of
both certificates. A notification warns if a certificate is close to
expiring and renewal hasn't worked, or if the server has refused the
phone.

- **Check now** runs the daily check straight away.
- **Renew certificate** gets a new Wi-Fi certificate even if nothing is
  due. It refuses while the current certificate hasn't been confirmed.
- **Remove enrollment** (in the menu) deletes the app's keys and
  certificates and removes the network from Wi-Fi. It doesn't revoke
  anything on the server; ask the administrator to disable the device.
- **Activity log** (in the menu) shows what the app did, for bug reports.

## Permissions

| Permission | Why |
| --- | --- |
| Wi-Fi and network state | Adding the network, and running the daily check only when online. |
| Network (GrapheneOS) | Reaching the enrollment server. |
| Nearby devices (Android 17) | Reaching an enrollment server on the local network. The app asks only for local network access (`ACCESS_LOCAL_NETWORK`), which Android lists under Nearby devices; it has no Bluetooth or Wi-Fi device scanning permissions. Asked for when setting up; without it, Android drops connections to local addresses and they time out. Not needed for a server on the internet. |
| Location, "all the time" (optional) | Android only tells an app that a connection through its network worked if the app may read Wi-Fi scan results, which needs location. With "only while using the app", renewals are confirmed only while the app is open. Without it, they're not confirmed at all. |
| Notifications (optional) | Warnings about failing renewals. |
| Run at startup | Keeping the daily check scheduled after a restart. |

## Manual setup

Without an enrollment server, open **Manual setup** (on the setup screen
or in the menu) and follow its steps:

1. Enter the SSID exactly as broadcast (including any spaces), the EAP
   identity and the RADIUS server's domain, choose the security type, and
   tap **Import CA certificate**: the CA that signed the RADIUS server's
   certificate.
2. **Generate key and CSR**, then share, save or copy the CSR and have it
   signed by the network's CA.
3. **Import file** or **Paste** the signed certificate.
4. **Add network**, or **Save through Settings** to add it as a normal
   saved network.
5. Once the phone has connected, **Delete key and certificate**. Wi-Fi
   keeps its own copy.

Manual certificates aren't renewed; repeat the steps before they expire.

## Troubleshooting

- **Setup fails with "connection closed".** A VPN app may be taking the
  connection and unable to reach the server. Let the VPN reach the server,
  or exclude EAP Enroll from the VPN.
- **Setup or renewal times out.** On Android 17, an enrollment server on
  the local network needs the **Nearby devices** permission. Allow it in
  the app's settings, or tap **Allow nearby devices** on the main screen.
- **The camera shows the link but doesn't open the app.** Some camera
  apps, including GrapheneOS Camera, don't open `eapenroll://` links. Paste
  the link instead.
- **"The app isn't allowed to use the network".** On GrapheneOS, network
  access is a permission that can be turned off. Allow **Network** in the app's
  settings.
- **The phone doesn't connect after the network was disconnected or
  forgotten.** Android then stops connecting to the app's network on its own.
  Select the network in Wi-Fi settings once, or turn Wi-Fi off and on.
- **Renewals aren't confirmed.** Check the location permission. With the
  app open, turning Wi-Fi off and on confirms within about half a minute
  (or tap **Check now** once it has reconnected).

## How it works

Android only lets device or profile owners give Wi-Fi access to keys in the
Keystore. So EAP Enroll generates the Wi-Fi key in software for each
certificate and hands the key and certificate to Wi-Fi in a network
suggestion. Wi-Fi stores them in its own keystore; the app keeps no copy.

The app authenticates to the enrollment server with a separate device
credential, whose key stays in the phone's StrongBox or TEE. RADIUS never
accepts that credential, and the server can require proof by hardware key
attestation that the key is really in secure hardware.

More detail:

- [docs/enrollment.md](docs/enrollment.md): setup, renewal, confirmation,
  and how the app handles the server's answers.
- [docs/design.md](docs/design.md): the design and the reasoning behind it.
- [docs/key-handover.md](docs/key-handover.md): the proof of concept
  and the Android behaviour it found.
- [docs/development.md](docs/development.md): building, tests and
  release signing.

## License

EAP Enroll is licensed under the [Mozilla Public License 2.0](LICENSE).
