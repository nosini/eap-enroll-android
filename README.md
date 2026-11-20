# eap-enroll-android

An Android app that gets an EAP-TLS Wi-Fi client certificate for a
personal (unmanaged) phone, and installs and renews it without the private
key ever being exportable. The network (SSID, identity, RADIUS
server domain, CA certificate) is set in the app.

Right now I make these certificates by hand: generate the key on a
computer, sign the CSR with my OpenBao PKI, and import a PKCS#12 file on
the phone. That works and stays the fallback. This project is about
whether the key can be created on the phone, kept in hardware, and used
for Wi-Fi without device management.

Status: not started. First step is the proof of concept in
[docs/design.md](docs/design.md#phase-0).
