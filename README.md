# eap-enroll-android

An Android app that gets an EAP-TLS Wi-Fi client certificate for a
personal (unmanaged) phone, and installs and renews it without the private
key ever leaving the phone. The network (SSID, identity, RADIUS
server domain, CA certificate) is set in the app.

Right now I make these certificates by hand: generate the key on a
computer, sign the CSR with my OpenBao PKI, and import a PKCS#12 file on
the phone. That works and stays the fallback. This app creates the key on
the phone and hands it, with the signed certificate, straight to Android's
Wi-Fi keystore, without device management.

Status: phase 0 proof of concept, not yet tested on a phone. See
[docs/design.md](docs/design.md#phase-0) for the plan and
[docs/phase0-results.md](docs/phase0-results.md) for what's known so far.

## Building

Needs JDK 17 and an Android SDK with platform 36.1.

    ./gradlew testDebugUnitTest assembleDebug

The APK ends up in `app/build/outputs/apk/debug/`.
