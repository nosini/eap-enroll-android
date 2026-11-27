# End-to-end test

Runs the app's enrollment client (`Enroller`, on the JVM) against a real
eap-enroll server. Only OpenBao is faked: `harness/` is a small Go program
that makes a throwaway PKI, answers the OpenBao calls the server makes,
writes the server's configuration and starts `eap-enroll serve`.

What it covers: setup with a one-time code, the first Wi-Fi certificate
and profile, confirming a new certificate (older ones revoked in OpenBao),
device credential renewal (old credential revoked) with the attestation
challenges the app uses, a replaced credential used again (device
disabled), too many requests (429, the app waits), single-use codes, a
wrong CA fingerprint in the setup link, and a disabled device or user. The
Android parts (Keystore key and its attestation, network suggestion,
broadcast, background job) are replaced by in-memory fakes; they need the
phone. Key attestation is off in this test: only a real phone can make an
attestation the server accepts.

Needs Go 1.27 and an `eap-enroll` binary built from eap-enroll-server:

```sh
e2e/run.sh /path/to/eap-enroll
```

The script builds the harness into `build/e2e/`, starts it, runs
`EndToEndTest` and stops it. The server's log ends up in
`build/e2e/run/server.log`. Without a running harness, `EndToEndTest` is
skipped in the normal unit test run.

For a phone test, run the harness by hand and reach it through
`adb reverse`:

```sh
build/e2e/e2e-harness -dir build/e2e/phone -eap-enroll /path/to/eap-enroll \
  -public-port 8443 [-device-ttl 1h] \
  [-attestation-roots /path/to/attestation-roots.pem -app-signing-cert SHA256]
```

- `-attestation-roots`: the server requires Android key attestation,
  trusting these roots (eap-enroll-server's
  `deploy/attestation-roots.pem`). The harness serves the server's
  revocation list itself, with one made-up entry, so Google's list isn't
  fetched and no real attestation key counts as revoked.
- `-app-signing-cert` (required with `-attestation-roots`, repeatable):
  the SHA-256 of the certificate the installed APK is signed with, which
  the attestation must name. For a debug build it's the
  `Signer #1 certificate SHA-256 digest` from
  `apksigner verify --print-certs app/build/outputs/apk/debug/app-debug.apk`.
  `-app-package` (default `eu.appwerf.eapenroll`) is the package name the
  attestation must name.
- `-device-ttl`: device credential lifetime (default `8760h`, at least
  `1h`), so a renewal comes due within the test.
- `POST …/code` (control URL in `build/e2e/phone/control`) runs the
  `eap-enroll` binary, which answers `exit status 1: <its stderr>` on
  failure. The fake OpenBao has only `alice` enabled (`bob` is
  disabled); other users need `POST …/group?user=U&group=staff` before
  `/code` works for them.

The harness puts a TCP proxy in front of the server that connects from a
different 127.x.y.z address for each connection, so the server's
per-address rate limits don't get in the way.
