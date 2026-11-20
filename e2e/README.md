# End-to-end test

Runs the app's enrollment client (`Enroller`, on the JVM) against a real
eap-enroll server. Only OpenBao is faked: `harness/` is a small Go program
that makes a throwaway PKI, answers the OpenBao calls the server makes,
writes the server's configuration and starts `eap-enroll serve`.

What it covers: setup with a one-time code, the first Wi-Fi certificate
and profile, confirming a new certificate (older ones revoked in OpenBao),
device credential renewal (old credential revoked), single-use codes, a
wrong CA fingerprint in the setup link, and a disabled device or user. The
Android parts (Keystore key, network suggestion, broadcast, background
job) are replaced by in-memory fakes; they need the phone.

Needs Go 1.27 and an `eap-enroll` binary built from eap-enroll-server:

```sh
e2e/run.sh /path/to/eap-enroll
```

The script builds the harness into `build/e2e/`, starts it, runs
`EndToEndTest` and stops it. The server's log ends up in
`build/e2e/run/server.log`. Without a running harness, `EndToEndTest` is
skipped in the normal unit test run.

The harness puts a TCP proxy in front of the server that connects from a
different 127.x.y.z address for each connection, so the server's
per-address rate limits don't get in the way.
