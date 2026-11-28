# Development

## Building

Building needs JDK 17 and an Android SDK with platform 37.2 and
build-tools 37.0.0.

    ./gradlew testDebugUnitTest assembleDebug

The debug APK ends up in `app/build/outputs/apk/debug/`.
[e2e/README.md](../e2e/README.md) describes the end-to-end test against
eap-enroll-server.

## Dependencies

Gradle checks every downloaded artifact (plugins included) against the
SHA-256 in `gradle/verification-metadata.xml`, locally and in CI. After
changing a dependency or a plugin version, regenerate the file with the
tasks that resolve them, from an empty Gradle home as CI starts with (a
warm cache skips metadata files such as BOMs that a cold one fetches),
then review the diff (new entries only for the changed dependencies):

    GRADLE_USER_HOME=$(mktemp -d) ./gradlew --no-daemon --no-configuration-cache \
      --write-verification-metadata sha256 \
      help :app:testDebugUnitTest :app:lintDebug :app:lintRelease \
      :app:assembleDebug :app:assembleRelease

The Android build tools are pinned (`buildToolsVersion`), and so are, in
`.github/workflows/build.yml`, the runner image, the JDK patch release and
the Android SDK packages; update them there together.

## Release builds

GitHub Actions builds releases from version tags only; pushes to `main`
don't build anything. For a `v*` tag it runs the unit tests and lint,
then builds and signs the release APK, attests it, and publishes it as a
GitHub release. Tests and lint run in a job of their own that never gets
the signing secrets; the signing job builds without a Gradle cache, daemon
or configuration cache, so nothing from the test run or the build keeps the
key. The tag must match `versionName` and be reachable from `main`:

    git tag -s v0.2.0 -m "EAP Enroll 0.2.0"
    git push origin v0.2.0

Re-running the workflow for a tag whose release is already published
fails rather than replacing the APK; it only finishes a draft that an
earlier run left behind. For a fixed build, release a new version. A
release is created only when GitHub says there is none; if looking it up
fails for another reason, the step fails with that error.

The attest job signs a SLSA build provenance attestation for the APK's
SHA-256 with `actions/attest`, which gets a short-lived Sigstore
certificate for the workflow run through GitHub's OIDC token. It is the
only job with `id-token: write`, and it never has the signing key; the
release is published only after it succeeds. A re-run that rebuilds a
draft's APK attests the new APK too, since an APK signature (ECDSA) is
different on every build.

The repository has immutable releases turned on (**Settings → General →
Releases**): once published, a release's APK and tag can't be changed or
deleted, and GitHub adds an attestation of the release. Uploading to a
draft still works, which the publish step relies on. README.md shows the
`gh` commands that check both attestations.

Signing needs two repository secrets:

- `SIGNING_KEYSTORE_BASE64`: the keystore, base64-encoded
  (`base64 -w0 release.jks`)
- `SIGNING_STORE_PASSWORD`: its password (PKCS12, so it's also the key
  password)

The key alias is `eapenroll`. The repository variable `SIGNING_CERT_SHA256`
holds the SHA-256 of the signing certificate (from `keytool -list -v`),
which the workflow compares with the built APK. The APK is named
`eap-enroll-$version.apk`.

Make the key outside the checkout:

    keytool -genkeypair -keystore release.jks -storetype PKCS12 \
        -alias eapenroll -keyalg EC -groupname secp384r1 \
        -sigalg SHA384withECDSA -validity 10000 -dname "CN=EAP Enroll"

Keep it backed up outside GitHub: without it, a new build can't update an
installed app, and uninstalling deletes the app's keys and its Wi-Fi
network.

For local release builds, put the signing details in a gitignored
`keystore.properties` next to `settings.gradle.kts`. `SIGNING_*`
environment variables take precedence, and a relative `storeFile` is
relative to the checkout. Without signing details, `assembleRelease`
writes an unsigned APK.

```properties
storeFile=/path/to/release.jks
storePassword=...
keyAlias=eapenroll
```

## Switching from a debug build to a release build

A release build can't be installed over a debug build because the signing
keys differ. Uninstall the debug build and set the app up again.

Android's key rotation would allow an in-place update, but a rotated
app's key attestation names the oldest certificate in its signing history
(`KeyAttestationApplicationIdProviderService` reads `GET_SIGNATURES`).
That would make the debug key the app's attested identity for good.
