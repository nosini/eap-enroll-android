# Notes for coding agents

## Start here

- If `AGENTS.local.md` exists, read it first. It's gitignored and has the
  maintainer's own notes: their setup, local files and working rules.
- The docs:
  - `README.md`: what the app does, for users.
  - `docs/enrollment.md`: the app's side of setup, renewal and
    confirmation, and what it does with each of the server's answers.
  - `docs/design.md`: the design and the reasoning behind it.
  - `docs/key-handover.md`: handing an app-generated key to Wi-Fi, and
    the Android behaviour found on the phone.
  - `docs/development.md`: building, release builds and signing.
  - `e2e/README.md`: the end-to-end test against a real server.
- The enrollment server is
  [eap-enroll-server](https://github.com/nosini/eap-enroll-server), a
  separate repository. Its `docs/protocol.md` is the contract the app
  follows; check changes to request handling against it. Changes the
  server needs are written up as proposals, not made from here.

## Boundaries

- No secrets in Git: no private keys, PKCS#12 files, keystores, tokens,
  setup links or codes, or Wi-Fi passwords. Setup codes and private keys
  also stay out of the activity log, logcat, notifications and
  exception messages.
- Nothing about a real network in tracked files: no real domains, CA
  names, host names, SSIDs, usernames or local paths. Keep those in
  gitignored `*.local.md` files. Code, docs and tests use placeholders
  like `radius.example.org`, and the app takes network values from the
  setup link, the server or its settings.
- Android behaviour that the JVM tests can't cover needs a phone test.
  Write exact steps and say which lines of the in-app **Activity log**
  (or logcat, tag `EapEnroll`) or which screenshots show the result.
- Pushing a `v*` tag makes GitHub Actions build, sign and publish a
  release.

## Build and test

- Java 17 and the Gradle wrapper, with the Android SDK platform named in
  `docs/development.md`.
- Before committing, run `./gradlew testDebugUnitTest lintDebug
  assembleDebug`.
- The unit tests run on the JVM against the stub `android.jar`. Android
  parts (Keystore, Wi-Fi suggestions, the state store) sit behind the
  interfaces in `Enroller.kt`, with fakes in `TestFakes.kt`. Watch for
  differences between the JVM and the phone: for example, Android's
  built-in `org.json` turns JSON `null` into the string `"null"`, but the
  `org.json` used by the tests throws.
- `EndToEndTest` is skipped unless `e2e/run.sh` runs it against an
  `eap-enroll` binary built from eap-enroll-server (needs Go; see
  `e2e/README.md`).
- Builds and scratch files go in the repository's ignored build
  directories or outside the repository.
- Pin Gradle, the Android Gradle Plugin, dependencies and GitHub Actions
  to exact versions, with `distributionSha256Sum` in the wrapper and
  Actions pinned to commit SHAs.
- The app has no runtime dependencies; the platform does the work
  (Keystore, JobScheduler, `org.json`, the crypto). Tests use only JUnit
  and `org.json`. Don't add a dependency for something the platform
  already does.

## Code

- Kotlin, one `app` module, minSdk 31 (Android 12, for the credential
  management app APIs), compiled for and targeting the newest platform.
- `Enroller` is the enrollment and renewal state machine. It doesn't
  use Android, so the JVM tests can run it. `AndroidEnrollment.kt` has
  the Android implementations, and `Background.kt` has the scheduled
  jobs, the connection broadcast and the notification.
- When behaviour changes, update `README.md` and `docs/enrollment.md` in
  the same commit.
- A release bumps `versionCode` and `versionName` together; the tag must
  match `versionName`.

## Commits

- Default branch is `main`; work on a branch.
- One fix or change per commit. The subject is a plain sentence in the
  imperative, without prefixes. The body says what went wrong or why the
  change is needed, then what changed.
