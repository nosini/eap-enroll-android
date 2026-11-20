# Notes for coding agents

## Start here

- Read `README.md` and `docs/design.md`. The design is a draft, and several
  Android API assumptions in it are marked as unverified. Check them
  against the Android documentation and on a real device.
- If `AGENT-HANDOFF.md` exists, read it: it's the untracked hand-over from
  the previous session.
- If `docs/private.local.md` exists, read it as well. It's gitignored and
  has my network's values, where my infrastructure repository lives, and
  details of the build environment.
- Handing an app-generated key to Wi-Fi works (`docs/key-handover.md`).
  Enrollment and renewal: the app's side is `docs/enrollment.md`; the
  enrollment server is built in my infrastructure repository, not here.
- My infrastructure repository is for reading facts, not for editing from
  here. If the app needs a server-side change, write it up as a proposal.

## Boundaries

- Don't log in to my servers, call my CA or other production APIs, or
  change RADIUS, Wi-Fi or router configuration. I issue test certificates
  and make production changes myself.
- No secrets in Git: no private keys, PKCS#12 files, tokens, enrollment
  codes or Wi-Fi passwords.
- Nothing personal in tracked files either: no real domains, CA names, host
  names, SSIDs, usernames or local paths. Those go in
  `docs/private.local.md`. Code, docs and tests use placeholders like
  `radius.example.org`, and the app takes network values as settings.
- I run the tests on the phone. Give me exact steps and tell me which log
  lines or screenshots to send back.
- Don't push, publish or sign release builds unless I ask.

## Build

- Java 17 and the Gradle wrapper. The Android SDK may be read-only; if a
  component is missing, ask me to install it.
- Builds and scratch files go in the repository's ignored build
  directories or outside the repository.
- Pin Gradle, the Android Gradle Plugin and dependencies to exact versions,
  with `distributionSha256Sum` in the wrapper. Keep dependencies minimal:
  AndroidX core, WorkManager once renewal starts, and no crypto libraries
  for what the platform already does.

## Code

- Kotlin, one `app` module, minSdk 31 (Android 12, for the credential
  management app APIs), targeting the newest installed platform.
- Default branch is `main`. Commits are signed; keep it that way.
