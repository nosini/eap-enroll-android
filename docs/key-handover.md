# Handing an app-generated key to Wi-Fi

## Conclusion

An app on an unmanaged phone can generate an EAP-TLS key, get it signed,
and hand key and certificate to Wi-Fi, which imports the key into its own
hardware-backed keystore. Tested on a Pixel 10 Pro XL with Android 17
against a WPA3-Enterprise network; both a network suggestion and
`Settings.ACTION_WIFI_ADD_NETWORKS` work. The key exists in the app's
memory while the CSR is made and the network is added, and encrypted under
an Android Keystore key in between; it never leaves the phone.

A key generated in hardware can't be used for Wi-Fi without a device or
profile owner (see below).

## Source review (2026-11-20)

Before testing on a phone, the open questions from the design were checked
against the Android 16 SDK sources (API 36.1) and AOSP `main`. Files read:

- `android/net/wifi/WifiEnterpriseConfig.java` (SDK sources)
- `android/app/admin/DevicePolicyManager.java` (SDK sources)
- `android/security/KeyChain.java` (SDK sources)
- `packages/modules/Wifi`: `service/.../WifiKeyStore.java`,
  `WifiConfigManager.java`
- `packages/apps/KeyChain`: `src/.../KeyChainService.java`
- `frameworks/base`: `services/devicepolicy/.../DevicePolicyManagerService.java`
- `packages/apps/Settings`: `src/.../wifi/WifiConfigController2.java`

OEM builds can differ from AOSP, so these results still need a test on a
real phone.

### Path B: the app's own Android Keystore key

Doesn't work with a non-exportable key.
`setClientKeyEntryWithCertificateChain()` calls `privateKey.getEncoded()`
and throws `IllegalArgumentException("Private key cannot be encoded")` when
it returns `null`. Android Keystore keys always return `null` there. The
method exists to copy a software key into the Wi-Fi keystore.

### Path A: credential management app

Blocked on an unmanaged phone.

- A credential management app may call `generateKeyPair()` and
  `setKeyPairCertificate()` for aliases in its policy
  (`DevicePolicyManagerService.generateKeyPair`).
- Wi-Fi only uses a KeyChain alias that has been granted to the Wi-Fi uid.
  `WifiKeyStore` calls `KeyChain.getWifiKeyGrantAsUser()`, which returns
  `null` without that grant, and the network is rejected
  (`Unable to get key grant` in the log).
- The grant can only be set by a system-uid caller
  (`KeyChainService.setGrant`). The only public route is
  `DevicePolicyManager.grantKeyPairToWifiAuth()`, which requires a profile
  owner, a device owner or a `DELEGATION_CERT_SELECTION` delegate
  (`canChooseCertificates`). A credential management app is none of these.
- The Wi-Fi dialog in Settings only lists keys in the Wi-Fi keystore
  namespace (`KeyProperties.NAMESPACE_WIFI`), so the user can't grant a
  KeyChain key to Wi-Fi there either.

### Path C: user-installed certificate

Works as before, but the key is generated off the phone.

### A route not in the design: a work profile owned by the app

An app can create a work profile on a personal phone and become its
profile owner, without an MDM server. A profile owner can call
`grantKeyPairToWifiAuth()`. `WifiKeyStore` looks up the grant in the
KeyChain of the user that created the network, so a network added from the
work profile should be able to use a key generated there. Wi-Fi also treats
profile owners as privileged callers (`isDeviceOwnerProfileOwnerOrSystem`
in `WifiConfigManager`), so `WifiManager.addNetwork()` should still be
available to them.

Not verified yet:

- that a network added from the work profile connects with the
  work-profile key;
- what happens to that network when the work profile is paused;
- whether StrongBox and P-384 are available for keys generated in the
  work profile.

Android allows only one work profile per device. On a phone that already
has one owned by another app (Shelter, for example), this app can't create
its own. The existing profile owner could delegate the certificate scopes
(`DevicePolicyManager.setDelegatedScopes()` with `DELEGATION_CERT_INSTALL`
and `DELEGATION_CERT_SELECTION`) to an app inside its profile, but Shelter
doesn't do that (checked in its source, 2026-09-27 snapshot).

### Variant of path B: a software key imported by Wi-Fi

The app generates the key in its own process (an exportable software key,
not in the Android Keystore) and passes it with the signed certificate to
`setClientKeyEntryWithCertificateChain()` in a `WifiNetworkSuggestion`.

- Suggestions support this: `WifiNetworkSuggestionsManager` calls
  `WifiKeyStore.updateNetworkKeys()`, which installs the key.
- Wi-Fi stores it in the Android Keystore of the Wi-Fi uid
  (`AndroidKeyStoreProvider.getKeyStoreForUid(Process.WIFI_UID)` in
  `WifiInjector`). The key is imported into KeyMint there, so after the
  import it's hardware-protected and can't be read back out.
- The key never leaves the phone, but it exists in the app's memory between
  generation and import. While the app waits for the certificate, it would
  have to keep the key encrypted under a non-exportable Android Keystore key
  and delete it after the import.
- The app can't use the key after handing it over. Renewal therefore means
  a new key each time (key rotation), and mutual-TLS renewal with the
  current key isn't possible without keeping a copy.
- Removing the suggestion, or uninstalling the app, removes the network and
  its key.

### Prior art: Droid_SCEP

[Droid_SCEP](https://github.com/schorschii/Droid_SCEP) (checked at commit
`d8e13b7`, 2026-06-21) doesn't get around these limits either:

- It generates an RSA key in software (`KeyPairGenerator.getInstance("RSA")`,
  not the Android Keystore).
- On a managed device with the `CERT_INSTALL` scope delegated by an MDM, it
  installs the key silently with `DevicePolicyManager.installKeyPair()`.
- Otherwise it wraps the key and certificate in a password-protected
  PKCS#12 and hands that to `KeyChain.createInstallIntent()`, where the
  user picks the credential use and types the password, or saves the file.
- While a SCEP request is pending, the private key is kept as PEM in
  `SharedPreferences`, unencrypted.
- It doesn't configure Wi-Fi networks; renewal only shows an expiry
  notification.

So it's the same as the software-key variant above, except that it goes
through the system certificate installer instead of a network suggestion.

### Local device-policy apps (no server)

Apps that become profile or device owner on the phone itself, checked in
their source on 2026-11-20:

- OwnDroid (`5f945cc`) can create a work profile or be device owner, and
  can delegate scopes to other apps, including `DELEGATION_CERT_INSTALL` and
  `DELEGATION_CERT_SELECTION`.
- TestDPC (`e027da9`), Google's sample, can do the same. Its EAP-TLS
  dialog uses `grantKeyPairToWifiAuth()` and `setClientKeyPairAlias()`.
- Dhizuku (`bb93306`) is a device owner that lets other apps call device
  policy methods through it.

With those two scopes delegated to this app, path A works as designed in
the source: `generateKeyPair()` (hardware-backed, StrongBox if available),
`setKeyPairCertificate()`, `grantKeyPairToWifiAuth()`, then a suggestion
with `setClientKeyPairAlias()`. Wi-Fi looks up the grant in the KeyChain
of the user that added the network, so this app has to run in the same
profile as the delegating owner.

Limits:

- Only one work profile per device. If another app (Shelter) already owns
  it, the work profile would have to be recreated under a delegating
  owner, which deletes the profile's apps and data.
- A device owner rules out a work profile, a clone profile and private
  space. Setting up a device owner sets `DISALLOW_ADD_MANAGED_PROFILE`,
  `DISALLOW_ADD_CLONE_PROFILE` and `DISALLOW_ADD_PRIVATE_PROFILE` on every
  user (`DevicePolicyManagerService`). The `UserManager` docs say managed
  profiles on fully managed devices were removed from the platform, and a
  device owner clearing that restriction is silently ignored. Only
  secondary users remain, which are a separate login rather than apps side
  by side. Setting a device owner over adb also needs a phone without
  accounts or extra users.
- Not verified: whether a network suggested from a work profile keeps
  working while the work profile is paused.

## Device tests

### 2026-11-20: Pixel 10 Pro XL, Android 17 (API 37), patch 2026-10-05

StrongBox present. Access point: WPA3-Enterprise only
(`[RSN-EAP/SHA256-CCMP-128][MFPR][MFPC]`). P-384 client key, certificate
signed manually from the app's CSR.

- `addNetworkSuggestions()` with the software key and chain returned
  `SUCCESS`, and the user approved the suggestion. `WifiKeyStore` logged no
  errors, so the key import was accepted.
- `Settings.ACTION_WIFI_ADD_NETWORKS` also works for EAP-TLS with a
  client key: Settings returned success per network and saved the network
  with the user certificate `"<SSID>"_WPA_EAP_IEEE8021X_TLS_NULL`, the alias
  Wi-Fi uses for keys it imported itself.
- **The network saved through Settings connected.** EAP-TLS works with a
  key generated by the app, without device management.
- **The suggestion connected on its own** (on a second SSID without the
  trailing space, same access point settings). Settings shows the network
  as "Connected via EAP Enroll".

Problems found on the way:

- The SSID of the test network ends with a space. The app trimmed the
  SSID field, so the network was never found (`NETWORK_NOT_FOUND_EVENT` in
  `dumpsys wifi`) and Settings didn't merge the saved network with the scan
  result. The app now keeps the SSID exactly as typed.
- Forgetting or disconnecting from a network puts its SSID on Android's
  user-disabled list (`disableEphemeralNetwork`), which blocks automatic
  joining of suggestions for that SSID until the user selects it or turns
  Wi-Fi off and on.
- Without `setMinimumTlsVersion()` the network allows TLS 1.0; the app now
  sets TLS 1.2 on Android 14 and later (the API is new in 14).
- Some keyboards turned `.` into a space in the domain field; the field now
  uses the URI keyboard and the domain is validated.

- After the app deleted its encrypted copy of the key and its wrapping
  key, the phone still reconnected (Wi-Fi off and on, and after a
  restart). Wi-Fi's imported copy is all that's needed.
- Removing the app's suggestion removed the network. AOSP removes the
  imported key at the same time (`WifiKeyStore.removeKeys()` from
  `WifiNetworkSuggestionsManager`); that part wasn't checked on the phone.
