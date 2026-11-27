# Handing an app-generated key to Wi-Fi

## Summary

An app on an unmanaged phone can generate an EAP-TLS key in software, get
it signed, and hand key and certificate to Wi-Fi, which imports the key
into its own hardware-backed keystore. Both a `WifiNetworkSuggestion` and
`Settings.ACTION_WIFI_ADD_NETWORKS` support this (verified on Android 17
against WPA3-Enterprise). In automatic enrollment the key exists only in
memory during setup or renewal; in manual setup it is encrypted under a
non-exportable Android Keystore key while waiting for signing. It never
leaves the phone.

A key generated directly in hardware can't be used for Wi-Fi unless a
device or profile owner delegates certificate installation and selection
to the app.

## How Android handles EAP-TLS keys

Based on the Android SDK sources and AOSP (`WifiEnterpriseConfig`,
`DevicePolicyManager`, `KeyChain`, `WifiKeyStore`, `WifiConfigManager`,
`KeyChainService`, `DevicePolicyManagerService`, `WifiConfigController2`):

### Software key imported by Wi-Fi (without delegated certificate scopes)

The app generates an exportable software key in its own process and passes
it with the signed certificate to `setClientKeyEntryWithCertificateChain()`
in a `WifiNetworkSuggestion` (or `Settings.ACTION_WIFI_ADD_NETWORKS`).

- `WifiNetworkSuggestionsManager` calls `WifiKeyStore.updateNetworkKeys()`,
  which imports the key into the Android Keystore of the Wi-Fi uid
  (`AndroidKeyStoreProvider.getKeyStoreForUid(Process.WIFI_UID)` in
  `WifiInjector`). Once imported into KeyMint, the key is
  hardware-protected and cannot be read back out.
- The app can't use the key after handing it over. Renewal therefore
  generates a new key each time, and renewal authentication uses a
  separate hardware-backed device credential.
- Removing the suggestion, revoking the app's Wi-Fi control permission, or
  uninstalling the app removes the network and its key
  (`WifiKeyStore.removeKeys()`).

### KeyChain key used by Wi-Fi (with delegated certificate scopes)

A profile owner that delegates both `DELEGATION_CERT_INSTALL` and
`DELEGATION_CERT_SELECTION` lets the app make the key with
`DevicePolicyManager.generateKeyPair(null, "EC", spec, 0)` and give
it its certificate with `setKeyPairCertificate()`. The generated key is
granted to the caller, so the app signs its CSR with
`AttestedKeyPair.getKeyPair().private`; a spec with a uid set is refused.
`grantKeyPairToWifiAuth()` needs `CERT_SELECTION`. The suggestion then
carries only the alias (`setClientKeyPairAlias()`), and
`WifiNetworkSuggestionsManager` accepts it when
`WifiKeyStore.validateKeyChainAlias()` finds the Wi-Fi grant in the app's
user. No device or profile owner check is needed on the suggestion; the
grant is enough.

### The app's own Android Keystore key

Doesn't work with a non-exportable key.
`setClientKeyEntryWithCertificateChain()` calls `privateKey.getEncoded()`
and throws `IllegalArgumentException("Private key cannot be encoded")` when
it returns `null`. Android Keystore keys always return `null` there; the
method exists to copy a software key into the Wi-Fi keystore.

### Credential management app

Blocked on an unmanaged phone:

- A credential management app may call `generateKeyPair()` and
  `setKeyPairCertificate()` for aliases in its policy
  (`DevicePolicyManagerService.generateKeyPair`).
- Wi-Fi only uses a KeyChain alias that has been granted to the Wi-Fi uid.
  `WifiKeyStore` calls `KeyChain.getWifiKeyGrantAsUser()`, which returns
  `null` without that grant, and the network is rejected
  (`Unable to get key grant`).
- The grant can only be set by a system-uid caller
  (`KeyChainService.setGrant`). The only public route is
  `DevicePolicyManager.grantKeyPairToWifiAuth()`, which requires a profile
  owner, a device owner or a `DELEGATION_CERT_SELECTION` delegate
  (`canChooseCertificates`). A credential management app is none of these.
- The Wi-Fi dialog in Settings only lists keys in the Wi-Fi keystore
  namespace (`KeyProperties.NAMESPACE_WIFI`), so the user can't grant a
  KeyChain key to Wi-Fi there either.

### User-installed certificate

Importing a PKCS#12 file through the system certificate installer works,
but requires generating or exporting the private key outside Wi-Fi.

### Work profile or device owner alternatives

- **Work profile owned by an app**: a profile owner can call
  `grantKeyPairToWifiAuth()`, and Wi-Fi treats profile owners as
  privileged callers (`isDeviceOwnerProfileOwnerOrSystem`). Android allows
  only one work profile per device, so another app can't create a work
  profile while an existing profile owner holds it; the delegation scopes
  have to come from that profile owner.
- **Delegated certificate scopes**: a profile owner that delegates
  `DELEGATION_CERT_INSTALL` and `DELEGATION_CERT_SELECTION` lets an app in
  the same profile use `generateKeyPair()`, `setKeyPairCertificate()`,
  `grantKeyPairToWifiAuth()` and `setClientKeyPairAlias()`. EAP Enroll
  takes this route when both scopes are delegated to it, and the software
  handover otherwise. A suggestion with a client key pair alias needs only
  the key granted to Wi-Fi in the app's user
  (`WifiKeyStore.validateKeyChainAlias`); `WifiNetworkSuggestionsManager`
  has no device or profile owner check of its own.
- **Local device-policy apps**: apps such as OwnDroid, TestDPC or Dhizuku
  can act as profile or device owner and delegate the scopes. A device
  owner disables work profiles, clone profiles and private space
  (`DISALLOW_ADD_MANAGED_PROFILE`, `DISALLOW_ADD_CLONE_PROFILE`,
  `DISALLOW_ADD_PRIVATE_PROFILE`).
- **Prior art**: [Droid_SCEP](https://github.com/schorschii/Droid_SCEP)
  likewise generates its key in software; without a managed
  `CERT_INSTALL` delegation, it wraps the key and certificate in a
  PKCS#12 for `KeyChain.createInstallIntent()` and does not configure
  Wi-Fi networks.

## Observed Android behaviour

- Both `addNetworkSuggestions()` and `Settings.ACTION_WIFI_ADD_NETWORKS`
  accept an app-generated EC P-384 key and certificate chain for EAP-TLS
  (including WPA3-Enterprise). Settings saves the key under the alias
  `"<SSID>"_WPA_EAP_IEEE8021X_TLS_NULL`.
- After the app deletes its own copy of the key and its wrapping key (in
  manual setup), the phone continues to reconnect across Wi-Fi toggles and
  restarts using Wi-Fi's imported copy.
- Removing the app's suggestion removes the network; Settings displays
  active suggestions as "Connected via EAP Enroll".
- SSIDs are matched verbatim, including leading or trailing spaces; the
  app never trims SSIDs.
- Forgetting or disconnecting from a network puts its SSID on Android's
  user-disabled list (`disableEphemeralNetwork`), which blocks automatic
  joining of suggestions for that SSID until the user selects the network
  in Wi-Fi settings or turns Wi-Fi off and on.
- Without `WifiEnterpriseConfig.setMinimumTlsVersion()`, Android allows
  TLS 1.0; the app sets `TLS_V1_2` on Android 14 and later.
