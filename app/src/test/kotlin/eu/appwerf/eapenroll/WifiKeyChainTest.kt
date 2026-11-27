package eu.appwerf.eapenroll

import java.util.Date
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Wi-Fi keys in the KeyChain when a profile owner delegates certificate scopes. */
class WifiKeyChainTest {
    private val server = FakeEstServer()
    private val keys = MemoryKeys()
    private val store = MemoryStore()
    private val wifiKeys = FakeWifiKeys()
    private val wifi = RecordingWifi()
    private val now = System.currentTimeMillis()
    private val day = 86_400_000L
    private val deviceCa = server.deviceCa
    private val wifiCa = TestPki.root("Wi-Fi CA")
    private val profile = WifiProfile("Example Net", "radius.example.org", listOf(TestPki.root("RADIUS CA").cert))
    private val link = SetupUri.parse(
        "eapenroll://setup?v=1&url=${server.url}&ca=${server.caFingerprint}&code=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
    )

    @After
    fun stop() = server.close()

    private fun enroller() = Enroller(
        keys, wifi, store, log = { println(it) }, clock = { now }, wifiKeys = wifiKeys,
    )

    /** The server issues a device credential, the profile and a Wi-Fi certificate. */
    private fun issuingEverything() {
        server.answer = {
            when (it.path) {
                "device/simpleenroll" -> FakeEstServer.issue(it, deviceCa, "alice", notAfter = Date(now + 365 * day))
                "wifi/profile" -> FakeEstServer.profile(profile)
                "wifi/simpleenroll" -> FakeEstServer.issue(it, wifiCa, "alice", notAfter = Date(now + 60 * day))
                "wifi/confirm" -> FakeEstServer.Answer(204)
                else -> FakeEstServer.Answer(503, "unavailable\n")
            }
        }
    }

    /** Like [issuingEverything], but [path] answers [answer]. */
    private fun issuingEverythingBut(path: String, answer: FakeEstServer.Answer) {
        issuingEverything()
        val normal = server.answer
        server.answer = { if (it.path == path) answer else normal(it) }
    }

    /** Set up, confirmed, with its KeyChain alias. */
    private fun setUpAndConfirmed(enroller: Enroller): String {
        issuingEverything()
        assertEquals(Enroller.Outcome.OK, enroller.setup(link))
        confirm(enroller)
        return store.load()!!.wifiKeyAlias!!
    }

    /** Enrolled, with nothing due. */
    private fun enrolled(): EnrollmentState {
        val alias = keys.create()
        val device = TestPki.leaf(deviceCa, "alice", keys.keyPair(alias), Date(now - day), Date(now + 365 * day))
        val wifiCert = TestPki.leaf(wifiCa, "alice", notBefore = Date(now - day), notAfter = Date(now + 59 * day))
        val state = EnrollmentState(
            server.url, server.caFingerprint, alias, listOf(device, deviceCa.cert),
            wifiChain = listOf(wifiCert, wifiCa.cert),
        )
        store.save(state)
        return state
    }

    /** Reports a connection after the install and confirms the certificate. */
    private fun confirm(enroller: Enroller) {
        val state = store.load()!!
        assertTrue(
            enroller.connectionObserved(
                state.profile!!.ssid, state.wifiInstalledAt + 60_000, 0, 0,
            ),
        )
        assertEquals(Enroller.Outcome.OK, enroller.maintain())
    }

    @Test
    fun withoutDelegationTheKeyIsSoftware() {
        wifiKeys.available = false
        issuingEverything()
        assertEquals(Enroller.Outcome.OK, enroller().setup(link))

        assertTrue(wifi.installs.single().key is WifiKey.Imported)
        val state = store.load()!!
        assertNull(state.wifiKeyAlias)
        assertTrue(state.oldWifiKeyAliases.isEmpty())
        assertTrue(wifiKeys.keys.isEmpty())
        assertTrue(wifiKeys.created.isEmpty())
        assertTrue(wifiKeys.chains.isEmpty())
        assertTrue(wifiKeys.granted.isEmpty())
    }

    @Test
    fun withDelegationTheKeyIsInTheKeyChain() {
        issuingEverything()
        assertEquals(Enroller.Outcome.OK, enroller().setup(link))

        val install = wifi.installs.single()
        val alias = (install.key as WifiKey.InKeyChain).alias
        val keyPair = wifiKeys.keys[alias]!!
        assertArrayEquals(keyPair.public.encoded, install.chain[0].publicKey.encoded)
        assertEquals(keyPair.public, FakeEstServer.csrKey(server.requests.single { it.path == "wifi/simpleenroll" }))

        val state = store.load()!!
        assertEquals(alias, state.wifiKeyAlias)
        assertTrue(state.oldWifiKeyAliases.isEmpty())
        assertEquals(Certs.withoutRoots(state.wifiChain!!), wifiKeys.chains[alias])
        assertTrue(alias in wifiKeys.granted)
    }

    @Test
    fun anOldKeyIsDeletedOnlyAfterTheNewCertificateIsConfirmed() {
        issuingEverything()
        val enroller = enroller()
        assertEquals(Enroller.Outcome.OK, enroller.setup(link))
        val firstAlias = store.load()!!.wifiKeyAlias!!
        confirm(enroller)
        assertTrue(wifiKeys.deleted.isEmpty())

        assertEquals(Enroller.Outcome.OK, enroller.maintain(renewWifi = true))
        var state = store.load()!!
        val secondAlias = state.wifiKeyAlias!!
        assertNotEquals(firstAlias, secondAlias)
        assertEquals(listOf(firstAlias), state.oldWifiKeyAliases)
        assertFalse(firstAlias in wifiKeys.deleted)

        confirm(enroller)
        state = store.load()!!
        assertEquals(listOf(firstAlias), wifiKeys.deleted)
        assertFalse(secondAlias in wifiKeys.deleted)
        assertEquals(secondAlias, state.wifiKeyAlias)
        assertTrue(state.oldWifiKeyAliases.isEmpty())
    }

    @Test
    fun aFailedKeyInTheKeyChainFallsBackToSoftware() {
        wifiKeys.createFailure = IllegalStateException("The KeyChain won't make the key")
        issuingEverything()
        assertEquals(Enroller.Outcome.OK, enroller().setup(link))

        assertTrue(wifi.installs.single().key is WifiKey.Imported)
        val state = store.load()!!
        assertNull(state.wifiKeyAlias)
        assertTrue(state.oldWifiKeyAliases.isEmpty())
        assertTrue(wifiKeys.keys.isEmpty())
    }

    @Test
    fun aFailedStoreKeepsTheCurrentKeyAndDeletesTheNewOne() {
        issuingEverything()
        val enroller = enroller()
        assertEquals(Enroller.Outcome.OK, enroller.setup(link))
        val firstAlias = store.load()!!.wifiKeyAlias!!
        confirm(enroller)
        val before = store.load()!!

        wifiKeys.storeFailure = IllegalStateException("The KeyChain won't store the certificate")
        assertEquals(Enroller.Outcome.LATER, enroller.maintain(renewWifi = true))

        val state = store.load()!!
        assertEquals(1, wifi.installs.size)
        assertEquals(firstAlias, state.wifiKeyAlias)
        assertTrue(state.oldWifiKeyAliases.isEmpty())
        assertEquals(before.wifiChain, state.wifiChain)
        val failedAlias = wifiKeys.deleted.single()
        assertNotEquals(firstAlias, failedAlias)
        assertFalse(failedAlias in wifiKeys.keys)
    }

    @Test
    fun aFailedKeyThatCannotBeDeletedStaysListedUntilALaterConfirmation() {
        issuingEverything()
        val enroller = enroller()
        assertEquals(Enroller.Outcome.OK, enroller.setup(link))
        val firstAlias = store.load()!!.wifiKeyAlias!!
        confirm(enroller)

        wifiKeys.storeFailure = IllegalStateException("The KeyChain won't store the certificate")
        wifiKeys.deleteFailure = { IllegalStateException("Delegation withdrawn") }
        assertEquals(Enroller.Outcome.LATER, enroller.maintain(renewWifi = true))
        var state = store.load()!!
        val failedAlias = state.oldWifiKeyAliases.single()
        assertNotEquals(firstAlias, failedAlias)
        assertEquals(firstAlias, state.wifiKeyAlias)
        assertTrue(failedAlias in wifiKeys.keys)

        wifiKeys.storeFailure = null
        wifiKeys.deleteFailure = null
        assertEquals(Enroller.Outcome.OK, enroller.maintain(renewWifi = true))
        state = store.load()!!
        val newAlias = state.wifiKeyAlias!!
        assertNotEquals(firstAlias, newAlias)
        assertTrue(failedAlias in state.oldWifiKeyAliases)
        assertTrue(firstAlias in state.oldWifiKeyAliases)

        confirm(enroller)
        state = store.load()!!
        assertTrue(failedAlias in wifiKeys.deleted)
        assertTrue(firstAlias in wifiKeys.deleted)
        assertTrue(state.oldWifiKeyAliases.isEmpty())
    }

    @Test
    fun withdrawnDelegationUsesSoftwareAndKeepsTheOldKeyListed() {
        issuingEverything()
        val enroller = enroller()
        assertEquals(Enroller.Outcome.OK, enroller.setup(link))
        val firstAlias = store.load()!!.wifiKeyAlias!!
        confirm(enroller)

        wifiKeys.available = false
        assertEquals(Enroller.Outcome.OK, enroller.maintain(renewWifi = true))
        var state = store.load()!!
        assertTrue(wifi.installs.last().key is WifiKey.Imported)
        assertNull(state.wifiKeyAlias)
        assertEquals(listOf(firstAlias), state.oldWifiKeyAliases)

        confirm(enroller)
        state = store.load()!!
        assertEquals(listOf(firstAlias), state.oldWifiKeyAliases)
        assertFalse(firstAlias in wifiKeys.deleted)
    }

    @Test
    fun forgetDeletesCurrentAndOldKeysEvenWhenOneFails() {
        val state = enrolled()
        listOf("wifi-current", "wifi-pending", "wifi-old-1", "wifi-old-2").forEach {
            wifiKeys.keys[it] = TestPki.keyPair("secp384r1")
        }
        store.save(state.copy(
            wifiKeyAlias = "wifi-current",
            pendingWifiKeyAliases = listOf("wifi-pending"),
            oldWifiKeyAliases = listOf("wifi-old-1", "wifi-old-2"),
        ))
        wifiKeys.deleteFailure = { alias ->
            if (alias == "wifi-old-1") IllegalStateException("The KeyChain won't remove it") else null
        }

        enroller().forget()

        assertNull(store.json)
        assertTrue(keys.keys.isEmpty())
        assertTrue("wifi-current" in wifiKeys.deleted)
        assertTrue("wifi-pending" in wifiKeys.deleted)
        assertTrue("wifi-old-2" in wifiKeys.deleted)
        assertFalse("wifi-old-1" in wifiKeys.deleted)
    }

    @Test
    fun setupWithANewLinkKeepsThePreviousEnrollmentsKeys() {
        val enroller = enroller()
        val first = setUpAndConfirmed(enroller)
        assertEquals(Enroller.Outcome.OK, enroller.maintain(renewWifi = true))
        val second = store.load()!!.wifiKeyAlias!!

        // The new enrollment's first Wi-Fi certificate isn't installed: the
        // previous suggestion, with the second key, stays in Wi-Fi.
        wifi.installFailure = WifiInstallException("Wi-Fi didn't take the network")
        assertEquals(Enroller.Outcome.LATER, enroller.setup(link))
        var state = store.load()!!
        assertNull(state.wifiKeyAlias)
        assertEquals(listOf(second), state.pendingWifiKeyAliases)
        assertEquals(listOf(first), state.oldWifiKeyAliases)
        assertFalse(second in wifiKeys.deleted)

        wifi.installFailure = null
        assertEquals(Enroller.Outcome.OK, enroller.maintain(renewWifi = true))
        state = store.load()!!
        val third = state.wifiKeyAlias!!
        assertTrue(state.pendingWifiKeyAliases.isEmpty())
        assertEquals(setOf(first, second), state.oldWifiKeyAliases.toSet())
        assertFalse(second in wifiKeys.deleted)

        confirm(enroller)
        assertTrue(first in wifiKeys.deleted)
        assertTrue(second in wifiKeys.deleted)
        assertFalse(third in wifiKeys.deleted)
        assertTrue(store.load()!!.oldWifiKeyAliases.isEmpty())
    }

    @Test
    fun aPendingKeyOfAnInterruptedRenewalIsNotDeleted() {
        val state = enrolled()
        listOf("wifi-current", "wifi-pending", "wifi-old").forEach { wifiKeys.keys[it] = TestPki.keyPair("secp384r1") }
        // Stopped after installing the suggestion with wifi-pending, before
        // storing the state: Wi-Fi may be using that key.
        store.save(state.copy(
            wifiKeyAlias = "wifi-current",
            pendingWifiKeyAliases = listOf("wifi-pending"),
            oldWifiKeyAliases = listOf("wifi-old"),
        ))
        issuingEverything()
        val enroller = enroller()

        assertEquals(Enroller.Outcome.OK, enroller.maintain())
        assertEquals(listOf("wifi-old"), wifiKeys.deleted)
        assertEquals(listOf("wifi-pending"), store.load()!!.pendingWifiKeyAliases)

        assertEquals(Enroller.Outcome.OK, enroller.maintain(renewWifi = true))
        val renewed = store.load()!!
        assertTrue(renewed.pendingWifiKeyAliases.isEmpty())
        assertEquals(setOf("wifi-current", "wifi-pending"), renewed.oldWifiKeyAliases.toSet())

        confirm(enroller)
        assertEquals(setOf("wifi-old", "wifi-current", "wifi-pending"), wifiKeys.deleted.toSet())
        assertFalse(renewed.wifiKeyAlias in wifiKeys.deleted)
    }

    @Test
    fun oldKeysAreDeletedOnALaterCheckOnceTheAppMay() {
        val enroller = enroller()
        val first = setUpAndConfirmed(enroller)
        assertEquals(Enroller.Outcome.OK, enroller.maintain(renewWifi = true))
        wifiKeys.deletable = false
        confirm(enroller)
        assertEquals(listOf(first), store.load()!!.oldWifiKeyAliases)

        wifiKeys.deletable = true
        assertEquals(Enroller.Outcome.OK, enroller.maintain())
        assertEquals(listOf(first), wifiKeys.deleted)
        assertTrue(store.load()!!.oldWifiKeyAliases.isEmpty())
    }

    @Test
    fun aFailedKeyFollowedByAFailedRequestLeavesNoAlias() {
        wifiKeys.createFailure = IllegalStateException("The KeyChain won't make the key")
        issuingEverythingBut("wifi/simpleenroll", FakeEstServer.Answer(503, "unavailable\n"))
        assertEquals(Enroller.Outcome.RETRY, enroller().setup(link))

        val state = store.load()!!
        assertTrue(state.pendingWifiKeyAliases.isEmpty())
        assertTrue(state.oldWifiKeyAliases.isEmpty())
        assertTrue(wifi.installs.isEmpty())
    }

    @Test
    fun aFailedRequestDeletesTheNewKey() {
        issuingEverythingBut("wifi/simpleenroll", FakeEstServer.Answer(503, "unavailable\n"))
        assertEquals(Enroller.Outcome.RETRY, enroller().setup(link))

        val state = store.load()!!
        val created = wifiKeys.deleted.single()
        assertFalse(created in wifiKeys.keys)
        assertTrue(state.pendingWifiKeyAliases.isEmpty())
        assertTrue(state.oldWifiKeyAliases.isEmpty())
    }

    @Test
    fun aFailedGrantKeepsTheCurrentKeyAndDeletesTheNewOne() {
        val enroller = enroller()
        val first = setUpAndConfirmed(enroller)
        wifiKeys.grantFailure = IllegalStateException("Granting the key to Wi-Fi failed")
        assertEquals(Enroller.Outcome.LATER, enroller.maintain(renewWifi = true))

        val state = store.load()!!
        assertEquals(1, wifi.installs.size)
        assertEquals(first, state.wifiKeyAlias)
        val failed = wifiKeys.deleted.single()
        assertNotEquals(first, failed)
        assertTrue(state.pendingWifiKeyAliases.isEmpty())
        assertTrue(state.oldWifiKeyAliases.isEmpty())
    }

    @Test
    fun aRefusedSuggestionDeletesTheNewKey() {
        val enroller = enroller()
        val first = setUpAndConfirmed(enroller)
        wifi.installFailure = WifiInstallException("Wi-Fi didn't take the network")
        assertEquals(Enroller.Outcome.LATER, enroller.maintain(renewWifi = true))

        val state = store.load()!!
        assertEquals(first, state.wifiKeyAlias)
        val failed = wifiKeys.deleted.single()
        assertNotEquals(first, failed)
        assertFalse(failed in wifiKeys.keys)
        assertTrue(state.pendingWifiKeyAliases.isEmpty())
        assertTrue(state.oldWifiKeyAliases.isEmpty())
    }

    @Test
    fun aFailingScopeCheckUsesASoftwareKey() {
        wifiKeys.availableFailure = SecurityException("No device policy service")
        issuingEverything()
        assertEquals(Enroller.Outcome.OK, enroller().setup(link))

        assertTrue(wifi.installs.single().key is WifiKey.Imported)
        assertNull(store.load()!!.wifiKeyAlias)
        assertTrue(wifiKeys.created.isEmpty())
    }

    @Test
    fun stateJsonKeepsTheWifiKeyFields() {
        val state = EnrollmentState(
            "https://enroll.example.org", "ab".repeat(32), "device-1",
            listOf(TestPki.leaf(TestPki.root("Test Root"), "alice")),
            wifiKeyAlias = "wifi-current",
            pendingWifiKeyAliases = listOf("wifi-pending"),
            oldWifiKeyAliases = listOf("wifi-old-1", "wifi-old-2"),
        )
        assertEquals(state, EnrollmentState.fromJson(JSONObject(state.toJson().toString())))

        val legacy = state.toJson().apply {
            remove("wifi_key_alias")
            remove("pending_wifi_key_aliases")
            remove("old_wifi_key_aliases")
        }
        val parsed = EnrollmentState.fromJson(legacy)
        assertNull(parsed.wifiKeyAlias)
        assertTrue(parsed.pendingWifiKeyAliases.isEmpty())
        assertTrue(parsed.oldWifiKeyAliases.isEmpty())

        val nullAlias = JSONObject(state.toJson().toString()).put("wifi_key_alias", JSONObject.NULL)
        assertNull(EnrollmentState.fromJson(nullAlias).wifiKeyAlias)
    }
}
