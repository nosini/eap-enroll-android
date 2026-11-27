package eu.appwerf.eapenroll

import java.security.MessageDigest
import java.security.cert.CertificateException
import java.util.Base64
import java.util.Date
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SetupUriTest {
    private val ca = "ab".repeat(32)
    private val code = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    @Test
    fun parsesServerOutput() {
        val link = SetupUri.parse(
            "eapenroll://setup?ca=$ca&code=$code&url=https%3A%2F%2Fenroll.example.org%3A8443&v=1\n",
        )
        assertEquals("https://enroll.example.org:8443", link.serverUrl)
        assertEquals(ca, link.caFingerprint)
        assertEquals(code, link.code)
        assertFalse(link.toString().contains(code))
    }

    @Test
    fun acceptsAnyOrderAndUpperCaseFingerprint() {
        val link = SetupUri.parse("eapenroll://setup?v=1&url=https://Enroll.Example.org/&code=$code&ca=${ca.uppercase()}")
        assertEquals("https://enroll.example.org", link.serverUrl)
        assertEquals(ca, link.caFingerprint)
    }

    @Test
    fun acceptsThePortsAtTheEdgesOfTheRange() {
        assertEquals("https://enroll.example.org:1", SetupUri.normalizeServerUrl("https://enroll.example.org:1"))
        assertEquals("https://enroll.example.org:65535", SetupUri.normalizeServerUrl("https://enroll.example.org:65535"))
        assertEquals("https://enroll.example.org", SetupUri.normalizeServerUrl("https://enroll.example.org"))
    }

    @Test
    fun malformedLinkDoesNotKeepTheCodeInTheCause() {
        // A space isn't allowed in a URI; URISyntaxException would quote
        // the whole link, code included.
        val e = assertThrows(IllegalArgumentException::class.java) {
            SetupUri.parse("eapenroll://setup?v=1&code=$code&url=https://enroll.example.org/a b")
        }
        assertNull(e.cause)
        assertFalse(e.message!!.contains(code))
    }

    @Test
    fun rejectsBadLinks() {
        val good = "ca=$ca&code=$code&url=https://enroll.example.org&v=1"
        for (bad in listOf(
            "https://setup?$good",
            "eapenroll://other?$good",
            "eapenroll://setup/path?$good",
            "eapenroll://setup?ca=$ca&code=$code&url=https://enroll.example.org&v=2",
            "eapenroll://setup?ca=$ca&code=$code&url=https://enroll.example.org",
            "eapenroll://setup?ca=$ca&code=$code&url=http://enroll.example.org&v=1",
            "eapenroll://setup?ca=$ca&code=$code&url=https://enroll.example.org/est&v=1",
            "eapenroll://setup?ca=$ca&code=$code&url=https://user@enroll.example.org&v=1",
            "eapenroll://setup?ca=$ca&code=$code&url=https://enroll.example.org:0&v=1",
            "eapenroll://setup?ca=$ca&code=$code&url=https://enroll.example.org:65536&v=1",
            "eapenroll://setup?ca=$ca&code=$code&url=https://enroll.example.org:99999&v=1",
            "eapenroll://setup?ca=abcd&code=$code&url=https://enroll.example.org&v=1",
            "eapenroll://setup?ca=$ca&code=${code.lowercase()}&url=https://enroll.example.org&v=1",
            "eapenroll://setup?ca=$ca&code=${code}A&url=https://enroll.example.org&v=1",
            "eapenroll://setup?$good&v=1",
        )) {
            assertThrows(bad, IllegalArgumentException::class.java) { SetupUri.parse(bad) }
        }
    }
}

class Pkcs7Test {
    private val root = TestPki.root("Test Root")
    private val ca = TestPki.intermediate(root, "Test CA")
    private val leaf = TestPki.leaf(ca, "alice")

    @Test
    fun readsCertsOnlyInOrder() {
        val certs = Pkcs7.certificates(TestPki.certsOnly(listOf(leaf, ca.cert, root.cert)))
        assertEquals(listOf(leaf, ca.cert, root.cert), certs)
    }

    @Test
    fun readsBase64WithLineBreaks() {
        val body = Base64.getMimeEncoder().encode(TestPki.certsOnly(listOf(leaf, ca.cert)))
        assertTrue(String(body).contains("\r\n"))
        assertEquals(listOf(leaf, ca.cert), Pkcs7.fromEstBody(body))
    }

    @Test
    fun rejectsMalformedData() {
        val good = TestPki.certsOnly(listOf(leaf))
        for (bad in listOf(
            good + byteArrayOf(0),
            good.copyOf(good.size - 1),
            TestPki.certsOnly(emptyList()),
            Der.sequence(Der.oid("1.2.840.113549.1.7.1"), Der.contextConstructed(0, Der.sequence())),
            leaf.encoded,
        )) {
            assertThrows(Exception::class.java) { Pkcs7.certificates(bad) }
        }
        assertThrows(IllegalArgumentException::class.java) { Pkcs7.fromEstBody("not base64!".toByteArray()) }
    }

    @Test
    fun derLengths() {
        val long = Der.tlv(0x04, ByteArray(300))
        assertEquals(300, Der.parse(long).content().size)
        // Long form for a short length isn't DER.
        assertThrows(IllegalArgumentException::class.java) { Der.parse(byteArrayOf(0x04, 0x81.toByte(), 0x01, 0x00)) }
        assertThrows(IllegalArgumentException::class.java) { Der.parse(byteArrayOf(0x30, 0x80.toByte(), 0x00, 0x00)) }
    }
}

class PinnedTrustTest {
    private val root = TestPki.root("Test TLS Root")
    private val ca = TestPki.intermediate(root, "Test TLS CA")
    private val server = TestPki.leaf(ca, "localhost", serverAuth = true)

    private fun fingerprint(der: ByteArray) = Hex.encode(MessageDigest.getInstance("SHA-256").digest(der))

    @Test
    fun trustsChainToPinnedCa() {
        EstTls.PinnedTrustManager(fingerprint(ca.cert.encoded)).checkServerTrusted(arrayOf(server, ca.cert), "ECDHE_ECDSA")
        EstTls.PinnedTrustManager(fingerprint(root.cert.encoded))
            .checkServerTrusted(arrayOf(server, ca.cert, root.cert), "ECDHE_ECDSA")
    }

    @Test
    fun rejectsOtherChains() {
        val other = TestPki.root("Other Root")
        assertThrows(CertificateException::class.java) {
            EstTls.PinnedTrustManager(fingerprint(other.cert.encoded)).checkServerTrusted(arrayOf(server, ca.cert), "ECDHE_ECDSA")
        }
        // The pinned certificate must be a CA, not the server's own certificate.
        assertThrows(CertificateException::class.java) {
            EstTls.PinnedTrustManager(fingerprint(server.encoded)).checkServerTrusted(arrayOf(server, ca.cert), "ECDHE_ECDSA")
        }
        // A leaf from another CA, with the pinned CA appended.
        val foreign = TestPki.leaf(other, "localhost", serverAuth = true)
        assertThrows(CertificateException::class.java) {
            EstTls.PinnedTrustManager(fingerprint(ca.cert.encoded)).checkServerTrusted(arrayOf(foreign, ca.cert), "ECDHE_ECDSA")
        }
    }
}

class CertsTest {
    private val ca = TestPki.root("Test CA")

    @Test
    fun renewalAndWarningTimes() {
        val day = 86_400_000L
        val start = System.currentTimeMillis() - day
        val cert = TestPki.leaf(ca, "alice", notBefore = Date(start), notAfter = Date(start + 60 * day))
        // Second precision in the certificate.
        val begin = cert.notBefore.time
        assertFalse(Certs.renewalDue(cert, begin + 39 * day))
        assertTrue(Certs.renewalDue(cert, begin + 40 * day))
        assertFalse(Certs.expiryWarning(cert, begin + 49 * day))
        assertTrue(Certs.expiryWarning(cert, begin + 50 * day))
    }

    @Test
    fun checksEveryLinkOfAChain() {
        val intermediate = TestPki.intermediate(ca, "Test Intermediate")
        val leaf = TestPki.leaf(intermediate, "alice")
        Certs.checkChain(listOf(leaf, intermediate.cert, ca.cert))
        Certs.checkChain(listOf(leaf))
        // Same name, other key: the intermediate's signature doesn't verify.
        val impostor = TestPki.root("Test CA")
        assertThrows(java.security.SignatureException::class.java) {
            Certs.checkChain(listOf(leaf, intermediate.cert, impostor.cert))
        }
        assertThrows(IllegalStateException::class.java) { Certs.checkChain(listOf(leaf, ca.cert)) }
        assertThrows(IllegalStateException::class.java) { Certs.checkChain(listOf(leaf, ca.cert, intermediate.cert)) }
    }

    @Test
    fun commonNameAsItIs() {
        for (name in listOf("alice", "alice+phone@example.org", "Doe, Alice", "a\\b;c\"d<e>", "#hash", " spaced ", "Zoë")) {
            assertEquals(name, Certs.commonName(TestPki.leaf(ca, name)))
        }
        // Not a UTF8String: BMPString and PrintableString.
        fun cn(tag: Int, value: ByteArray) = Der.set(Der.sequence(Der.oid("2.5.4.3"), Der.tlv(tag, value)))
        val organization = Der.set(Der.sequence(Der.oid("2.5.4.10"), Der.tlv(0x13, "Example".toByteArray())))
        val bmp = TestPki.leaf(ca, "x", subject = Der.sequence(cn(0x1e, "Zoë".toByteArray(Charsets.UTF_16BE))))
        assertEquals("Zoë", Certs.commonName(bmp))
        val printable = TestPki.leaf(ca, "x", subject = Der.sequence(organization, cn(0x13, "alice".toByteArray())))
        assertEquals("alice", Certs.commonName(printable))
        assertEquals("", Certs.commonName(TestPki.leaf(ca, "x", subject = Der.sequence(organization))))
    }

    @Test
    fun dropsRootsForWifi() {
        val intermediate = TestPki.intermediate(ca, "Test Intermediate")
        val leaf = TestPki.leaf(intermediate, "alice")
        assertEquals(listOf(leaf, intermediate.cert), Certs.withoutRoots(listOf(leaf, intermediate.cert, ca.cert)))
        assertEquals("alice", Certs.commonName(leaf))
    }
}

class StateJsonTest {
    @Test
    fun roundTrip() {
        val root = TestPki.root("Test Root")
        val device = TestPki.leaf(root, "alice")
        val wifi = TestPki.leaf(root, "alice")
        val state = EnrollmentState(
            serverUrl = "https://enroll.example.org",
            caFingerprint = "ab".repeat(32),
            deviceAlias = "device-1",
            deviceChain = listOf(device, root.cert),
            previousDeviceAlias = "device-0",
            profile = WifiProfile("Example Net ", "radius.example.org", listOf(root.cert)),
            wifiChain = listOf(wifi, root.cert),
            wifiInstalledAt = 1234,
            wifiInstalledElapsed = 789,
            wifiInstalledBoot = 7,
            confirmPending = true,
            connectedAfterInstall = true,
            problem = Problem.USER_DISABLED,
            waitUntil = 3456,
            lastError = "HTTP 403: disabled",
            lastErrorAt = 5678,
            lastSuccessAt = 9012,
        )
        assertEquals(state, EnrollmentState.fromJson(JSONObject(state.toJson().toString())))

        val minimal = EnrollmentState("https://enroll.example.org", "ab".repeat(32), "device-1", listOf(device))
        val parsed = EnrollmentState.fromJson(JSONObject(minimal.toJson().toString()))
        assertEquals(minimal, parsed)
        assertNull(parsed.profile)
    }

    @Test
    fun stateWithoutTheInstallElapsedTimeMeansZero() {
        val root = TestPki.root("Test Root")
        val state = EnrollmentState(
            "https://enroll.example.org", "ab".repeat(32), "device-1", listOf(TestPki.leaf(root, "alice")),
            wifiInstalledAt = 1234, wifiInstalledElapsed = 789, wifiInstalledBoot = 7,
        )
        val json = state.toJson()
        json.remove("wifi_installed_elapsed")
        json.remove("wifi_installed_boot")
        val parsed = EnrollmentState.fromJson(json)
        assertEquals(0, parsed.wifiInstalledElapsed)
        assertEquals(0, parsed.wifiInstalledBoot)
    }

    @Test
    fun profileFromServerJson() {
        val root = TestPki.root("Test Root")
        val json = """{"ssid":" Example Net ","server_domain":"radius.example.org",
            "server_ca_certificates":["${Base64.getEncoder().encodeToString(root.cert.encoded)}"]}"""
        val profile = Profiles.parse(json.toByteArray())
        assertEquals(" Example Net ", profile.ssid)
        assertEquals(listOf(root.cert), profile.serverCaCertificates)

        val leaf = TestPki.leaf(root, "radius")
        val notCa = json.replace(Base64.getEncoder().encodeToString(root.cert.encoded), Base64.getEncoder().encodeToString(leaf.encoded))
        assertThrows(IllegalArgumentException::class.java) { Profiles.parse(notCa.toByteArray()) }
    }

    @Test
    fun profileWithWrongTypesIsRejected() {
        val ca = "\"${Base64.getEncoder().encodeToString(TestPki.root("Test Root").cert.encoded)}\""
        fun profile(ssid: String = "\"Example Net\"", domain: String = "\"radius.example.org\"", cas: String = "[$ca]") =
            """{"ssid":$ssid,"server_domain":$domain,"server_ca_certificates":$cas}"""
        for (bad in listOf(
            profile(ssid = "null"),
            profile(ssid = "12345"),
            profile(domain = "null"),
            profile(domain = "true"),
            profile(cas = "null"),
            profile(cas = ca),
            profile(cas = "[null]"),
            profile(cas = "[42]"),
            profile(cas = "[\"\"]"),
            profile(cas = "[\"not base64!\"]"),
            profile(cas = "[\"${Base64.getEncoder().encodeToString(ByteArray(16) { 1 })}\"]"),
            """{"ssid":"Example Net","server_domain":"radius.example.org"}""",
            "<html>Bad Gateway</html>",
            "[]",
            "",
        )) {
            assertThrows(bad, IllegalArgumentException::class.java) { Profiles.parse(bad.toByteArray()) }
        }
        Profiles.parse(profile().toByteArray())
    }
}
