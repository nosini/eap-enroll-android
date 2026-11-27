package eu.appwerf.eapenroll

import java.net.InetAddress
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.util.Date
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlin.concurrent.thread
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class PinnedAnchorTest {
    private val hour = 3_600_000L
    private val now = System.currentTimeMillis()

    private fun pin(issuer: TestPki.Issuer) = EstTls.PinnedTrustManager(Hex.encode(sha256(issuer.cert.encoded)))

    @Test
    fun rejectsAPinnedCaOutsideItsValidity() {
        val expired = TestPki.root("Expired CA", notBefore = Date(now - 2 * hour), notAfter = Date(now - hour))
        val server = TestPki.leaf(expired, "localhost", serverAuth = true)
        assertThrows(CertificateExpiredException::class.java) {
            pin(expired).checkServerTrusted(arrayOf(server, expired.cert), "ECDHE_ECDSA")
        }
        val future = TestPki.root("Future CA", notBefore = Date(now + hour), notAfter = Date(now + 2 * hour))
        val early = TestPki.leaf(future, "localhost", serverAuth = true)
        assertThrows(CertificateNotYetValidException::class.java) {
            pin(future).checkServerTrusted(arrayOf(early, future.cert), "ECDHE_ECDSA")
        }
    }

    @Test
    fun rejectsTheCaAsTheServersCertificate() {
        val ca = TestPki.root("Pinned CA")
        assertThrows(CertificateException::class.java) { pin(ca).checkServerTrusted(arrayOf(ca.cert), "ECDHE_ECDSA") }
        val intermediate = TestPki.intermediate(ca, "Intermediate CA")
        assertThrows(CertificateException::class.java) {
            pin(ca).checkServerTrusted(arrayOf(intermediate.cert, ca.cert), "ECDHE_ECDSA")
        }
    }
}

class HostnamesTest {
    private val ca = TestPki.root("Test CA")

    private fun cert(vararg names: String) = TestPki.leaf(ca, "server", serverAuth = true, altNames = names.toList())

    @Test
    fun matchesHostNames() {
        val cert = cert("enroll.example.org", "*.wild.example.org")
        assertTrue(Hostnames.matches("enroll.example.org", cert))
        assertTrue(Hostnames.matches("Enroll.Example.ORG", cert))
        assertTrue(Hostnames.matches("enroll.example.org.", cert))
        assertTrue(Hostnames.matches("a.wild.example.org", cert))
        assertFalse(Hostnames.matches("other.example.org", cert))
        assertFalse(Hostnames.matches("example.org", cert))
        // A wildcard covers exactly one label.
        assertFalse(Hostnames.matches("wild.example.org", cert))
        assertFalse(Hostnames.matches("a.b.wild.example.org", cert))
    }

    @Test
    fun rejectsBroadOrPartialWildcards() {
        assertFalse(Hostnames.matches("example.org", cert("*.org")))
        assertFalse(Hostnames.matches("enroll.example.org", cert("e*.example.org")))
        assertFalse(Hostnames.matches("enroll.example.org", cert("*.*.org")))
    }

    @Test
    fun matchesIpAddressesOnlyAgainstIpNames() {
        val cert = cert("192.0.2.10", "2001:db8::1", "198.51.100.7.example.org")
        assertTrue(Hostnames.matches("192.0.2.10", cert))
        assertTrue(Hostnames.matches("2001:db8:0:0:0:0:0:1", cert))
        assertTrue(Hostnames.matches("[2001:db8::1]", cert))
        assertFalse(Hostnames.matches("192.0.2.11", cert))
        assertFalse(Hostnames.matches("198.51.100.7", cert))
        // A host name doesn't match an address.
        assertFalse(Hostnames.matches("enroll.example.org", cert("192.0.2.10")))
    }

    @Test
    fun ignoresTheCommonName() {
        val noNames = TestPki.leaf(ca, "enroll.example.org")
        assertFalse(Hostnames.matches("enroll.example.org", noNames))
    }
}

/** Handshakes against local servers. */
class EstTlsConnectionTest {
    private val ca = TestPki.root("Test EST CA")

    /** A server for "localhost" that accepts one connection with [protocols] and completes the handshake. */
    private fun server(vararg protocols: String): SSLServerSocket {
        val keys = TestPki.keyPair()
        val leaf = TestPki.leaf(ca, "localhost", keys, serverAuth = true)
        val store = KeyStore.getInstance("PKCS12").apply {
            load(null)
            setKeyEntry("server", keys.private, CharArray(0), arrayOf(leaf, ca.cert))
        }
        val keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            .apply { init(store, CharArray(0)) }.keyManagers
        val context = SSLContext.getInstance("TLS").apply { init(keyManagers, null, null) }
        val socket = context.serverSocketFactory.createServerSocket(0, 1, InetAddress.getLoopbackAddress()) as SSLServerSocket
        socket.enabledProtocols = arrayOf(*protocols)
        thread(isDaemon = true) {
            runCatching { (socket.accept() as SSLSocket).use { it.startHandshake() } }
        }
        return socket
    }

    private fun connect(server: SSLServerSocket): SSLSocket {
        val sockets = EstTls.socketFactory(EstTls.context(Hex.encode(sha256(ca.cert.encoded)), null))
        return (sockets.createSocket("localhost", server.localPort) as SSLSocket).apply { startHandshake() }
    }

    @Test
    fun speaksTls13Only() {
        server("TLSv1.3", "TLSv1.2").use { server ->
            connect(server).use { assertEquals("TLSv1.3", it.session.protocol) }
        }
        server("TLSv1.2").use { server ->
            assertThrows(SSLException::class.java) { connect(server).close() }
        }
    }

    @Test
    fun sendsTheCredentialOnlyToTheRightHost() {
        val keys = MemoryKeys()
        val alias = keys.create()
        for ((name, works) in listOf("localhost" to true, "other.example.org" to false)) {
            FakeEstServer(hostName = name).use { server ->
                val credential = TestPki.leaf(server.deviceCa, "alice", keys.keyPair(alias))
                server.answer = { FakeEstServer.Answer(404) }
                val client = EstClient(server.url, server.caFingerprint, ClientCredential(keys.keyPair(alias).private, listOf(credential)))
                val result = runCatching { client.wifiProfile() }
                assertEquals(name, works, result.isSuccess)
                // A server whose certificate is for another name never sees the credential.
                assertEquals(name, if (works) listOf(credential) else emptyList(), server.handshakeClientCertificates.distinct())
                assertEquals(name, works, server.requests.isNotEmpty())
            }
        }
    }

    /** The fake server, like the real one, refuses a client certificate it can't verify in the handshake. */
    @Test
    fun credentialIsCheckedInTheHandshake() {
        val keys = MemoryKeys()
        val alias = keys.create()
        val now = System.currentTimeMillis()
        val hour = 3_600_000L
        FakeEstServer().use { server ->
            server.answer = { FakeEstServer.Answer(404) }
            for ((label, credential, works) in listOf(
                Triple("valid", TestPki.leaf(server.deviceCa, "alice", keys.keyPair(alias)), true),
                Triple("expired", TestPki.leaf(server.deviceCa, "alice", keys.keyPair(alias), Date(now - 2 * hour), Date(now - hour)), false),
                Triple("other CA", TestPki.leaf(TestPki.root("Fake Device CA"), "alice", keys.keyPair(alias)), false),
            )) {
                server.requests.clear()
                val client = EstClient(server.url, server.caFingerprint, ClientCredential(keys.keyPair(alias).private, listOf(credential)))
                val result = runCatching { client.wifiProfile() }
                assertEquals(label, works, result.isSuccess)
                assertEquals(label, works, server.requests.isNotEmpty())
            }
        }
    }
}
