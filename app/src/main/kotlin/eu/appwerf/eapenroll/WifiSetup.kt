package eu.appwerf.eapenroll

import android.net.wifi.WifiEnterpriseConfig
import android.net.wifi.WifiManager
import android.net.wifi.WifiNetworkSuggestion
import android.os.Build
import java.security.PrivateKey
import java.security.cert.X509Certificate

data class NetworkSettings(
    val ssid: String,
    val identity: String,
    val serverDomain: String,
    val wpa3: Boolean,
    val caCertificates: List<X509Certificate>,
)

object WifiSetup {
    /**
     * Builds an EAP-TLS suggestion that hands [privateKey] and [chain] to
     * Wi-Fi. Server validation needs both the CA certificates and the domain.
     * With [notifyOnConnect], Wi-Fi sends this app
     * `ACTION_WIFI_NETWORK_SUGGESTION_POST_CONNECTION` after connecting (if
     * the app may read scan results).
     */
    fun suggestion(
        settings: NetworkSettings,
        privateKey: PrivateKey,
        chain: List<X509Certificate>,
        notifyOnConnect: Boolean = false,
    ): WifiNetworkSuggestion {
        require(settings.ssid.isNotEmpty()) { "SSID is empty" }
        require(settings.identity.isNotEmpty()) { "Identity is empty" }
        require(settings.serverDomain.isNotEmpty()) { "Server domain is empty" }
        require(settings.caCertificates.isNotEmpty()) { "No CA certificate imported" }

        val enterprise = WifiEnterpriseConfig().apply {
            eapMethod = WifiEnterpriseConfig.Eap.TLS
            phase2Method = WifiEnterpriseConfig.Phase2.NONE
            identity = settings.identity
            caCertificates = settings.caCertificates.toTypedArray()
            domainSuffixMatch = settings.serverDomain
            setClientKeyEntryWithCertificateChain(privateKey, chain.toTypedArray())
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                // The default minimum is TLS 1.0. Settable from Android 14.
                minimumTlsVersion = WifiEnterpriseConfig.TLS_V1_2
            }
        }

        val builder = WifiNetworkSuggestion.Builder()
            .setSsid(settings.ssid)
            .setIsAppInteractionRequired(notifyOnConnect)
        if (settings.wpa3) {
            builder.setWpa3EnterpriseStandardModeConfig(enterprise)
        } else {
            builder.setWpa2EnterpriseConfig(enterprise)
        }
        return builder.build()
    }

    fun statusName(status: Int): String = when (status) {
        WifiManager.STATUS_NETWORK_SUGGESTIONS_SUCCESS -> "SUCCESS"
        WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_INTERNAL -> "ERROR_INTERNAL"
        WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_APP_DISALLOWED -> "ERROR_APP_DISALLOWED"
        WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_DUPLICATE -> "ERROR_ADD_DUPLICATE"
        WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_EXCEEDS_MAX_PER_APP ->
            "ERROR_ADD_EXCEEDS_MAX_PER_APP"
        WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID -> "ERROR_REMOVE_INVALID"
        WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_NOT_ALLOWED -> "ERROR_ADD_NOT_ALLOWED"
        WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_INVALID -> "ERROR_ADD_INVALID"
        WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_RESTRICTED_BY_ADMIN ->
            "ERROR_RESTRICTED_BY_ADMIN"
        else -> "status $status"
    }

    fun approvalName(status: Int): String = when (status) {
        WifiManager.STATUS_SUGGESTION_APPROVAL_UNKNOWN -> "UNKNOWN"
        WifiManager.STATUS_SUGGESTION_APPROVAL_PENDING -> "PENDING"
        WifiManager.STATUS_SUGGESTION_APPROVAL_APPROVED_BY_USER -> "APPROVED_BY_USER"
        WifiManager.STATUS_SUGGESTION_APPROVAL_REJECTED_BY_USER -> "REJECTED_BY_USER"
        WifiManager.STATUS_SUGGESTION_APPROVAL_APPROVED_BY_CARRIER_PRIVILEGE ->
            "APPROVED_BY_CARRIER_PRIVILEGE"
        else -> "status $status"
    }
}
