package com.vpnshare.tether

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

object VpnDetector {

    /** Check if VPN is active using system APIs. */
    fun isVpnActive(context: Context): Boolean {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val activeNetwork: Network? = cm.activeNetwork
            val caps = activeNetwork?.let { cm.getNetworkCapabilities(it) }
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        } else {
            @Suppress("DEPRECATION")
            NetworkUtils.isVpnActive()
        }
    }

    /** Check external IP (goes through VPN when active). Returns IP and country string. */
    suspend fun checkExternalIp(): String = withContext(Dispatchers.IO) {
        try {
            // Use multiple services for reliability
            val urls = listOf(
                "https://api.ipify.org",
                "https://ifconfig.me/ip",
                "https://ipinfo.io/ip",
                "https://api.my-ip.io/ip"
            )
            for (urlStr in urls) {
                try {
                    val url = URL(urlStr)
                    val conn = url.openConnection() as HttpURLConnection
                    conn.connectTimeout = 10000
                    conn.readTimeout = 10000
                    conn.setRequestProperty("User-Agent", "VpnShare/1.0")
                    conn.instanceFollowRedirects = true
                    val ip = conn.inputStream.bufferedReader().use { it.readText().trim() }
                    conn.disconnect()
                    if (ip.isNotEmpty() && ip.length < 50) {
                        // Try to get country info
                        val country = tryGetCountry(ip)
                        return@withContext if (country != null) "$ip ($country)" else ip
                    }
                } catch (_: Exception) { continue }
            }
            "Не удалось определить IP"
        } catch (e: Exception) {
            "Ошибка: ${e.message}"
        }
    }

    private fun tryGetCountry(ip: String): String? {
        return try {
            val url = URL("https://ipapi.co/$ip/country_name/")
            val conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.setRequestProperty("User-Agent", "VpnShare/1.0")
            val country = conn.inputStream.bufferedReader().use { it.readText().trim() }
            conn.disconnect()
            if (country.length in 2..50) country else null
        } catch (_: Exception) { null }
    }
}
