package com.vpnshare.tether

import java.net.*
import java.util.*

object NetworkUtils {

    /** Known USB-tethering interface name prefixes. */
    private val USB_IFACE_PATTERNS = listOf(
        "rndis",  // older Android
        "ncm",    // newer Android (NCM)
        "usb",    // generic usb
        "ecm",    // CDC ECM
        "tap",    // sometimes used
        "dummy"   // sometimes used for tethering
    )

    /** Subnets commonly used by Android USB tethering. */
    private val USB_SUBNETS = listOf(
        "192.168.42.",  // classic
        "192.168.43.",  // some devices
        "192.168.137.", // Windows ICS-like (not typical for android->pc, but check)
        "10.0.0.",
        "172.20.10."
    )

    data class BindAddress(val ip: String, val interfaceName: String)

    /**
     * Detect the IP address of the USB-tethering interface and 127.0.0.1.
     * @return list of BindAddress to listen on.
     */
    fun getListenAddresses(): List<BindAddress> {
        val result = mutableListOf<BindAddress>()
        // Always listen on localhost
        result.add(BindAddress("127.0.0.1", "lo"))

        try {
            val ifaces: Enumeration<NetworkInterface> = NetworkInterface.getNetworkInterfaces()
                    ?: return result
            for (iface in ifaces) {
                if (!iface.isUp) continue
                if (iface.isLoopback) continue
                val name = iface.name.lowercase()
                val displayName = iface.displayName.lowercase()

                // Check if this is a USB tethering interface by name
                val isUsbByName = USB_IFACE_PATTERNS.any { name.startsWith(it) || displayName.contains(it) }

                // Check addresses
                for (addr in iface.interfaceAddresses) {
                    val ip = addr.address ?: continue
                    if (ip !is Inet4Address) continue
                    if (ip.isLoopbackAddress) continue
                    if (ip.isMulticastAddress) continue
                    val ipStr = ip.hostAddress ?: continue

                    // Skip VPN interfaces (usually have /32 or point-to-point)
                    if (iface.isPointToPoint) continue

                    val isUsbSubnet = USB_SUBNETS.any { ipStr.startsWith(it) }

                    if (isUsbByName || isUsbSubnet) {
                        result.add(BindAddress(ipStr, iface.name))
                    }
                }
            }
        } catch (_: Exception) {}

        return result
    }

    /** Get the USB IP to show to the user (the phone's IP on the USB network). */
    fun getUsbIp(): String? {
        return getListenAddresses().firstOrNull { it.ip != "127.0.0.1" }?.ip
    }

    /** Check if a client IP comes from localhost or the USB subnet. */
    fun isAllowedClient(clientIp: String): Boolean {
        if (clientIp == "127.0.0.1" || clientIp == "localhost" || clientIp.startsWith("::1")) return true
        return USB_SUBNETS.any { clientIp.startsWith(it) }
    }

    /** Resolve a hostname to an IP (uses system DNS, which goes through VPN). */
    fun resolve(host: String): InetAddress {
        return InetAddress.getByName(host)
    }

    /** Check if any VPN interface is present/active. */
    fun isVpnActive(): Boolean {
        try {
            val ifaces: Enumeration<NetworkInterface> = NetworkInterface.getNetworkInterfaces()
                    ?: return false
            for (iface in ifaces) {
                if (!iface.isUp) continue
                val name = iface.name.lowercase()
                // Common VPN interface names on Android:
                // tun0, ppp0, cmtun, tap0, xgm_tun, v4-wlan0 etc.
                if (name.startsWith("tun") || name.startsWith("ppp") || name.startsWith("vpn")
                    || name.startsWith("clash") || name.startsWith("tun0")) {
                    // Also check it's not a docker/other tun - heuristic: has point-to-point or no MAC
                    if (iface.isPointToPoint || iface.hardwareAddress == null) {
                        return true
                    }
                    // Check for IPv4 addresses on the interface
                    for (addr in iface.interfaceAddresses) {
                        if (addr.address is Inet4Address && !addr.address.isLoopbackAddress) {
                            return true
                        }
                    }
                }
            }
        } catch (_: Exception) {}
        return false
    }
}
