package com.vpnshare.tether

import android.util.Log
import kotlinx.coroutines.*
import kotlin.coroutines.currentCoroutineContext
import java.io.*
import java.net.*

/**
 * SOCKS5 proxy server with CONNECT (TCP) and UDP ASSOCIATE support.
 */
class Socks5Proxy(private val port: Int) {

    companion object {
        private const val TAG = "Socks5Proxy"
        private const val BUF_SIZE = 32768

        private const val SOCKS5 = 0x05
        private const val AUTH_NONE = 0x00
        private const val CMD_CONNECT = 0x01
        private const val CMD_UDP_ASSOCIATE = 0x03
        private const val ATYP_IPV4 = 0x01
        private const val ATYP_DOMAIN = 0x03
        private const val ATYP_IPV6 = 0x04

        private const val REP_SUCCEEDED = 0x00
        private const val REP_GENERAL_FAILURE = 0x01
        private const val REP_CONN_REFUSED = 0x05
        private const val REP_TTL_EXPIRED = 0x06
        private const val REP_CMD_NOT_SUPPORTED = 0x07
        private const val REP_ATYP_NOT_SUPPORTED = 0x08
    }

    private var serverSocket: ServerSocket? = null
    private var acceptJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    @Volatile
    var running = false
        private set

    private var udpSocket: DatagramSocket? = null
    private var udpJob: Job? = null

    private val udpClients = java.util.Collections.synchronizedMap(mutableMapOf<String, UdpClientState>())

    private data class UdpClientState(
        val clientAddr: InetAddress,
        @Volatile var replyPort: Int,
        val remoteSockets: MutableMap<String, DatagramSocket> = mutableMapOf(),
        @Volatile var active: Boolean = true
    )

    fun start() {
        if (running) return
        running = true
        val addrs = NetworkUtils.getListenAddresses()
        for (ba in addrs) {
            try {
                val addr = InetAddress.getByName(ba.ip)
                val ss = ServerSocket(port, 50, addr)
                serverSocket = ss
                Log.i(TAG, "SOCKS5 listening on ${ba.ip}:$port (${ba.interfaceName})")
                acceptLoop(ss)
                break
            } catch (e: Exception) {
                Log.w(TAG, "Cannot bind to ${ba.ip}:$port: ${e.message}")
            }
        }
        if (serverSocket == null) {
            try {
                val ss = ServerSocket(port, 50)
                serverSocket = ss
                Log.i(TAG, "SOCKS5 listening on 0.0.0.0:$port (fallback)")
                acceptLoop(ss)
            } catch (e: Exception) {
                running = false
                throw e
            }
        }
    }

    private fun acceptLoop(ss: ServerSocket) {
        acceptJob = scope.launch {
            while (isActive && running) {
                try {
                    val client = withContext(Dispatchers.IO) { ss.accept() }
                    val clientIp = (client.inetAddress.hostAddress ?: "")
                    if (!NetworkUtils.isAllowedClient(clientIp)) {
                        withContext(Dispatchers.IO) { try { client.close() } catch (_: Exception) {} }
                        continue
                    }
                    client.soTimeout = 120000
                    client.tcpNoDelay = true
                    handleClient(client)
                } catch (_: SocketTimeoutException) {
                } catch (e: Exception) {
                    if (running) Log.e(TAG, "Accept error: ${e.message}")
                }
            }
        }
    }

    private fun handleClient(client: Socket) {
        scope.launch {
            var clientIPStr = ""
            try {
                val input = client.getInputStream().buffered()
                val output = client.getOutputStream()

                val ver = input.read()
                if (ver != SOCKS5) { client.close(); return@launch }
                val nmethods = input.read()
                if (nmethods < 1) { client.close(); return@launch }
                val methods = ByteArray(nmethods)
                readFully(input, methods)
                if (methods.find { it.toInt() == AUTH_NONE } == null) {
                    output.write(byteArrayOf(SOCKS5.toByte(), 0xFF.toByte()))
                    client.close(); return@launch
                }
                output.write(byteArrayOf(SOCKS5.toByte(), AUTH_NONE.toByte()))

                val reqVer = input.read()
                if (reqVer != SOCKS5) { client.close(); return@launch }
                val cmd = input.read()
                input.read()
                val atyp = input.read()

                val destAddr: InetAddress
                when (atyp) {
                    ATYP_IPV4 -> {
                        val ip = ByteArray(4); readFully(input, ip)
                        destAddr = InetAddress.getByAddress(ip)
                    }
                    ATYP_DOMAIN -> {
                        val len = input.read()
                        if (len < 1) { client.close(); return@launch }
                        val domain = ByteArray(len); readFully(input, domain)
                        destAddr = NetworkUtils.resolve(String(domain))
                    }
                    ATYP_IPV6 -> {
                        val ip = ByteArray(16); readFully(input, ip)
                        destAddr = InetAddress.getByAddress(ip)
                    }
                    else -> { sendReply(client, REP_ATYP_NOT_SUPPORTED); client.close(); return@launch }
                }
                val ph = input.read(); val pl = input.read()
                val destPort = (ph shl 8) or pl
                val dest = InetSocketAddress(destAddr, destPort)

                when (cmd) {
                    CMD_CONNECT -> handleConnect(client, input, output, dest)
                    CMD_UDP_ASSOCIATE -> {
                        clientIPStr = client.inetAddress.hostAddress ?: ""
                        handleUdpAssociate(client, output, client.inetAddress)
                        val buf = ByteArray(1)
                        try {
                            while (client.isConnected && !client.isClosed) {
                                val n = withContext(Dispatchers.IO) {
                                    try { input.read(buf) } catch (_: Exception) { -1 }
                                }
                                if (n <= 0) break
                            }
                        } catch (_: Exception) {}
                    }
                    else -> { sendReply(client, REP_CMD_NOT_SUPPORTED); client.close() }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Client handler: ${e.message}")
            } finally {
                if (clientIPStr.isNotEmpty()) {
                    synchronized(udpClients) {
                        val state = udpClients.remove(clientIPStr)
                        state?.let {
                            it.active = false
                            it.remoteSockets.values.forEach { s -> try { s.close() } catch (_: Exception) {} }
                        }
                    }
                }
                withContext(Dispatchers.IO) { try { client.close() } catch (_: Exception) {} }
                maybeStopUdpRelay()
            }
        }
    }

    private fun handleConnect(client: Socket, cin: InputStream, cout: OutputStream, dest: InetSocketAddress) {
        scope.launch {
            var remote: Socket? = null
            try {
                remote = Socket()
                remote.tcpNoDelay = true
                withContext(Dispatchers.IO) { remote.connect(dest, 30000) }
                sendReply(client, REP_SUCCEEDED, remote.localSocketAddress as? InetSocketAddress)
                val rin = remote.getInputStream().buffered()
                val rout = remote.getOutputStream()
                val c2r = launch { relay(cin, rout) }
                val r2c = launch { relay(rin, cout) }
                c2r.join()
                r2c.cancelAndJoin()
            } catch (e: ConnectException) { sendReply(client, REP_CONN_REFUSED) }
            catch (e: SocketTimeoutException) { sendReply(client, REP_TTL_EXPIRED) }
            catch (e: Exception) {
                Log.w(TAG, "CONNECT to ${dest.hostName}:${dest.port}: ${e.message}")
                sendReply(client, REP_GENERAL_FAILURE)
            } finally {
                withContext(Dispatchers.IO) { try { remote?.close() } catch (_: Exception) {} }
                withContext(Dispatchers.IO) { try { client.close() } catch (_: Exception) {} }
            }
        }
    }

    private suspend fun relay(src: InputStream, dst: OutputStream) {
        val buf = ByteArray(BUF_SIZE)
        try {
            while (currentCoroutineContext().isActive) {
                val n = withContext(Dispatchers.IO) {
                    try { src.read(buf) } catch (_: Exception) { -1 }
                }
                if (n <= 0) break
                withContext(Dispatchers.IO) {
                    try { dst.write(buf, 0, n); dst.flush() } catch (_: Exception) {}
                }
            }
        } catch (_: Exception) {}
    }

    private fun handleUdpAssociate(client: Socket, cout: OutputStream, clientAddr: InetAddress) {
        try {
            synchronized(udpClients) {
                if (udpSocket == null || udpSocket!!.isClosed) {
                    udpSocket = DatagramSocket(0)
                    udpSocket!!.soTimeout = 1000
                    startUdpRelay(udpSocket!!)
                }
            }

            val udpPort = udpSocket!!.localPort
            val clientIPStr = clientAddr.hostAddress ?: return

            synchronized(udpClients) {
                val old = udpClients[clientIPStr]
                old?.let {
                    it.active = false
                    it.remoteSockets.values.forEach { s -> try { s.close() } catch (_: Exception) {} }
                }
                udpClients[clientIPStr] = UdpClientState(
                    clientAddr = clientAddr,
                    replyPort = 0,
                    active = true
                )
            }

            val bindAddr = InetSocketAddress(clientAddr, udpPort)
            sendReply(client, REP_SUCCEEDED, bindAddr)
            Log.i(TAG, "UDP ASSOCIATE: client=$clientIPStr, UDP port=$udpPort")
        } catch (e: Exception) {
            Log.e(TAG, "UDP ASSOCIATE: ${e.message}")
            sendReply(client, REP_GENERAL_FAILURE)
        }
    }

    private fun startUdpRelay(udp: DatagramSocket) {
        udpJob?.cancel()
        udpJob = scope.launch(Dispatchers.IO) {
            val buf = ByteArray(BUF_SIZE)
            while (isActive && running) {
                try {
                    val dg = DatagramPacket(buf, buf.size)
                    udp.soTimeout = 1000
                    udp.receive(dg)
                    val data = dg.data.copyOfRange(dg.offset, dg.offset + dg.length)
                    val fromIP = dg.address.hostAddress ?: continue

                    val clientState = synchronized(udpClients) { udpClients[fromIP] }
                    if (clientState != null && clientState.active) {
                        // Update client's reply port from actual packet
                        if (clientState.replyPort == 0) {
                            clientState.replyPort = dg.port
                        } else if (clientState.replyPort != dg.port) {
                            clientState.replyPort = dg.port
                        }
                        handleUdpClientPacket(udp, data, clientState)
                    }
                    // If not from a known client IP, drop it (responses come back on per-target sockets)
                } catch (_: SocketTimeoutException) {
                    cleanupInactiveClients()
                } catch (e: Exception) {
                    if (isActive && running) Log.w(TAG, "UDP relay: ${e.message}")
                }
            }
        }
    }

    private fun handleUdpClientPacket(udp: DatagramSocket, data: ByteArray, state: UdpClientState) {
        if (data.size < 4) return
        val frag = data[2].toInt() and 0xFF
        if (frag != 0) return

        val atyp = data[3].toInt() and 0xFF
        var pos = 4
        val targetAddr: InetAddress
        when (atyp) {
            ATYP_IPV4 -> {
                if (data.size < pos + 4 + 2) return
                val ip = data.copyOfRange(pos, pos + 4); pos += 4
                targetAddr = InetAddress.getByAddress(ip)
            }
            ATYP_DOMAIN -> {
                if (data.size < pos + 1) return
                val len = data[pos].toInt() and 0xFF; pos++
                if (data.size < pos + len + 2) return
                val dom = data.copyOfRange(pos, pos + len); pos += len
                targetAddr = try { NetworkUtils.resolve(String(dom)) } catch (_: Exception) { return }
            }
            ATYP_IPV6 -> {
                if (data.size < pos + 16 + 2) return
                val ip = data.copyOfRange(pos, pos + 16); pos += 16
                targetAddr = InetAddress.getByAddress(ip)
            }
            else -> return
        }
        val portHigh = data[pos].toInt() and 0xFF; pos++
        val portLow = data[pos].toInt() and 0xFF; pos++
        val targetPort = (portHigh shl 8) or portLow
        val payload = data.copyOfRange(pos, data.size)
        val target = InetSocketAddress(targetAddr, targetPort)
        val targetKey = "${targetAddr.hostAddress}:$targetPort"

        // Get or create per-target socket
        var rs: DatagramSocket?
        var isNew = false
        synchronized(state.remoteSockets) {
            rs = state.remoteSockets[targetKey]
            if (rs == null) {
                try {
                    val sock = DatagramSocket()
                    sock.soTimeout = 60000
                    rs = sock
                    state.remoteSockets[targetKey] = sock
                    isNew = true
                } catch (e: Exception) {
                    Log.w(TAG, "UDP create socket for $targetKey: ${e.message}")
                    return
                }
            }
        }
        val remoteSocket = rs ?: return

        // Send payload to target
        try {
            val outDg = DatagramPacket(payload, payload.size, target)
            remoteSocket.send(outDg)
        } catch (e: Exception) {
            synchronized(state.remoteSockets) {
                state.remoteSockets.remove(targetKey)?.close()
            }
            return
        }

        // Start receive loop for this remote socket (only once)
        if (isNew) {
            val udpRef = udp
            val stateRef = state
            val keyRef = targetKey
            scope.launch(Dispatchers.IO) {
                val rbuf = ByteArray(BUF_SIZE)
                try {
                    while (isActive && stateRef.active) {
                        remoteSocket.soTimeout = 5000
                        val rdg = DatagramPacket(rbuf, rbuf.size)
                        try { remoteSocket.receive(rdg) } catch (_: SocketTimeoutException) {
                            if (!stateRef.active) break
                            continue
                        } catch (_: Exception) { break }

                        // Build SOCKS5 UDP reply
                        val fromBytes = rdg.address.address
                        val isV4 = rdg.address is Inet4Address
                        val atypByte = if (isV4) ATYP_IPV4 else ATYP_IPV6
                        val addrLen = fromBytes.size
                        val replyHeader = ByteArray(4 + addrLen + 2)
                        replyHeader[0] = 0; replyHeader[1] = 0; replyHeader[2] = 0
                        replyHeader[3] = atypByte.toByte()
                        System.arraycopy(fromBytes, 0, replyHeader, 4, addrLen)
                        replyHeader[4 + addrLen] = ((rdg.port shr 8) and 0xFF).toByte()
                        replyHeader[4 + addrLen + 1] = (rdg.port and 0xFF).toByte()
                        val reply = ByteArray(replyHeader.size + rdg.length)
                        System.arraycopy(replyHeader, 0, reply, 0, replyHeader.size)
                        System.arraycopy(rbuf, rdg.offset, reply, replyHeader.size, rdg.length)

                        val dest = InetSocketAddress(stateRef.clientAddr, stateRef.replyPort)
                        val replyDg = DatagramPacket(reply, reply.size, dest)
                        try { udpRef.send(replyDg) } catch (_: Exception) { break }
                    }
                } finally {
                    try { remoteSocket.close() } catch (_: Exception) {}
                    synchronized(stateRef.remoteSockets) { stateRef.remoteSockets.remove(keyRef) }
                }
            }
        }
    }

    private fun cleanupInactiveClients() {
        synchronized(udpClients) {
            val iter = udpClients.values.iterator()
            while (iter.hasNext()) {
                val cs = iter.next()
                if (!cs.active) {
                    cs.remoteSockets.values.forEach { try { it.close() } catch (_: Exception) {} }
                    cs.remoteSockets.clear()
                    iter.remove()
                }
            }
        }
    }

    private fun maybeStopUdpRelay() {
        synchronized(udpClients) {
            if (udpClients.isEmpty()) {
                udpJob?.cancel()
                udpJob = null
                try { udpSocket?.close() } catch (_: Exception) {}
                udpSocket = null
            }
        }
    }

    private fun sendReply(client: Socket, rep: Int, bindAddr: InetSocketAddress? = null) {
        try {
            val ba = bindAddr ?: InetSocketAddress("0.0.0.0", 0)
            val addrBytes = ba.address?.address ?: byteArrayOf(0, 0, 0, 0)
            val actualAddrBytes = when {
                addrBytes.size == 4 -> addrBytes
                addrBytes.size == 16 -> addrBytes
                else -> byteArrayOf(0, 0, 0, 0)
            }
            val actualAtyp = if (actualAddrBytes.size == 16) ATYP_IPV6 else ATYP_IPV4
            val reply = ByteArray(6 + actualAddrBytes.size)
            reply[0] = SOCKS5.toByte()
            reply[1] = rep.toByte()
            reply[2] = 0
            reply[3] = actualAtyp.toByte()
            System.arraycopy(actualAddrBytes, 0, reply, 4, actualAddrBytes.size)
            reply[4 + actualAddrBytes.size] = ((ba.port shr 8) and 0xFF).toByte()
            reply[4 + actualAddrBytes.size + 1] = (ba.port and 0xFF).toByte()
            client.getOutputStream().write(reply)
            client.getOutputStream().flush()
        } catch (_: Exception) {}
    }

    private fun readFully(stream: InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = stream.read(buf, off, buf.size - off)
            if (n < 0) throw EOFException("Unexpected end of SOCKS5 handshake")
            off += n
        }
    }

    fun stop() {
        running = false
        acceptJob?.cancel()
        udpJob?.cancel()
        scope.cancel()
        synchronized(udpClients) {
            for (cs in udpClients.values) {
                cs.active = false
                cs.remoteSockets.values.forEach { try { it.close() } catch (_: Exception) {} }
            }
            udpClients.clear()
        }
        try { udpSocket?.close() } catch (_: Exception) {}
        udpSocket = null
        try { serverSocket?.close() } catch (_: Exception) {}
        serverSocket = null
        Log.i(TAG, "SOCKS5 stopped")
    }
}
