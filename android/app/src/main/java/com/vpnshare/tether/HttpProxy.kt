package com.vpnshare.tether

import android.util.Log
import kotlinx.coroutines.*
import java.io.*
import java.net.*

/**
 * HTTP/HTTPS proxy server. Supports CONNECT for HTTPS and basic HTTP forward.
 */
class HttpProxy(private val port: Int) {

    companion object {
        private const val TAG = "HttpProxy"
        private const val BUF_SIZE = 32768
    }

    private var serverSocket: ServerSocket? = null
    private var acceptJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    @Volatile
    var running = false
        private set

    fun start() {
        if (running) return
        running = true
        val addrs = NetworkUtils.getListenAddresses()
        var bound = false
        for (ba in addrs) {
            try {
                val addr = InetAddress.getByName(ba.ip)
                val ss = ServerSocket(port, 50, addr)
                serverSocket = ss
                Log.i(TAG, "HTTP proxy listening on ${ba.ip}:$port")
                bound = true
                acceptLoop(ss)
                break
            } catch (e: Exception) {
                Log.w(TAG, "Cannot bind HTTP to ${ba.ip}:$port: ${e.message}")
            }
        }
        if (!bound) {
            try {
                val ss = ServerSocket(port, 50)
                serverSocket = ss
                Log.i(TAG, "HTTP proxy listening on 0.0.0.0:$port (fallback)")
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
                    val client = ss.accept()
                    val clientIp = client.inetAddress.hostAddress ?: ""
                    if (!NetworkUtils.isAllowedClient(clientIp)) {
                        try { client.close() } catch (_: Exception) {}
                        continue
                    }
                    client.soTimeout = 60000
                    client.tcpNoDelay = true
                    handleClient(client)
                } catch (_: SocketTimeoutException) {
                } catch (e: Exception) {
                    if (running) Log.e(TAG, "HTTP accept error: ${e.message}")
                }
            }
        }
    }

    private fun handleClient(client: Socket) {
        scope.launch {
            try {
                val input = BufferedInputStream(client.getInputStream())
                val output = client.getOutputStream()

                val requestLine = readLine(input) ?: run { client.close(); return@launch }
                val parts = requestLine.split(" ")
                if (parts.size < 3) {
                    sendError(output, 400, "Bad Request")
                    client.close(); return@launch
                }
                val method = parts[0].uppercase()
                val url = parts[1]

                val headers = mutableMapOf<String, String>()
                while (true) {
                    val line = readLine(input) ?: break
                    if (line.isEmpty()) break
                    val colon = line.indexOf(':')
                    if (colon > 0) {
                        headers[line.substring(0, colon).trim()] = line.substring(colon + 1).trim()
                    }
                }

                when (method) {
                    "CONNECT" -> handleConnect(client, input, output, url)
                    else -> handleForward(client, input, output, method, url, headers)
                }
            } catch (e: Exception) {
                Log.w(TAG, "HTTP client error: ${e.message}")
                try { client.close() } catch (_: Exception) {}
            }
        }
    }

    private fun handleConnect(client: Socket, cin: InputStream, cout: OutputStream, target: String) {
        scope.launch {
            var remote: Socket? = null
            try {
                val hostPort = target.split(":")
                val host = hostPort[0]
                val port = if (hostPort.size > 1) hostPort[1].toIntOrNull() ?: 443 else 443

                val addr = InetSocketAddress(NetworkUtils.resolve(host), port)
                remote = Socket()
                remote.tcpNoDelay = true
                remote.connect(addr, 30000)

                cout.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
                cout.flush()

                val rin = remote.getInputStream().buffered()
                val rout = remote.getOutputStream()

                val c2r = launch { relay(cin, rout) }
                val r2c = launch { relay(rin, cout) }
                c2r.join()
                r2c.cancelAndJoin()
            } catch (e: Exception) {
                Log.w(TAG, "CONNECT to $target: ${e.message}")
                sendError(cout, 502, "Bad Gateway")
            } finally {
                try { remote?.close() } catch (_: Exception) {}
                try { client.close() } catch (_: Exception) {}
            }
        }
    }

    private fun handleForward(client: Socket, cin: BufferedInputStream, cout: OutputStream,
                              method: String, url: String, headers: MutableMap<String, String>) {
        scope.launch {
            var remote: Socket? = null
            try {
                val uri = URI(url)
                val host = uri.host ?: throw IOException("No host")
                val port = if (uri.port > 0) uri.port else if (uri.scheme == "https") 443 else 80
                val path = if (uri.rawPath != null && uri.rawPath.isNotEmpty()) {
                    uri.rawPath + if (uri.rawQuery != null) "?${uri.rawQuery}" else ""
                } else "/"

                val addr = InetSocketAddress(NetworkUtils.resolve(host), port)
                remote = Socket()
                remote.tcpNoDelay = true
                remote.connect(addr, 30000)
                val rout = remote.getOutputStream()
                val rin = BufferedInputStream(remote.getInputStream())

                headers.remove("Proxy-Connection")
                headers["Host"] = if (port != 80 && port != 443) "$host:$port" else host
                headers["Connection"] = "close"

                val sb = StringBuilder()
                sb.append("$method $path HTTP/1.1\r\n")
                for ((k, v) in headers) sb.append("$k: $v\r\n")
                sb.append("\r\n")
                rout.write(sb.toString().toByteArray())
                rout.flush()

                // Relay bidirectional
                val c2r = launch { relay(cin, rout) }
                delay(100)
                c2r.cancelAndJoin()
                relay(rin, cout)
            } catch (e: Exception) {
                Log.w(TAG, "HTTP forward: ${e.message}")
                sendError(cout, 502, "Bad Gateway")
            } finally {
                try { remote?.close() } catch (_: Exception) {}
                try { client.close() } catch (_: Exception) {}
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

    private fun sendError(out: OutputStream, code: Int, msg: String) {
        try {
            val body = "<html><body><h1>$code $msg</h1></body></html>"
            val resp = "HTTP/1.1 $code $msg\r\nContent-Type: text/html\r\nContent-Length: ${body.toByteArray().size}\r\nConnection: close\r\n\r\n$body"
            out.write(resp.toByteArray())
            out.flush()
        } catch (_: Exception) {}
    }

    private fun readLine(stream: InputStream): String? {
        val sb = StringBuilder()
        var prev = -1
        while (true) {
            val c = stream.read()
            if (c == -1) return if (sb.isEmpty()) null else sb.toString()
            if (c == '\n') {
                if (prev == '\r') sb.deleteCharAt(sb.length - 1)
                return sb.toString()
            }
            sb.append(c.toChar())
            prev = c
        }
    }

    fun stop() {
        running = false
        acceptJob?.cancel()
        scope.cancel()
        try { serverSocket?.close() } catch (_: Exception) {}
        serverSocket = null
        Log.i(TAG, "HTTP proxy stopped")
    }
}
