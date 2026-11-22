package com.vpnshare.tether

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*

class ProxyService : Service() {

    companion object {
        private const val TAG = "ProxyService"
        private const val CHANNEL_ID = "vpnshare_proxy"
        private const val NOTIFICATION_ID = 1337
        const val ACTION_START = "com.vpnshare.tether.START"
        const val ACTION_STOP = "com.vpnshare.tether.STOP"
        const val EXTRA_SOCKS_PORT = "socks_port"
        const val EXTRA_HTTP_PORT = "http_port"

        const val DEFAULT_SOCKS_PORT = 1080
        const val DEFAULT_HTTP_PORT = 8080

        @Volatile
        var instance: ProxyService? = null
            private set

        var isRunning = false
            private set

        var socksPort = DEFAULT_SOCKS_PORT
            private set
        var httpPort = DEFAULT_HTTP_PORT
            private set
    }

    private var socks5: Socks5Proxy? = null
    private var httpProxy: HttpProxy? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onCreate() {
        super.onCreate()
        instance = this
        createNotificationChannel()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                socksPort = intent.getIntExtra(EXTRA_SOCKS_PORT, DEFAULT_SOCKS_PORT)
                httpPort = intent.getIntExtra(EXTRA_HTTP_PORT, DEFAULT_HTTP_PORT)
                startProxy()
            }
            ACTION_STOP -> {
                stopProxy()
                stopSelf()
            }
        }
        return START_STICKY
    }

    private fun startProxy() {
        if (isRunning) return
        isRunning = true

        // Start foreground immediately
        startForeground(NOTIFICATION_ID, buildNotification("Запуск прокси…"))

        // Acquire locks
        acquireLocks()

        scope.launch {
            try {
                // Start SOCKS5 proxy
                socks5 = Socks5Proxy(socksPort).also { it.start() }
                // Start HTTP proxy
                httpProxy = HttpProxy(httpPort).also { it.start() }
                Log.i(TAG, "Proxies started on SOCKS=$socksPort HTTP=$httpPort")
                updateNotification("Прокси запущен")
                // Broadcast status
                sendBroadcast(Intent("com.vpnshare.tether.STATUS").putExtra("running", true))
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start proxy: ${e.message}", e)
                updateNotification("Ошибка запуска: ${e.message}")
                isRunning = false
                sendBroadcast(Intent("com.vpnshare.tether.STATUS").putExtra("running", false)
                    .putExtra("error", e.message))
                delay(3000)
                stopSelf()
            }
        }
    }

    private fun stopProxy() {
        isRunning = false
        try {
            socks5?.stop()
            httpProxy?.stop()
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping proxies: ${e.message}")
        }
        socks5 = null
        httpProxy = null
        releaseLocks()
        sendBroadcast(Intent("com.vpnshare.tether.STATUS").putExtra("running", false))
        Log.i(TAG, "Proxies stopped")
    }

    private fun buildNotification(text: String): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = Intent(this, ProxyService::class.java).apply { action = ACTION_STOP }
        val stopPending = PendingIntent.getService(
            this, 1, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("VPN Share")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Стоп", stopPending)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel),
                NotificationManager.IMPORTANCE_LOW
            )
            channel.setShowBadge(false)
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }
    }

    @Suppress("DEPRECATION")
    private fun acquireLocks() {
        try {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "VPNShare::WakeLock").apply {
                acquire(12 * 60 * 60 * 1000L) // 12h max
            }
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "VPNShare::WifiLock").apply {
                acquire()
            }
        } catch (e: Exception) {
            Log.w(TAG, "Could not acquire all locks: ${e.message}")
        }
    }

    private fun releaseLocks() {
        try { wakeLock?.release() } catch (_: Exception) {}
        try { wifiLock?.release() } catch (_: Exception) {}
        wakeLock = null
        wifiLock = null
    }

    override fun onDestroy() {
        stopProxy()
        scope.cancel()
        instance = null
        super.onDestroy()
    }
}
