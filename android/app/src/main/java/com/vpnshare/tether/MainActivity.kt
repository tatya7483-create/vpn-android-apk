package com.vpnshare.tether

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.vpnshare.tether.databinding.ActivityMainBinding
import kotlinx.coroutines.*

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private var vpnCheckJob: Job? = null
    private var vpnMonitorJob: Job? = null

    companion object {
        private const val REQ_NOTIFICATION = 100
        private const val REQ_BATTERY = 101
    }

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val running = intent?.getBooleanExtra("running", false) ?: false
            val error = intent?.getStringExtra("error")
            updateUi(running, error)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Request notification permission on Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this,
                    arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIFICATION)
            }
        }

        binding.btnStartStop.setOnClickListener {
            if (ProxyService.isRunning) {
                stopProxy()
            } else {
                startProxy()
            }
        }

        binding.btnCheckVpn.setOnClickListener {
            checkVpn()
        }

        // Register receiver
        val filter = IntentFilter("com.vpnshare.tether.STATUS")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(statusReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(statusReceiver, filter)
        }

        updateUi(ProxyService.isRunning)
        startVpnMonitoring()
        updateIpDisplay()
    }

    override fun onResume() {
        super.onResume()
        updateUi(ProxyService.isRunning)
        updateIpDisplay()
    }

    private fun startProxy() {
        // Check VPN is on (warn but don't block)
        if (!VpnDetector.isVpnActive(this)) {
            Toast.makeText(this, "Внимание: VPN не включён! Трафик пойдёт напрямую.", Toast.LENGTH_LONG).show()
        }

        // Request battery optimization whitelist
        requestBatteryException()

        val intent = Intent(this, ProxyService::class.java).apply {
            action = ProxyService.ACTION_START
            putExtra(ProxyService.EXTRA_SOCKS_PORT, ProxyService.DEFAULT_SOCKS_PORT)
            putExtra(ProxyService.EXTRA_HTTP_PORT, ProxyService.DEFAULT_HTTP_PORT)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        binding.tvStatus.text = getString(R.string.status_starting)
        binding.tvStatus.setTextColor(ContextCompat.getColor(this, R.color.gray))
    }

    private fun stopProxy() {
        val intent = Intent(this, ProxyService::class.java).apply {
            action = ProxyService.ACTION_STOP
        }
        startService(intent)
        binding.tvStatus.text = getString(R.string.status_stopping)
        binding.tvStatus.setTextColor(ContextCompat.getColor(this, R.color.gray))
    }

    private fun updateUi(running: Boolean, error: String? = null) {
        if (error != null) {
            binding.tvStatus.text = "${getString(R.string.status_error)}: $error"
            binding.tvStatus.setTextColor(ContextCompat.getColor(this, R.color.red))
            binding.btnStartStop.text = getString(R.string.btn_start)
            binding.btnStartStop.backgroundTintList = ContextCompat.getColorStateList(this, R.color.green)
            binding.btnCheckVpn.isEnabled = false
            binding.cardInfo.visibility = android.view.View.GONE
            return
        }
        if (running) {
            binding.tvStatus.text = getString(R.string.status_running)
            binding.tvStatus.setTextColor(ContextCompat.getColor(this, R.color.green))
            binding.btnStartStop.text = getString(R.string.btn_stop)
            binding.btnStartStop.backgroundTintList = ContextCompat.getColorStateList(this, R.color.red)
            binding.btnCheckVpn.isEnabled = true
            binding.cardInfo.visibility = android.view.View.VISIBLE
            updateIpDisplay()
        } else {
            binding.tvStatus.text = getString(R.string.status_stopped)
            binding.tvStatus.setTextColor(ContextCompat.getColor(this, R.color.red))
            binding.btnStartStop.text = getString(R.string.btn_start)
            binding.btnStartStop.backgroundTintList = ContextCompat.getColorStateList(this, R.color.green)
            binding.btnCheckVpn.isEnabled = false
            binding.cardInfo.visibility = android.view.View.GONE
        }
    }

    private fun updateIpDisplay() {
        val usbIp = NetworkUtils.getUsbIp() ?: "Не определён"
        binding.tvPhoneIp.text = usbIp
        binding.tvSocksPort.text = "${ProxyService.DEFAULT_SOCKS_PORT} (SOCKS5)"
        binding.tvHttpPort.text = "${ProxyService.DEFAULT_HTTP_PORT} (HTTP)"
    }

    private fun checkVpn() {
        vpnCheckJob?.cancel()
        binding.tvVpnCheckResult.text = getString(R.string.checking)
        binding.cardVpnCheck.visibility = android.view.View.VISIBLE
        vpnCheckJob = scope.launch {
            val result = VpnDetector.checkExternalIp()
            val vpnActive = VpnDetector.isVpnActive(this@MainActivity)
            val prefix = if (vpnActive) "✓ VPN активен. " else "⚠ VPN ВЫКЛЮЧЕН! "
            binding.tvVpnCheckResult.text = prefix + "IP: $result"
            binding.tvVpnCheckResult.setTextColor(
                ContextCompat.getColor(this@MainActivity,
                    if (vpnActive) R.color.green else R.color.red)
            )
        }
    }

    private fun startVpnMonitoring() {
        vpnMonitorJob?.cancel()
        vpnMonitorJob = scope.launch(Dispatchers.IO) {
            while (isActive) {
                val active = VpnDetector.isVpnActive(this@MainActivity)
                withContext(Dispatchers.Main) {
                    if (active) {
                        binding.tvVpnStatus.text = getString(R.string.vpn_on)
                        binding.tvVpnStatus.setTextColor(ContextCompat.getColor(this@MainActivity, R.color.green))
                    } else {
                        binding.tvVpnStatus.text = getString(R.string.vpn_off)
                        binding.tvVpnStatus.setTextColor(ContextCompat.getColor(this@MainActivity, R.color.red))
                    }
                }
                delay(3000)
            }
        }
    }

    private fun requestBatteryException() {
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        val packageName = packageName
        if (!pm.isIgnoringBatteryOptimizations(packageName)) {
            try {
                val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = Uri.parse("package:$packageName")
                }
                startActivityForResult(intent, REQ_BATTERY)
            } catch (_: Exception) {}
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_NOTIFICATION) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                Toast.makeText(this, "Разрешение на уведомления получено", Toast.LENGTH_SHORT).show()
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        try { unregisterReceiver(statusReceiver) } catch (_: Exception) {}
        vpnCheckJob?.cancel()
        vpnMonitorJob?.cancel()
        scope.cancel()
    }
}
