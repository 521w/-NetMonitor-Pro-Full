package com.netmonitor.pro.core

import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.TrafficStats
import android.os.Handler
import android.os.Looper
import android.util.Log

class NetworkMonitor(private val context: Context) {
    private val handler = Handler(Looper.getMainLooper())
    private val pm = context.packageManager
    private val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private var previousUidBytes = mutableMapOf<Int, Pair<Long, Long>>()
    private var running = false
    private var intervalMs = 3000L

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            Log.d("NetMonitor", "Network available")
        }
        override fun onLost(network: Network) {
            Log.d("NetMonitor", "Network lost")
        }
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            Log.d("NetMonitor", "Capabilities changed")
        }
    }

    fun start(interval: Long = 3000L) {
        intervalMs = interval
        running = true
        val request = NetworkRequest.Builder().build()
        try { cm.registerNetworkCallback(request, networkCallback) } catch (_: Exception) {}
        handler.post(pollRunnable)
    }

    fun stop() {
        running = false
        handler.removeCallbacks(pollRunnable)
        try { cm.unregisterNetworkCallback(networkCallback) } catch (_: Exception) {}
    }

    private val pollRunnable = object : Runnable {
        override fun run() {
            if (!running) return
            pollTraffic()
            handler.postDelayed(this, intervalMs)
        }
    }

    private fun pollTraffic() {
        val packages = pm.getInstalledApplications(PackageManager.GET_META_DATA)
        for (appInfo in packages) {
            val uid = appInfo.uid
            val tx = TrafficStats.getUidTxBytes(uid)
            val rx = TrafficStats.getUidRxBytes(uid)
            if (tx <= 0 && rx <= 0) continue
            val prev = previousUidBytes[uid]
            if (prev != null) {
                val deltaTx = tx - prev.first
                val deltaRx = rx - prev.second
                if (deltaTx > 0 || deltaRx > 0) {
                    val label = try {
                        pm.getApplicationLabel(appInfo).toString()
                    } catch (_: Exception) { appInfo.packageName }
                    val event = NetEvent(
                        uid = uid,
                        appName = label,
                        packageName = appInfo.packageName,
                        txBytes = deltaTx,
                        rxBytes = deltaRx,
                        direction = if (deltaTx > deltaRx) "OUT" else "IN",
                        protocol = "TCP",
                        source = "trafficstats"
                    )
                    EventBus.publish(event)
                }
            }
            previousUidBytes[uid] = Pair(tx, rx)
        }
    }
}
