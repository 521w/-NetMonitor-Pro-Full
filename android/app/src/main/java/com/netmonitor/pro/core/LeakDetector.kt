package com.netmonitor.pro.core

class LeakDetector {
    var volumeThreshold: Long = 5_000_000

    fun scan(events: List<NetEvent>): List<LeakAlert> {
        val alerts = mutableListOf<LeakAlert>()
        for ((dest, destEvents) in events.groupBy { it.destIp }) {
            val totalBytes = destEvents.sumOf { it.txBytes + it.rxBytes }
            if (totalBytes > volumeThreshold) {
                alerts.add(LeakAlert("HIGH_VOLUME", "\u5927\u6d41\u91cf\u4f20\u8f93\u81f3 $dest", "\u4e2d"))
            }
        }
        val unusual = events.filter { it.port !in listOf(80, 443, 8080, 53) }
        if (unusual.size > events.size * 0.3 && events.size > 5) {
            alerts.add(LeakAlert("UNUSUAL_PORTS", "${unusual.size} \u4e2a\u975e\u6807\u51c6\u7aef\u53e3\u8fde\u63a5", "\u4e2d"))
        }
        return alerts
    }
}

data class LeakAlert(val type: String, val message: String, val severity: String)
