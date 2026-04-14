package com.netmonitor.pro.core

class LeakDetector {
    fun scan(events: List<NetEvent>): List<LeakAlert> {
        val alerts = mutableListOf<LeakAlert>()
        for ((dest, destEvents) in events.groupBy { it.destIp }) {
            val totalBytes = destEvents.sumOf { it.bytesTransferred }
            if (totalBytes > 5_000_000) {
                alerts.add(LeakAlert("HIGH_VOLUME", "Large transfer to $dest", "MEDIUM"))
            }
        }
        val unusual = events.filter { it.port !in listOf(80, 443, 8080, 53) }
        if (unusual.size > events.size * 0.3 && events.size > 5) {
            alerts.add(LeakAlert("UNUSUAL_PORTS", "${'$'}{unusual.size} non-standard ports", "MEDIUM"))
        }
        return alerts
    }
}

data class LeakAlert(val type: String, val message: String, val severity: String)
