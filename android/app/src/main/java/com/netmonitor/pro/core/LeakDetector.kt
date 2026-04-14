package com.netmonitor.pro.core

class LeakDetector {
    fun leak(iface:String, dst:String): Boolean {
        val vpn = iface.contains("tun")
        return !vpn && (dst.contains(":") || dst.startsWith("1.") || dst.startsWith("2."))
    }
}
