package com.netmonitor.pro.core

data class NetEvent(
    val id: Long = 0,
    val timestamp: Long = System.currentTimeMillis(),
    val uid: Int = 0,
    val appName: String = "",
    val packageName: String = "",
    val destIp: String = "",
    val destHost: String = "",
    val protocol: String = "TCP",
    val port: Int = 0,
    val txBytes: Long = 0,
    val rxBytes: Long = 0,
    val direction: String = "OUT",
    val riskLevel: Int = 0,
    val blocked: Boolean = false,
    val source: String = "system"
)
