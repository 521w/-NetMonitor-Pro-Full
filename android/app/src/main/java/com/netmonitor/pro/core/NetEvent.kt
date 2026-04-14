package com.netmonitor.pro.core

data class NetEvent(
    val timestamp: Long = System.currentTimeMillis(),
    val sourceIp: String = "",
    val destIp: String = "",
    val protocol: String = "TCP",
    val port: Int = 0,
    val bytesTransferred: Long = 0,
    val direction: String = "OUT",
    val appName: String = "unknown",
    val riskLevel: Int = 0
)
