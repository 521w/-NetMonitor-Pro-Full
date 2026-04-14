package com.netmonitor.pro.core

data class NetEvent(
    val pid: Int,
    val uid: Int,
    val dst: String,
    val type: String = "TCP",
    val timestamp: Long = System.currentTimeMillis()
)
