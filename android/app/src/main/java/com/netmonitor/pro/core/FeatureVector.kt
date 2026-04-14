package com.netmonitor.pro.core

data class FeatureVector(
    val avgPacketSize: Double = 0.0,
    val connectionFrequency: Double = 0.0,
    val uniqueDestinations: Int = 0,
    val protocolDistribution: Map<String, Double> = emptyMap(),
    val timeOfDay: Int = 0,
    val totalBytes: Long = 0
)
