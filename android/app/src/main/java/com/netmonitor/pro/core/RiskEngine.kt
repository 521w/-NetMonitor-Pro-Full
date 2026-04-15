package com.netmonitor.pro.core

class RiskEngine {
    var highVolumeThreshold: Long = 10_000_000
    var destCountThreshold: Int = 20
    var freqThreshold: Double = 100.0

    fun evaluate(features: FeatureVector): Int {
        var risk = 0
        if (features.totalBytes > highVolumeThreshold) risk += 20
        if (features.uniqueDestinations > destCountThreshold) risk += 15
        if (features.timeOfDay in 1..5) risk += 25
        if (features.connectionFrequency > freqThreshold) risk += 20
        if (features.avgPacketSize > 5000) risk += 10
        return risk.coerceIn(0, 100)
    }

    fun getRiskLabel(score: Int): String = when {
        score < 30 -> "\u4f4e"
        score < 60 -> "\u4e2d"
        else -> "\u9ad8"
    }
}
