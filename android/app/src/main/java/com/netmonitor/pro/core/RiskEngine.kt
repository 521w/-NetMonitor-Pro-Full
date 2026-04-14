package com.netmonitor.pro.core

class RiskEngine {
    fun evaluate(features: FeatureVector): Int {
        var risk = 0
        if (features.totalBytes > 10_000_000) risk += 20
        if (features.uniqueDestinations > 20) risk += 15
        if (features.timeOfDay in 1..5) risk += 25
        if (features.connectionFrequency > 100) risk += 20
        if (features.avgPacketSize > 5000) risk += 10
        return risk.coerceIn(0, 100)
    }
    fun getRiskLabel(score: Int): String = when {
        score < 30 -> "LOW"
        score < 60 -> "MEDIUM"
        else -> "HIGH"
    }
}
