package com.netmonitor.pro.ml

import com.netmonitor.pro.core.FeatureVector

class BehaviorModel {
    private val baseline = mutableListOf<FeatureVector>()

    fun train(features: FeatureVector) {
        baseline.add(features)
        if (baseline.size > 100) baseline.removeAt(0)
    }

    fun predict(features: FeatureVector): Double {
        if (baseline.size < 5) return 0.0
        val avgBytes = baseline.map { it.totalBytes.toDouble() }.average()
        val avgDest = baseline.map { it.uniqueDestinations.toDouble() }.average()
        val avgFreq = baseline.map { it.connectionFrequency }.average()
        var anomaly = 0.0
        if (avgBytes > 0) anomaly += ((features.totalBytes - avgBytes) / avgBytes).coerceAtLeast(0.0) * 0.35
        if (avgDest > 0) anomaly += ((features.uniqueDestinations - avgDest) / avgDest).coerceAtLeast(0.0) * 0.35
        if (avgFreq > 0) anomaly += ((features.connectionFrequency - avgFreq) / avgFreq).coerceAtLeast(0.0) * 0.3
        return anomaly.coerceIn(0.0, 1.0)
    }

    fun getStatus(): String = when {
        baseline.size < 5 -> "\u5b66\u4e60\u4e2d (${baseline.size}/5)"
        else -> "\u5df2\u5efa\u6a21 (${baseline.size} \u6837\u672c)"
    }
}
