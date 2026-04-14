package com.netmonitor.pro.ml

import com.netmonitor.pro.core.FeatureVector

class BehaviorModel {
    private val baseline = mutableListOf<FeatureVector>()
    fun train(features: FeatureVector) {
        baseline.add(features)
        if (baseline.size > 100) baseline.removeAt(0)
    }
    fun predict(features: FeatureVector): Double {
        if (baseline.isEmpty()) return 0.5
        val avgBytes = baseline.map { it.totalBytes.toDouble() }.average()
        val avgDest = baseline.map { it.uniqueDestinations.toDouble() }.average()
        var anomaly = 0.0
        if (avgBytes > 0) anomaly += ((features.totalBytes - avgBytes).coerceAtLeast(0.0)) / avgBytes * 0.5
        if (avgDest > 0) anomaly += ((features.uniqueDestinations - avgDest).coerceAtLeast(0.0)) / avgDest * 0.5
        return anomaly.coerceIn(0.0, 1.0)
    }
}
