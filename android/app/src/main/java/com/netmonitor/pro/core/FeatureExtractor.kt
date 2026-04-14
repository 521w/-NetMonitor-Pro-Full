package com.netmonitor.pro.core

import java.util.Calendar

class FeatureExtractor {
    fun extract(events: List<NetEvent>): FeatureVector {
        if (events.isEmpty()) return FeatureVector()
        val avgSize = events.map { it.bytesTransferred.toDouble() }.average()
        val uniqueDest = events.map { it.destIp }.distinct().size
        val protocols = events.groupBy { it.protocol }
            .mapValues { it.value.size.toDouble() / events.size }
        val totalBytes = events.sumOf { it.bytesTransferred }
        val hour = Calendar.getInstance().get(Calendar.HOUR_OF_DAY)
        return FeatureVector(avgSize, events.size.toDouble(), uniqueDest, protocols, hour, totalBytes)
    }
}
