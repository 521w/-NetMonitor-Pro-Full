package com.netmonitor.pro.core

class FeatureExtractor {

    fun extract(list: List<NetEvent>): FeatureVector {

        val total = list.size.coerceAtLeast(1).toFloat()

        val ipv6 = list.count { it.dst.contains(":") }
        val external = list.count { !(it.dst.startsWith("10.") || it.dst.startsWith("192.168.") || it.dst.startsWith("172.")) }

        return FeatureVector(
            dnsRatio = 0f,
            ipv6Ratio = ipv6 / total,
            externalRatio = external / total,
            entropy = 0f
        )
    }
}
