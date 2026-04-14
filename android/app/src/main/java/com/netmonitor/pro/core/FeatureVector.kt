package com.netmonitor.pro.core

data class FeatureVector(
    val dnsRatio: Float,
    val ipv6Ratio: Float,
    val externalRatio: Float,
    val entropy: Float
)
