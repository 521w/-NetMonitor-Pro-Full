package com.netmonitor.pro.core

class RiskEngine {
    fun score(f: FeatureVector): Int {
        var s = 0
        if (f.ipv6Ratio > 0.3) s += 40
        if (f.externalRatio > 0.5) s += 50
        return s.coerceIn(0,100)
    }
}
