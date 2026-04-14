package com.netmonitor.pro.ml

import com.netmonitor.pro.core.FeatureVector

class BehaviorModel {

    private val base = mutableMapOf<Int, FeatureVector>()

    fun train(uid:Int, f:FeatureVector){
        base[uid]=f
    }

    fun predict(uid:Int, cur:FeatureVector):Float{
        val b = base[uid] ?: return 50f
        return kotlin.math.abs(cur.ipv6Ratio-b.ipv6Ratio)*40 +
               kotlin.math.abs(cur.externalRatio-b.externalRatio)*50
    }
}
