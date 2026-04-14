package com.netmonitor.pro

import com.netmonitor.pro.core.*
import com.netmonitor.pro.ml.BehaviorModel
import com.netmonitor.pro.ui.FlowGraphView

import android.os.*
import android.widget.*
import androidx.appcompat.app.AppCompatActivity

class MainActivity: AppCompatActivity(){

    private val extractor = FeatureExtractor()
    private val risk = RiskEngine()
    private val leak = LeakDetector()

    override fun onCreate(s:Bundle?){
        super.onCreate(s)

        val tv = TextView(this)
        setContentView(tv)

        Thread{
            while(true){
                val events = EventBus.drain()
                if(events.isEmpty()){ Thread.sleep(300); continue }

                val f = extractor.extract(events)
                val score = risk.score(f)

                runOnUiThread{
                    tv.text = "Risk=$score\nEvents=${events.size}"
                }
            }
        }.start()
    }
}
