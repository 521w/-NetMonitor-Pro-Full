package com.netmonitor.pro

    import android.graphics.Color
    import android.os.Bundle
    import android.os.Handler
    import android.os.Looper
    import android.view.View
    import android.widget.ProgressBar
    import android.widget.TextView
    import androidx.appcompat.app.AppCompatActivity
    import androidx.recyclerview.widget.LinearLayoutManager
    import androidx.recyclerview.widget.RecyclerView
    import com.google.android.material.card.MaterialCardView
    import com.netmonitor.pro.core.*
    import com.netmonitor.pro.ml.BehaviorModel
    import com.netmonitor.pro.ui.EventAdapter
    import com.netmonitor.pro.ui.FlowGraphView
    import kotlin.random.Random

    class MainActivity : AppCompatActivity() {
        private lateinit var tvRiskScore: TextView
        private lateinit var tvRiskLabel: TextView
        private lateinit var progressRisk: ProgressBar
        private lateinit var tvConnections: TextView
        private lateinit var tvData: TextView
        private lateinit var cardAlerts: MaterialCardView
        private lateinit var tvAlerts: TextView
        private lateinit var flowGraph: FlowGraphView
        private val handler = Handler(Looper.getMainLooper())
        private val adapter = EventAdapter()
        private val allEvents = mutableListOf<NetEvent>()
        private val extractor = FeatureExtractor()
        private val riskEngine = RiskEngine()
        private val leakDetector = LeakDetector()
        private val model = BehaviorModel()
        private var totalBytes = 0L
        private var count = 0
        private val dests = listOf("142.250.80.46","31.13.71.36","157.240.1.35","104.244.42.1","52.94.236.248","13.107.42.14","185.60.218.35","151.101.1.140")
        private val apps = listOf("Chrome","WeChat","Alipay","Douyin","Taobao","System","Maps","Mail")
        private val protos = listOf("TCP","TCP","TCP","UDP","HTTPS","DNS")

        override fun onCreate(savedInstanceState: Bundle?) {
            super.onCreate(savedInstanceState)
            setContentView(R.layout.activity_main)
            tvRiskScore = findViewById(R.id.tvRiskScore)
            tvRiskLabel = findViewById(R.id.tvRiskLabel)
            progressRisk = findViewById(R.id.progressRisk)
            tvConnections = findViewById(R.id.tvConnections)
            tvData = findViewById(R.id.tvDataTransferred)
            cardAlerts = findViewById(R.id.cardAlerts)
            tvAlerts = findViewById(R.id.tvAlerts)
            flowGraph = findViewById(R.id.flowGraph)
            val rv = findViewById<RecyclerView>(R.id.rvEvents)
            rv.layoutManager = LinearLayoutManager(this)
            rv.adapter = adapter
            EventBus.subscribe { e -> runOnUiThread {
                allEvents.add(e); if (allEvents.size > 200) allEvents.removeAt(0)
                count++; totalBytes += e.bytesTransferred; adapter.addEvent(e); update()
            }}
            handler.post(object : Runnable { override fun run() {
                EventBus.publish(NetEvent(sourceIp="192.168.1.${'$'}{Random.nextInt(2,50)}", destIp=dests.random(), protocol=protos.random(),
                    port=listOf(80,443,8080,53,3000,8443,9090).random(), bytesTransferred=Random.nextLong(100,500_000),
                    direction=if(Random.nextBoolean()) "OUT" else "IN", appName=apps.random(), riskLevel=Random.nextInt(0,100)))
                handler.postDelayed(this, Random.nextLong(1000, 3000))
            }})
        }
        private fun update() {
            tvConnections.text = count.toString()
            tvData.text = when { totalBytes>1_000_000_000->"${'$'}{totalBytes/1_000_000_000} GB"; totalBytes>1_000_000->"${'$'}{totalBytes/1_000_000} MB"; totalBytes>1_000->"${'$'}{totalBytes/1_000} KB"; else->"${'$'}totalBytes B" }
            val feat = extractor.extract(allEvents.takeLast(50)); model.train(feat)
            val score = riskEngine.evaluate(feat); val label = riskEngine.getRiskLabel(score)
            tvRiskScore.text = score.toString(); tvRiskLabel.text = label; progressRisk.progress = score
            val c = when { score>60->Color.parseColor("#F44336"); score>30->Color.parseColor("#FF9800"); else->Color.parseColor("#4CAF50") }
            tvRiskScore.setTextColor(c); tvRiskLabel.setTextColor(c)
            flowGraph.addPoint(allEvents.lastOrNull()?.bytesTransferred?.toFloat() ?: 0f)
            val alerts = leakDetector.scan(allEvents.takeLast(100))
            if (alerts.isNotEmpty()) { cardAlerts.visibility = View.VISIBLE; tvAlerts.text = alerts.joinToString("
") { it.message } }
            else { cardAlerts.visibility = View.GONE }
        }
        override fun onDestroy() { super.onDestroy(); handler.removeCallbacksAndMessages(null); EventBus.clear() }
    }
