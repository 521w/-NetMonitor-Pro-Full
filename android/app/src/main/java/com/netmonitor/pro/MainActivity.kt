package com.netmonitor.pro

import android.Manifest
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.preference.PreferenceManager
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.card.MaterialCardView
import com.netmonitor.pro.core.*
import com.netmonitor.pro.db.LogDatabase
import com.netmonitor.pro.ml.BehaviorModel
import com.netmonitor.pro.ui.EventAdapter
import com.netmonitor.pro.ui.FlowGraphView

class MainActivity : AppCompatActivity() {
    private lateinit var tvRiskScore: TextView
    private lateinit var tvRiskLabel: TextView
    private lateinit var progressRisk: ProgressBar
    private lateinit var tvConnections: TextView
    private lateinit var tvData: TextView
    private lateinit var tvModelStatus: TextView
    private lateinit var tvAnomalyScore: TextView
    private lateinit var cardAlerts: MaterialCardView
    private lateinit var tvAlerts: TextView
    private lateinit var flowGraph: FlowGraphView
    private lateinit var tvStatus: TextView
    private lateinit var db: LogDatabase
    private lateinit var prefs: SharedPreferences

    private val handler = Handler(Looper.getMainLooper())
    private val adapter = EventAdapter()
    private val allEvents = mutableListOf<NetEvent>()
    private val extractor = FeatureExtractor()
    private val riskEngine = RiskEngine()
    private val leakDetector = LeakDetector()
    private val model = BehaviorModel()
    private var monitor: NetworkMonitor? = null
    private var totalTx = 0L
    private var totalRx = 0L
    private var count = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val toolbar = findViewById<Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        supportActionBar?.title = ""

        db = LogDatabase(this)
        prefs = PreferenceManager.getDefaultSharedPreferences(this)

        tvRiskScore = findViewById(R.id.tvRiskScore)
        tvRiskLabel = findViewById(R.id.tvRiskLabel)
        progressRisk = findViewById(R.id.progressRisk)
        tvConnections = findViewById(R.id.tvConnections)
        tvData = findViewById(R.id.tvData)
        tvModelStatus = findViewById(R.id.tvModelStatus)
        tvAnomalyScore = findViewById(R.id.tvAnomalyScore)
        cardAlerts = findViewById(R.id.cardAlerts)
        tvAlerts = findViewById(R.id.tvAlerts)
        flowGraph = findViewById(R.id.flowGraph)
        tvStatus = findViewById(R.id.tvStatus)

        val rv = findViewById<RecyclerView>(R.id.rvEvents)
        rv.layoutManager = LinearLayoutManager(this)
        rv.adapter = adapter

        applySettings()
        requestPermissions()

        EventBus.subscribe { event ->
            runOnUiThread {
                allEvents.add(event)
                if (allEvents.size > 300) allEvents.removeAt(0)
                count++
                totalTx += event.txBytes
                totalRx += event.rxBytes
                val scored = event.copy(riskLevel = riskEngine.evaluate(extractor.extract(listOf(event))))
                adapter.addEvent(scored)
                db.insert(scored)
                updateDashboard()
            }
        }

        monitor = NetworkMonitor(this)
        val interval = prefs.getString("poll_interval", "3000")?.toLongOrNull() ?: 3000L
        monitor?.start(interval)
        tvStatus.text = "\u76d1\u63a7\u4e2d"
        tvStatus.setTextColor(Color.parseColor("#4CAF50"))
    }

    private fun applySettings() {
        riskEngine.highVolumeThreshold = prefs.getString("threshold_volume", "10000000")?.toLongOrNull() ?: 10_000_000
        riskEngine.destCountThreshold = prefs.getString("threshold_dest", "20")?.toIntOrNull() ?: 20
        leakDetector.volumeThreshold = prefs.getString("threshold_leak", "5000000")?.toLongOrNull() ?: 5_000_000
    }

    private fun updateDashboard() {
        tvConnections.text = count.toString()
        val total = totalTx + totalRx
        tvData.text = when {
            total > 1_073_741_824 -> String.format("%.1f GB", total / 1_073_741_824.0)
            total > 1_048_576 -> String.format("%.1f MB", total / 1_048_576.0)
            total > 1024 -> String.format("%.1f KB", total / 1024.0)
            else -> "$total B"
        }

        val recent = allEvents.takeLast(50)
        val feat = extractor.extract(recent)
        model.train(feat)
        val score = riskEngine.evaluate(feat)
        val label = riskEngine.getRiskLabel(score)
        val anomaly = model.predict(feat)

        tvRiskScore.text = score.toString()
        tvRiskLabel.text = label
        progressRisk.progress = score
        val c = when {
            score > 60 -> Color.parseColor("#F44336")
            score > 30 -> Color.parseColor("#FF9800")
            else -> Color.parseColor("#4CAF50")
        }
        tvRiskScore.setTextColor(c)
        tvRiskLabel.setTextColor(c)

        tvModelStatus.text = model.getStatus()
        tvAnomalyScore.text = String.format("%.0f%%", anomaly * 100)
        tvAnomalyScore.setTextColor(when {
            anomaly > 0.7 -> Color.parseColor("#F44336")
            anomaly > 0.4 -> Color.parseColor("#FF9800")
            else -> Color.parseColor("#4CAF50")
        })

        flowGraph.addPoint((allEvents.lastOrNull()?.let { it.txBytes + it.rxBytes } ?: 0).toFloat())

        val alerts = leakDetector.scan(allEvents.takeLast(100))
        if (alerts.isNotEmpty()) {
            cardAlerts.visibility = View.VISIBLE
            tvAlerts.text = alerts.joinToString("\n") { "\u26a0 ${it.message}" }
        } else {
            cardAlerts.visibility = View.GONE
        }
    }

    private fun requestPermissions() {
        val perms = mutableListOf<String>()
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.INTERNET) != PackageManager.PERMISSION_GRANTED)
            perms.add(Manifest.permission.INTERNET)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
                perms.add(Manifest.permission.POST_NOTIFICATIONS)
        }
        if (perms.isNotEmpty()) ActivityCompat.requestPermissions(this, perms.toTypedArray(), 100)
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_settings -> { startActivity(Intent(this, SettingsActivity::class.java)); true }
            R.id.action_logs -> { startActivity(Intent(this, LogActivity::class.java)); true }
            else -> super.onOptionsItemSelected(item)
        }
    }

    override fun onResume() {
        super.onResume()
        applySettings()
    }

    override fun onDestroy() {
        super.onDestroy()
        monitor?.stop()
        handler.removeCallbacksAndMessages(null)
        EventBus.clear()
    }
}
