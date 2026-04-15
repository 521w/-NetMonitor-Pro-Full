package com.netmonitor.pro

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.content.FileProvider
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.netmonitor.pro.db.LogDatabase
import com.netmonitor.pro.ui.EventAdapter

class LogActivity : AppCompatActivity() {
    private lateinit var db: LogDatabase
    private val adapter = EventAdapter()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_log)
        val toolbar = findViewById<Toolbar>(R.id.toolbarLog)
        setSupportActionBar(toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = "\u65e5\u5fd7\u8bb0\u5f55"

        db = LogDatabase(this)
        val rv = findViewById<RecyclerView>(R.id.rvLogs)
        rv.layoutManager = LinearLayoutManager(this)
        rv.adapter = adapter

        val tvCount = findViewById<TextView>(R.id.tvLogCount)
        loadLogs(tvCount)

        findViewById<Button>(R.id.btnExport).setOnClickListener { exportLogs() }
        findViewById<Button>(R.id.btnClear).setOnClickListener {
            AlertDialog.Builder(this)
                .setTitle("\u786e\u8ba4\u6e05\u9664")
                .setMessage("\u786e\u5b9a\u8981\u6e05\u9664\u6240\u6709\u65e5\u5fd7\u8bb0\u5f55\u5417\uff1f")
                .setPositiveButton("\u6e05\u9664") { _, _ ->
                    db.clearAll()
                    loadLogs(tvCount)
                    Toast.makeText(this, "\u65e5\u5fd7\u5df2\u6e05\u9664", Toast.LENGTH_SHORT).show()
                }
                .setNegativeButton("\u53d6\u6d88", null)
                .show()
        }
    }

    private fun loadLogs(tvCount: TextView) {
        val events = db.getRecent(200)
        adapter.setEvents(events)
        tvCount.text = "\u5171 ${db.getCount()} \u6761\u8bb0\u5f55"
    }

    private fun exportLogs() {
        try {
            val file = db.exportToCsv(getExternalFilesDir(null) ?: filesDir)
            val uri = FileProvider.getUriForFile(this, "${packageName}.fileprovider", file)
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "text/csv"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(intent, "\u5bfc\u51fa\u65e5\u5fd7"))
        } catch (e: Exception) {
            Toast.makeText(this, "\u5bfc\u51fa\u5931\u8d25: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    override fun onSupportNavigateUp(): Boolean { finish(); return true }
}
