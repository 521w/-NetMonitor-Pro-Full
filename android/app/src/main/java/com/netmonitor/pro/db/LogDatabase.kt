package com.netmonitor.pro.db

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import com.netmonitor.pro.core.NetEvent
import java.io.File
import java.io.FileWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class LogDatabase(context: Context) : SQLiteOpenHelper(context, "netmonitor.db", null, 1) {

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                uid INTEGER,
                app_name TEXT,
                package_name TEXT,
                dest_ip TEXT,
                dest_host TEXT,
                protocol TEXT,
                port INTEGER,
                tx_bytes INTEGER,
                rx_bytes INTEGER,
                direction TEXT,
                risk_level INTEGER,
                blocked INTEGER,
                source TEXT
            )
        """.trimIndent())
    }

    override fun onUpgrade(db: SQLiteDatabase, old: Int, new: Int) {
        db.execSQL("DROP TABLE IF EXISTS events")
        onCreate(db)
    }

    fun insert(event: NetEvent) {
        writableDatabase.insert("events", null, ContentValues().apply {
            put("timestamp", event.timestamp)
            put("uid", event.uid)
            put("app_name", event.appName)
            put("package_name", event.packageName)
            put("dest_ip", event.destIp)
            put("dest_host", event.destHost)
            put("protocol", event.protocol)
            put("port", event.port)
            put("tx_bytes", event.txBytes)
            put("rx_bytes", event.rxBytes)
            put("direction", event.direction)
            put("risk_level", event.riskLevel)
            put("blocked", if (event.blocked) 1 else 0)
            put("source", event.source)
        })
    }

    fun getRecent(limit: Int = 200): List<NetEvent> {
        val list = mutableListOf<NetEvent>()
        val cursor = readableDatabase.query("events", null, null, null, null, null, "timestamp DESC", limit.toString())
        while (cursor.moveToNext()) {
            list.add(NetEvent(
                id = cursor.getLong(0), timestamp = cursor.getLong(1), uid = cursor.getInt(2),
                appName = cursor.getString(3) ?: "", packageName = cursor.getString(4) ?: "",
                destIp = cursor.getString(5) ?: "", destHost = cursor.getString(6) ?: "",
                protocol = cursor.getString(7) ?: "", port = cursor.getInt(8),
                txBytes = cursor.getLong(9), rxBytes = cursor.getLong(10),
                direction = cursor.getString(11) ?: "", riskLevel = cursor.getInt(12),
                blocked = cursor.getInt(13) == 1, source = cursor.getString(14) ?: ""
            ))
        }
        cursor.close()
        return list
    }

    fun exportToCsv(dir: File): File {
        val sdf = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault())
        val file = File(dir, "netmonitor_${sdf.format(Date())}.csv")
        val writer = FileWriter(file)
        writer.write("\u65f6\u95f4,\u5e94\u7528,\u5305\u540d,\u76ee\u6807IP,\u7aef\u53e3,\u534f\u8bae,\u53d1\u9001,\u63a5\u6536,\u65b9\u5411,\u98ce\u9669\n")
        val cursor = readableDatabase.query("events", null, null, null, null, null, "timestamp DESC")
        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
        while (cursor.moveToNext()) {
            writer.write("${fmt.format(Date(cursor.getLong(1)))},${cursor.getString(3)},${cursor.getString(4)},${cursor.getString(5)},${cursor.getInt(8)},${cursor.getString(7)},${cursor.getLong(9)},${cursor.getLong(10)},${cursor.getString(11)},${cursor.getInt(12)}\n")
        }
        cursor.close()
        writer.close()
        return file
    }

    fun clearAll() { writableDatabase.delete("events", null, null) }

    fun getCount(): Int {
        val cursor = readableDatabase.rawQuery("SELECT COUNT(*) FROM events", null)
        cursor.moveToFirst()
        val count = cursor.getInt(0)
        cursor.close()
        return count
    }
}
