package com.netmonitor.pro.vpn

import android.content.Context
import android.util.Log
import com.netmonitor.pro.model.NetworkEvent
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedOutputStream
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicBoolean

/**
 * NetMonitor Pro — 事件上报器
 *
 * 功能：
 * - 从 VpnCaptureService 的事件队列中批量消费事件
 * - JWT 认证 + 批量 POST 到云端 API
 * - 自动重试 + 退避策略
 * - 离线缓冲（内存队列，可扩展为本地 SQLite 缓冲）
 */
class ApiReporter(
    private val context: Context,
    private val apiUrl: String,
    private val apiToken: String,
    private val batchSize: Int = 50,
    private val flushIntervalMs: Long = 5000L,
    private val maxRetries: Int = 3,
) {
    companion object {
        private const val TAG = "NetMonReporter"
        private const val CONNECT_TIMEOUT = 10_000
        private const val READ_TIMEOUT = 15_000
    }

    private val isRunning = AtomicBoolean(false)
    private val buffer: ConcurrentLinkedQueue<NetworkEvent> = ConcurrentLinkedQueue()
    private val maxBufferSize = 50_000
    private var scheduler: ScheduledExecutorService? = null
    private var executor: ExecutorService? = null

    // ─── 统计 ───
    @Volatile var totalSent: Long = 0; private set
    @Volatile var totalErrors: Long = 0; private set
    @Volatile var lastError: String? = null; private set

    /**
     * 启动上报器
     */
    fun start() {
        if (isRunning.getAndSet(true)) {
            Log.w(TAG, "上报器已在运行")
            return
        }

        executor = Executors.newSingleThreadExecutor { r ->
            Thread(r, "NetMon-Reporter").apply { isDaemon = true }
        }
        scheduler = Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "NetMon-Scheduler").apply { isDaemon = true }
        }

        // 定时刷新
        scheduler?.scheduleWithFixedDelay(
            { flush() },
            flushIntervalMs,
            flushIntervalMs,
            TimeUnit.MILLISECONDS
        )

        Log.i(TAG, "上报器已启动 → $apiUrl | batch=$batchSize | interval=${flushIntervalMs}ms")
    }

    /**
     * 停止上报器（会尝试发送剩余缓冲数据）
     */
    fun stop() {
        if (!isRunning.getAndSet(false)) return

        // 最终刷新
        flush()

        scheduler?.shutdown()
        executor?.shutdown()

        try {
            executor?.awaitTermination(10, TimeUnit.SECONDS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        }

        Log.i(TAG, "上报器已停止 | 总发送=$totalSent | 总错误=$totalErrors")
    }

    /**
     * 入队事件
     */
    fun enqueue(event: NetworkEvent) {
        if (buffer.size >= maxBufferSize) {
            // 丢弃最旧的事件
            buffer.poll()
        }
        buffer.offer(event)

        // 达到批量阈值时立即触发
        if (buffer.size >= batchSize) {
            executor?.submit { flush() }
        }
    }

    /**
     * 批量入队
     */
    fun enqueueAll(events: List<NetworkEvent>) {
        for (event in events) {
            enqueue(event)
        }
    }

    /**
     * 刷新缓冲区 — 发送所有待发送事件
     */
    private fun flush() {
        if (buffer.isEmpty()) return

        val batch = mutableListOf<NetworkEvent>()
        while (batch.size < batchSize) {
            val event = buffer.poll() ?: break
            batch.add(event)
        }

        if (batch.isEmpty()) return

        var retries = 0
        while (retries < maxRetries) {
            try {
                val success = sendBatch(batch)
                if (success) {
                    totalSent += batch.size
                    return
                }
            } catch (e: Exception) {
                lastError = e.message
                Log.w(TAG, "上报失败 (retry=$retries): ${e.message}")
            }

            retries++
            if (retries < maxRetries) {
                // 指数退避
                val delay = (1000L * (1 shl retries)).coerceAtMost(10_000L)
                Thread.sleep(delay)
            }
        }

        // 全部重试失败，回退到缓冲区
        totalErrors += batch.size
        for (event in batch.reversed()) {
            buffer.offer(event) // 放回队列尾部
        }
        Log.e(TAG, "上报最终失败，${batch.size} 条事件已回退到缓冲区")
    }

    /**
     * 发送一批事件到 API
     */
    private fun sendBatch(batch: List<NetworkEvent>): Boolean {
        val url = URL("${apiUrl.trimEnd('/')}/api/v1/ingest/batch")
        val conn = url.openConnection() as HttpURLConnection

        try {
            conn.requestMethod = "POST"
            conn.connectTimeout = CONNECT_TIMEOUT
            conn.readTimeout = READ_TIMEOUT
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            conn.setRequestProperty("Authorization", "Bearer $apiToken")
            conn.setRequestProperty("User-Agent", "NetMonitor-Pro-Android/1.0")

            // 构建 JSON
            val eventsArray = JSONArray()
            for (event in batch) {
                eventsArray.put(event.toJson())
            }
            val payload = JSONObject().apply {
                put("events", eventsArray)
            }

            // 发送
            val body = payload.toString().toByteArray(Charsets.UTF_8)
            conn.setFixedLengthStreamingMode(body.size)

            BufferedOutputStream(conn.outputStream).use { out ->
                out.write(body)
                out.flush()
            }

            // 检查响应
            val responseCode = conn.responseCode
            if (responseCode in 200..207) {
                Log.d(TAG, "上报成功: ${batch.size} 条事件")
                return true
            } else {
                val errorBody = try {
                    conn.errorStream?.bufferedReader()?.readText() ?: ""
                } catch (e: Exception) { "" }
                lastError = "HTTP $responseCode: $errorBody"
                Log.w(TAG, "上报失败: HTTP $responseCode")
                return false
            }

        } finally {
            conn.disconnect()
        }
    }

    /**
     * 获取上报状态
     */
    fun getStatus(): Map<String, Any> = mapOf(
        "running" to isRunning.get(),
        "buffer_size" to buffer.size,
        "total_sent" to totalSent,
        "total_errors" to totalErrors,
        "last_error" to (lastError ?: ""),
    )
}
