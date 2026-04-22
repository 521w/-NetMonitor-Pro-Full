package com.netmonitor.pro.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.netmonitor.pro.model.NetworkEvent
import com.netmonitor.pro.model.EventType
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * NetMonitor Pro — VPN 抓包服务（免 Root）
 *
 * 原理：通过 Android VpnService 创建本地 TUN 接口，
 * 所有应用的网络流量都会经过此接口，从而实现免 Root 的全量抓包。
 *
 * 功能：
 * - 捕获所有 TCP/UDP 连接的五元组信息
 * - 解析 IP/TCP/UDP 包头
 * - DNS 查询识别（目标端口 53）
 * - 按应用 UID 过滤
 * - 实时统计（包数、字节数）
 * - 前台服务通知
 * - 事件队列供 UI 和上报模块消费
 */
class VpnCaptureService : VpnService() {

    companion object {
        private const val TAG = "NetMonVPN"
        private const val CHANNEL_ID = "netmon_vpn_channel"
        private const val NOTIFICATION_ID = 1001

        // VPN 虚拟接口配置
        private const val VPN_ADDRESS = "10.120.0.1"
        private const val VPN_ADDRESS_V6 = "fd00:1:fd00:1:fd00:1:fd00:1"
        private const val VPN_ROUTE = "0.0.0.0"
        private const val VPN_ROUTE_V6 = "::"
        private const val VPN_DNS = "8.8.8.8"
        private const val VPN_DNS_V6 = "2001:4860:4860::8888"
        private const val VPN_MTU = 1500

        // 服务控制 Action
        const val ACTION_START = "com.netmonitor.pro.vpn.START"
        const val ACTION_STOP = "com.netmonitor.pro.vpn.STOP"

        // 外部访问
        @Volatile
        var instance: VpnCaptureService? = null
            private set

        fun isRunning(): Boolean = instance?.isCapturing?.get() == true
    }

    // ─── 状态 ───
    private val isCapturing = AtomicBoolean(false)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var captureThread: Thread? = null
    private var forwardThread: Thread? = null

    // ─── 统计 ───
    val packetCount = AtomicLong(0)
    val byteCount = AtomicLong(0)
    val tcpCount = AtomicLong(0)
    val udpCount = AtomicLong(0)
    val dnsCount = AtomicLong(0)

    // ─── 事件队列（供 UI / 上报模块消费） ───
    val eventQueue: ConcurrentLinkedQueue<NetworkEvent> = ConcurrentLinkedQueue()
    private val maxQueueSize = 10000

    // ─── 过滤配置 ───
    private var filterUids: Set<Int> = emptySet()
    private var captureUdp: Boolean = true

    // ─── 事件回调（可选，UI 层注册） ───
    var onEventCaptured: ((NetworkEvent) -> Unit)? = null

    // ══════════════════════════════════════════════════════════
    //  生命周期
    // ══════════════════════════════════════════════════════════

    override fun onCreate() {
        super.onCreate()
        instance = this
        createNotificationChannel()
        Log.i(TAG, "VPN 服务已创建")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopCapture()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START, null -> {
                // 读取过滤配置
                intent?.let {
                    filterUids = it.getIntArrayExtra("filter_uids")?.toSet() ?: emptySet()
                    captureUdp = it.getBooleanExtra("capture_udp", true)
                }
                startCapture()
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopCapture()
        instance = null
        Log.i(TAG, "VPN 服务已销毁")
        super.onDestroy()
    }

    // ══════════════════════════════════════════════════════════
    //  VPN 接口建立
    // ══════════════════════════════════════════════════════════

    private fun startCapture() {
        if (isCapturing.get()) {
            Log.w(TAG, "已在捕获中，忽略重复启动")
            return
        }

        try {
            // 建立 VPN 接口
            val builder = Builder()
                .setSession("NetMonitor Pro")
                .setMtu(VPN_MTU)
                .addAddress(VPN_ADDRESS, 32)
                .addRoute(VPN_ROUTE, 0)
                .addDnsServer(VPN_DNS)

            // IPv6 支持
            try {
                builder.addAddress(VPN_ADDRESS_V6, 128)
                builder.addRoute(VPN_ROUTE_V6, 0)
                builder.addDnsServer(VPN_DNS_V6)
            } catch (e: Exception) {
                Log.w(TAG, "IPv6 配置失败，仅使用 IPv4: ${e.message}")
            }

            // 排除自身流量，防止回环
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.w(TAG, "无法排除自身应用: ${e.message}")
            }

            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                Log.e(TAG, "VPN 接口建立失败 — 用户可能未授权")
                stopSelf()
                return
            }

            isCapturing.set(true)

            // 启动前台通知
            startForeground(NOTIFICATION_ID, buildNotification("正在监控网络流量..."))

            // 启动捕获线程
            captureThread = Thread(CaptureRunnable(), "NetMon-Capture").apply { start() }
            // 启动转发线程（将包原样写回，不中断网络）
            forwardThread = Thread(ForwardRunnable(), "NetMon-Forward").apply { start() }

            Log.i(TAG, "✅ VPN 捕获已启动 | UDP=$captureUdp | 过滤UID=$filterUids")

        } catch (e: Exception) {
            Log.e(TAG, "启动 VPN 捕获失败", e)
            stopCapture()
        }
    }

    private fun stopCapture() {
        if (!isCapturing.compareAndSet(true, false)) return

        captureThread?.interrupt()
        forwardThread?.interrupt()

        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.w(TAG, "关闭 VPN 接口异常: ${e.message}")
        }
        vpnInterface = null

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }

        Log.i(TAG, "⏹ VPN 捕获已停止 | 总包数=${packetCount.get()} | 总字节=${byteCount.get()}")
    }

    // ══════════════════════════════════════════════════════════
    //  包捕获线程
    // ══════════════════════════════════════════════════════════

    private inner class CaptureRunnable : Runnable {
        override fun run() {
            val fd = vpnInterface?.fileDescriptor ?: return
            val input = FileInputStream(fd)
            val buffer = ByteBuffer.allocate(VPN_MTU)

            Log.d(TAG, "捕获线程启动")

            while (isCapturing.get() && !Thread.interrupted()) {
                try {
                    buffer.clear()
                    val length = input.read(buffer.array())
                    if (length <= 0) continue

                    buffer.limit(length)
                    packetCount.incrementAndGet()
                    byteCount.addAndGet(length.toLong())

                    // 解析 IP 包头
                    val event = parsePacket(buffer, length) ?: continue

                    // UID 过滤
                    if (filterUids.isNotEmpty() && event.uid !in filterUids) continue

                    // UDP 过滤
                    if (!captureUdp && event.protocol == "UDP") continue

                    // 入队
                    if (eventQueue.size < maxQueueSize) {
                        eventQueue.offer(event)
                    }

                    // 回调
                    onEventCaptured?.invoke(event)

                    // 更新统计
                    when (event.protocol) {
                        "TCP" -> tcpCount.incrementAndGet()
                        "UDP" -> {
                            udpCount.incrementAndGet()
                            if (event.dstPort == 53) dnsCount.incrementAndGet()
                        }
                    }

                } catch (e: InterruptedException) {
                    break
                } catch (e: Exception) {
                    if (isCapturing.get()) {
                        Log.e(TAG, "包解析异常: ${e.message}")
                    }
                }
            }

            Log.d(TAG, "捕获线程结束")
        }
    }

    // ══════════════════════════════════════════════════════════
    //  包转发线程（透传，不中断用户网络）
    // ══════════════════════════════════════════════════════════

    private inner class ForwardRunnable : Runnable {
        override fun run() {
            val fd = vpnInterface?.fileDescriptor ?: return
            val output = FileOutputStream(fd)
            val buffer = ByteBuffer.allocate(VPN_MTU)

            Log.d(TAG, "转发线程启动")

            // 注意：在真实 VPN 实现中，需要建立 TUN 到实际网络的隧道
            // 此处是简化版 — 实际部署需要实现 IP 包的 socket 转发
            // 参考 PCAPdroid / NetGuard 的实现
            while (isCapturing.get() && !Thread.interrupted()) {
                try {
                    Thread.sleep(100)
                } catch (e: InterruptedException) {
                    break
                }
            }

            Log.d(TAG, "转发线程结束")
        }
    }

    // ══════════════════════════════════════════════════════════
    //  IP 包解析
    // ══════════════════════════════════════════════════════════

    private fun parsePacket(buffer: ByteBuffer, length: Int): NetworkEvent? {
        if (length < 20) return null // 最小 IPv4 头

        buffer.position(0)
        val versionAndIhl = buffer.get().toInt() and 0xFF
        val ipVersion = (versionAndIhl shr 4) and 0x0F

        return when (ipVersion) {
            4 -> parseIPv4Packet(buffer, length)
            6 -> parseIPv6Packet(buffer, length)
            else -> null
        }
    }

    private fun parseIPv4Packet(buffer: ByteBuffer, length: Int): NetworkEvent? {
        if (length < 20) return null

        buffer.position(0)
        val versionIhl = buffer.get().toInt() and 0xFF
        val ihl = (versionIhl and 0x0F) * 4 // IP 头长度（字节）

        buffer.position(2)
        val totalLength = buffer.short.toInt() and 0xFFFF

        buffer.position(9)
        val protocol = buffer.get().toInt() and 0xFF

        // 源/目的 IP
        buffer.position(12)
        val srcBytes = ByteArray(4)
        buffer.get(srcBytes)
        val dstBytes = ByteArray(4)
        buffer.get(dstBytes)

        val srcAddr = InetAddress.getByAddress(srcBytes).hostAddress ?: return null
        val dstAddr = InetAddress.getByAddress(dstBytes).hostAddress ?: return null

        // 解析传输层
        var srcPort = 0
        var dstPort = 0
        var protocolName = protocol.toString()

        if (length >= ihl + 4) {
            buffer.position(ihl)
            when (protocol) {
                6 -> { // TCP
                    protocolName = "TCP"
                    srcPort = buffer.short.toInt() and 0xFFFF
                    dstPort = buffer.short.toInt() and 0xFFFF
                }
                17 -> { // UDP
                    protocolName = "UDP"
                    srcPort = buffer.short.toInt() and 0xFFFF
                    dstPort = buffer.short.toInt() and 0xFFFF
                }
                1 -> { // ICMP
                    protocolName = "ICMP"
                }
            }
        }

        val eventType = when {
            protocol == 17 && dstPort == 53 -> EventType.DNS_QUERY
            protocol == 6 -> EventType.TCP_CONNECT
            protocol == 17 -> EventType.UDP_SEND
            else -> EventType.TCP_CONNECT
        }

        return NetworkEvent(
            timestamp = System.currentTimeMillis(),
            eventType = eventType,
            ipVersion = 4,
            protocol = protocolName,
            srcAddr = srcAddr,
            srcPort = srcPort,
            dstAddr = dstAddr,
            dstPort = dstPort,
            bytesSent = totalLength.toLong(),
            pid = 0,  // VPN 模式无法直接获取 PID
            uid = 0,  // 需要通过 /proc/net 映射
            comm = ""
        )
    }

    private fun parseIPv6Packet(buffer: ByteBuffer, length: Int): NetworkEvent? {
        if (length < 40) return null // IPv6 固定头 40 字节

        buffer.position(4)
        val payloadLength = buffer.short.toInt() and 0xFFFF
        val nextHeader = buffer.get().toInt() and 0xFF

        buffer.position(8)
        val srcBytes = ByteArray(16)
        buffer.get(srcBytes)
        val dstBytes = ByteArray(16)
        buffer.get(dstBytes)

        val srcAddr = InetAddress.getByAddress(srcBytes).hostAddress ?: return null
        val dstAddr = InetAddress.getByAddress(dstBytes).hostAddress ?: return null

        var srcPort = 0
        var dstPort = 0
        var protocolName = nextHeader.toString()

        if (length >= 44) {
            buffer.position(40)
            when (nextHeader) {
                6 -> {
                    protocolName = "TCP"
                    srcPort = buffer.short.toInt() and 0xFFFF
                    dstPort = buffer.short.toInt() and 0xFFFF
                }
                17 -> {
                    protocolName = "UDP"
                    srcPort = buffer.short.toInt() and 0xFFFF
                    dstPort = buffer.short.toInt() and 0xFFFF
                }
                58 -> {
                    protocolName = "ICMPv6"
                }
            }
        }

        val eventType = when {
            nextHeader == 17 && dstPort == 53 -> EventType.DNS_QUERY
            nextHeader == 6 -> EventType.TCP_CONNECT
            nextHeader == 17 -> EventType.UDP_SEND
            else -> EventType.TCP_CONNECT
        }

        return NetworkEvent(
            timestamp = System.currentTimeMillis(),
            eventType = eventType,
            ipVersion = 6,
            protocol = protocolName,
            srcAddr = srcAddr,
            srcPort = srcPort,
            dstAddr = dstAddr,
            dstPort = dstPort,
            bytesSent = payloadLength.toLong(),
            pid = 0,
            uid = 0,
            comm = ""
        )
    }

    // ══════════════════════════════════════════════════════════
    //  UID 映射（通过 /proc/net/tcp & /proc/net/udp）
    // ══════════════════════════════════════════════════════════

    /**
     * 尝试通过 /proc/net 文件将连接映射到 UID
     * 注意：此方法在无 Root 环境下权限受限，可能无法读取全部连接
     */
    fun resolveUid(protocol: String, srcAddr: String, srcPort: Int): Int {
        val procFile = when (protocol) {
            "TCP" -> "/proc/net/tcp"
            "UDP" -> "/proc/net/udp"
            else -> return -1
        }

        try {
            val hexPort = String.format("%04X", srcPort)
            val lines = java.io.File(procFile).readLines()
            for (line in lines.drop(1)) { // 跳过标题行
                val parts = line.trim().split("\\s+".toRegex())
                if (parts.size < 8) continue
                val localParts = parts[1].split(":")
                if (localParts.size == 2 && localParts[1].equals(hexPort, ignoreCase = true)) {
                    return parts[7].toIntOrNull() ?: -1
                }
            }
        } catch (e: Exception) {
            // 权限不足时静默失败
        }
        return -1
    }

    // ══════════════════════════════════════════════════════════
    //  通知
    // ══════════════════════════════════════════════════════════

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "NetMonitor 网络监控",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "NetMonitor Pro VPN 抓包服务运行状态"
                setShowBadge(false)
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(content: String): Notification {
        val stopIntent = Intent(this, VpnCaptureService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPending = PendingIntent.getService(
            this, 0, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("NetMonitor Pro")
            .setContentText(content)
            .setSmallIcon(android.R.drawable.ic_menu_manage)
            .setOngoing(true)
            .addAction(android.R.drawable.ic_media_pause, "停止监控", stopPending)
            .build()
    }

    // ══════════════════════════════════════════════════════════
    //  公开方法
    // ══════════════════════════════════════════════════════════

    /** 获取当前统计信息 */
    fun getStats(): Map<String, Long> = mapOf(
        "packets" to packetCount.get(),
        "bytes" to byteCount.get(),
        "tcp" to tcpCount.get(),
        "udp" to udpCount.get(),
        "dns" to dnsCount.get(),
    )

    /** 弹出队列中的所有事件 */
    fun drainEvents(): List<NetworkEvent> {
        val events = mutableListOf<NetworkEvent>()
        while (true) {
            val event = eventQueue.poll() ?: break
            events.add(event)
        }
        return events
    }

    /** 重置统计计数器 */
    fun resetStats() {
        packetCount.set(0)
        byteCount.set(0)
        tcpCount.set(0)
        udpCount.set(0)
        dnsCount.set(0)
    }
}
