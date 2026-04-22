package com.netmonitor.pro.model

import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.*

/**
 * 网络事件数据模型
 * 统一表示 VPN 模式和 eBPF/Xposed 模式采集到的网络事件
 */
data class NetworkEvent(
    /** 事件时间戳（毫秒） */
    val timestamp: Long,

    /** 事件类型 */
    val eventType: EventType,

    /** IP 版本：4 或 6 */
    val ipVersion: Int,

    /** 协议名称：TCP / UDP / ICMP / ICMPv6 */
    val protocol: String,

    /** 源 IP 地址 */
    val srcAddr: String,

    /** 源端口 */
    val srcPort: Int,

    /** 目标 IP 地址 */
    val dstAddr: String,

    /** 目标端口 */
    val dstPort: Int,

    /** 发送字节数 */
    val bytesSent: Long = 0,

    /** 进程 ID（VPN 模式可能为 0） */
    val pid: Int = 0,

    /** 用户 ID */
    val uid: Int = 0,

    /** 进程名（VPN 模式可能为空） */
    val comm: String = "",

    /** 连接结果（仅 TCP_CONNECT_RET） */
    val connectResult: String? = null,

    /** 设备 ID */
    val deviceId: String? = null,

    /** 采集来源：vpn / ebpf / xposed */
    val source: CaptureSource = CaptureSource.VPN,
) {
    /** 是否为 DNS 查询 */
    val isDnsQuery: Boolean
        get() = eventType == EventType.DNS_QUERY || dstPort == 53

    /** 格式化时间 */
    val formattedTime: String
        get() {
            val sdf = SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault())
            return sdf.format(Date(timestamp))
        }

    /** 格式化完整时间 */
    val formattedDateTime: String
        get() {
            val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault())
            return sdf.format(Date(timestamp))
        }

    /** 连接摘要（用于 UI 列表展示） */
    val summary: String
        get() = "$protocol $srcAddr:$srcPort → $dstAddr:$dstPort"

    /** 转换为 JSON 对象（用于 API 上报） */
    fun toJson(): JSONObject = JSONObject().apply {
        put("timestamp", SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }.format(Date(timestamp)))
        put("event_type", eventType.apiName)
        put("ip_version", ipVersion)
        put("protocol", protocol)
        put("src_addr", srcAddr)
        put("src_port", srcPort)
        put("dst_addr", dstAddr)
        put("dst_port", dstPort)
        put("bytes_sent", bytesSent)
        put("pid", pid)
        put("uid", uid)
        put("comm", comm)
        connectResult?.let { put("connect_result", it) }
        deviceId?.let { put("device_id", it) }
    }

    /** 转换为 JSON 字符串 */
    fun toJsonString(): String = toJson().toString()
}

/**
 * 事件类型枚举
 */
enum class EventType(val code: Int, val displayName: String, val apiName: String) {
    TCP_CONNECT(1, "TCP 连接", "TCP_CONNECT"),
    TCP_CONNECT_RET(2, "TCP 连接结果", "TCP_CONNECT_RET"),
    UDP_SEND(3, "UDP 发送", "UDP_SEND"),
    TCP_CLOSE(4, "TCP 关闭", "TCP_CLOSE"),
    DNS_QUERY(5, "DNS 查询", "DNS_QUERY");

    companion object {
        fun fromCode(code: Int): EventType =
            entries.find { it.code == code } ?: TCP_CONNECT

        fun fromApiName(name: String): EventType =
            entries.find { it.apiName == name } ?: TCP_CONNECT
    }
}

/**
 * 采集来源
 */
enum class CaptureSource(val displayName: String) {
    VPN("VPN 模式"),
    EBPF("eBPF 模式"),
    XPOSED("Xposed 模式");
}
