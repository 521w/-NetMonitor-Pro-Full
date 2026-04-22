package com.netmonitor.pro.vpn

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log

/**
 * NetMonitor Pro — VPN 控制器
 *
 * 提供给 UI 层调用的简洁 API，封装 VPN 权限请求、启动/停止逻辑
 *
 * 用法:
 *   val controller = VpnController(context)
 *   // 在 Activity 中请求权限
 *   controller.requestPermissionIfNeeded(activity, REQUEST_CODE)
 *   // 权限通过后启动
 *   controller.start()
 *   // 停止
 *   controller.stop()
 */
class VpnController(private val context: Context) {

    companion object {
        private const val TAG = "VpnController"
        const val VPN_PERMISSION_REQUEST_CODE = 10086
    }

    // ─── 配置 ───
    private var filterUids: IntArray = intArrayOf()
    private var captureUdp: Boolean = true
    private var apiUrl: String? = null
    private var apiToken: String? = null

    private var reporter: ApiReporter? = null

    /**
     * 设置 UID 过滤（可选）
     * 传空数组 = 全量采集
     */
    fun setFilterUids(uids: IntArray): VpnController {
        filterUids = uids
        return this
    }

    /**
     * 是否采集 UDP 流量
     */
    fun setCaptureUdp(enabled: Boolean): VpnController {
        captureUdp = enabled
        return this
    }

    /**
     * 配置 API 上报（可选）
     */
    fun setApiConfig(url: String, token: String): VpnController {
        apiUrl = url
        apiToken = token
        return this
    }

    /**
     * 检查是否需要 VPN 权限，如需要则弹出系统授权对话框
     *
     * @return true = 已有权限可直接启动, false = 需要等待 onActivityResult
     */
    fun requestPermissionIfNeeded(activity: Activity, requestCode: Int = VPN_PERMISSION_REQUEST_CODE): Boolean {
        val intent = VpnService.prepare(activity)
        return if (intent != null) {
            // 需要用户授权
            activity.startActivityForResult(intent, requestCode)
            false
        } else {
            // 已有权限
            true
        }
    }

    /**
     * 处理权限请求结果（在 Activity.onActivityResult 中调用）
     *
     * @return true = 用户授权成功
     */
    fun handlePermissionResult(requestCode: Int, resultCode: Int): Boolean {
        if (requestCode != VPN_PERMISSION_REQUEST_CODE) return false
        return resultCode == Activity.RESULT_OK
    }

    /**
     * 启动 VPN 捕获
     */
    fun start() {
        // 再次检查权限
        val prepareIntent = VpnService.prepare(context)
        if (prepareIntent != null) {
            Log.e(TAG, "VPN 权限未授予，无法启动")
            return
        }

        val intent = Intent(context, VpnCaptureService::class.java).apply {
            action = VpnCaptureService.ACTION_START
            putExtra("filter_uids", filterUids)
            putExtra("capture_udp", captureUdp)
        }

        context.startForegroundService(intent)

        // 启动 API 上报器（如果配置了）
        if (apiUrl != null && apiToken != null) {
            reporter = ApiReporter(
                context = context,
                apiUrl = apiUrl!!,
                apiToken = apiToken!!,
            ).also { it.start() }

            // 注册事件回调
            // 延迟等服务启动
            android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                VpnCaptureService.instance?.onEventCaptured = { event ->
                    reporter?.enqueue(event)
                }
            }, 1000)
        }

        Log.i(TAG, "VPN 捕获启动请求已发送")
    }

    /**
     * 停止 VPN 捕获
     */
    fun stop() {
        reporter?.stop()
        reporter = null

        val intent = Intent(context, VpnCaptureService::class.java).apply {
            action = VpnCaptureService.ACTION_STOP
        }
        context.startService(intent)

        Log.i(TAG, "VPN 捕获停止请求已发送")
    }

    /**
     * 当前是否在捕获
     */
    fun isRunning(): Boolean = VpnCaptureService.isRunning()

    /**
     * 获取实时统计
     */
    fun getStats(): Map<String, Long> {
        return VpnCaptureService.instance?.getStats() ?: emptyMap()
    }

    /**
     * 获取上报状态
     */
    fun getReporterStatus(): Map<String, Any> {
        return reporter?.getStatus() ?: emptyMap()
    }

    /**
     * 弹出所有已捕获事件
     */
    fun drainEvents(): List<com.netmonitor.pro.model.NetworkEvent> {
        return VpnCaptureService.instance?.drainEvents() ?: emptyList()
    }
}
