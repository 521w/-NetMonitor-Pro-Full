package com.netmonitor.pro.xposed

import android.util.Log
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.net.InetSocketAddress

class NetMonitorHook : IXposedHookLoadPackage {
    companion object {
        const val TAG = "NetMonitorXposed"
    }

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        Log.i(TAG, "Hook loaded for: ${lpparam.packageName}")
        hookSocket(lpparam)
        hookOkHttp(lpparam)
        hookUrlConnection(lpparam)
    }

    private fun hookSocket(lpparam: XC_LoadPackage.LoadPackageParam) {
        try {
            XposedHelpers.findAndHookMethod(
                "java.net.Socket", lpparam.classLoader,
                "connect", java.net.SocketAddress::class.java, Int::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val addr = param.args[0] as? InetSocketAddress ?: return
                        Log.i(TAG, "[${lpparam.packageName}] Socket.connect -> ${addr.hostName}:${addr.port}")
                    }
                }
            )
        } catch (e: Exception) {
            Log.w(TAG, "Socket hook failed: ${e.message}")
        }
    }

    private fun hookOkHttp(lpparam: XC_LoadPackage.LoadPackageParam) {
        try {
            val callClass = XposedHelpers.findClass("okhttp3.internal.connection.RealCall", lpparam.classLoader)
            XposedHelpers.findAndHookMethod(callClass, "execute", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    try {
                        val request = XposedHelpers.callMethod(param.thisObject, "request")
                        val url = XposedHelpers.callMethod(request, "url")
                        Log.i(TAG, "[${lpparam.packageName}] OkHttp -> $url")
                    } catch (_: Exception) {}
                }
            })
        } catch (_: Exception) {
            Log.d(TAG, "OkHttp not found in ${lpparam.packageName}")
        }
    }

    private fun hookUrlConnection(lpparam: XC_LoadPackage.LoadPackageParam) {
        try {
            XposedHelpers.findAndHookMethod(
                "java.net.URL", lpparam.classLoader, "openConnection",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val url = param.thisObject as java.net.URL
                        Log.i(TAG, "[${lpparam.packageName}] URL.openConnection -> ${url.host}:${url.port}")
                    }
                }
            )
        } catch (e: Exception) {
            Log.w(TAG, "URL hook failed: ${e.message}")
        }
    }
}
