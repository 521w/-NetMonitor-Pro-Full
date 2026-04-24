# NetMonitor Pro — ProGuard 混淆规则
# 文件位置: android/app/proguard-rules.pro
#
# 新增文件: 原项目 release 未开启混淆，现在开启后需要此配置

# ── Retrofit ──
-keepattributes Signature
-keepattributes *Annotation*
-keep class retrofit2.** { *; }
-keepclasseswithmembers class * {
    @retrofit2.http.* <methods>;
}
-dontwarn retrofit2.**

# ── OkHttp ──
-dontwarn okhttp3.**
-dontwarn okio.**
-keep class okhttp3.** { *; }

# ── Gson ──
-keep class com.google.gson.** { *; }
-keepattributes EnclosingMethod
-keep class * implements com.google.gson.TypeAdapterFactory
-keep class * implements com.google.gson.JsonSerializer
-keep class * implements com.google.gson.JsonDeserializer

# ── 数据模型类（不混淆，Gson 需要反射） ──
-keep class com.netmonitor.pro.data.model.** { *; }
-keep class com.netmonitor.pro.api.model.** { *; }

# ── Xposed ──
-keep class de.robv.android.xposed.** { *; }
-dontwarn de.robv.android.xposed.**

# ── MPAndroidChart ──
-keep class com.github.mikephil.charting.** { *; }