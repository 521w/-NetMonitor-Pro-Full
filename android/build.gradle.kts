// NetMonitor Pro — Android 根构建配置 (优化版)
// 文件位置: android/build.gradle.kts
//
// 优化点:
//   1. AGP 和 Kotlin 版本升级到 2026 年主流稳定版

plugins {
    id("com.android.application") version "8.5.0" apply false
    id("org.jetbrains.kotlin.android") version "2.0.0" apply false
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

tasks.register("clean", Delete::class) {
    delete(rootProject.layout.buildDirectory)
}