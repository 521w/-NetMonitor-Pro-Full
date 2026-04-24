// NetMonitor Pro — Android App 模块构建配置 (优化版)
// 文件位置: android/app/build.gradle.kts
//
// 优化点:
//   1. targetSdk 升级到 35（2026 年 Google Play 要求）
//   2. compileSdk 升级到 35
//   3. Release 构建开启混淆 (isMinifyEnabled = true) 和资源压缩
//   4. 新增网络库依赖 (OkHttp + Retrofit)，解决原项目缺少 API 通信库的问题
//   5. 新增 Gson 序列化依赖
//   6. 升级 AndroidX 依赖到最新稳定版

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.netmonitor.pro"
    compileSdk = 35  // [优化] 从 34 升级到 35

    defaultConfig {
        applicationId = "com.netmonitor.pro"
        minSdk = 26
        targetSdk = 35  // [优化] 从 34 升级到 35，满足 Google Play 2026 要求
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // 构建配置字段：服务端地址（可通过 BuildConfig 访问）
        buildConfigField("String", "API_BASE_URL",
            "\"${project.findProperty("netmon.api.url") ?: "http://10.0.2.2:5000"}\"")
    }

    buildTypes {
        debug {
            isDebuggable = true
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        release {
            isMinifyEnabled = true      // [优化] 原为 false，APK 未混淆/未优化
            isShrinkResources = true    // [优化] 新增资源压缩，减小 APK 体积
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // 签名配置（生产环境需配置 signingConfigs）
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        viewBinding = true
        buildConfig = true
    }

    lint {
        abortOnError = false
        warningsAsErrors = false
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    // ── AndroidX 核心 ──
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    implementation("androidx.activity:activity-ktx:1.9.0")
    implementation("androidx.fragment:fragment-ktx:1.7.1")

    // ── Lifecycle (ViewModel + LiveData) ──
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.8.2")
    implementation("androidx.lifecycle:lifecycle-livedata-ktx:2.8.2")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.2")

    // ── RecyclerView (事件列表展示) ──
    implementation("androidx.recyclerview:recyclerview:1.3.2")
    implementation("androidx.swiperefreshlayout:swiperefreshlayout:1.1.0")

    // ── [优化] 网络库：OkHttp + Retrofit（原项目缺失，无法与 server API 通信）──
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")
    implementation("com.squareup.retrofit2:retrofit:2.11.0")
    implementation("com.squareup.retrofit2:converter-gson:2.11.0")

    // ── JSON 序列化 ──
    implementation("com.google.code.gson:gson:2.11.0")

    // ── 协程 ──
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // ── 图表库（网络流量可视化）──
    implementation("com.github.PhilJay:MPAndroidChart:v3.1.0")

    // ── WorkManager (后台定时同步) ──
    implementation("androidx.work:work-runtime-ktx:2.9.0")

    // ── Xposed API (系统级 hook，需要 root) ──
    compileOnly("de.robv.android.xposed:api:82")

    // ── 测试 ──
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
}