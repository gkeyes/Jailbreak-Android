plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.gkeyes.lhasa26.ui"
    compileSdk { version = release(37) { minorApiLevel = 2 } }

    defaultConfig {
        minSdk = 37
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    api("androidx.compose.runtime:runtime:1.13.0-rc01")
    api("androidx.compose.ui:ui:1.13.0-rc01")
    implementation("androidx.compose.foundation:foundation:1.13.0-rc01")
    implementation("androidx.activity:activity-compose:1.12.4")
    val miuixVersion = "0.9.5-beta03"
    implementation("top.yukonga.miuix.kmp:miuix-ui:$miuixVersion")
    implementation("top.yukonga.miuix.kmp:miuix-blur:$miuixVersion")
    implementation("top.yukonga.miuix.kmp:miuix-glass:$miuixVersion")
    implementation("top.yukonga.miuix.kmp:miuix-glass-icons:$miuixVersion")
}
