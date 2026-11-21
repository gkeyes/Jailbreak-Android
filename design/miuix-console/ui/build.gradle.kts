plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.gkeyes.lhasa26.ui"
    compileSdk = 37

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
    api("androidx.compose.runtime:runtime:1.12.0")
    api("androidx.compose.ui:ui:1.12.0")
    implementation("androidx.compose.foundation:foundation:1.12.0")
    implementation("androidx.activity:activity-compose:1.12.4")
    implementation("top.yukonga.miuix.kmp:miuix-ui:0.9.4")
}
