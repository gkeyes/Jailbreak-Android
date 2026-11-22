plugins {
    id("com.android.application")
}

android {
    namespace = "com.gkeyes.lhasa26"
    compileSdk { version = release(37) { minorApiLevel = 2 } }

    defaultConfig {
        applicationId = "com.gkeyes.lhasa26"
        minSdk = 37
        targetSdk = 37
        versionCode = 306
        versionName = "0.3.6"
        resourceConfigurations += listOf("zh", "en")
    }

    signingConfigs {
        create("release") {
            // 签名材料只从环境变量来（本地导出或 CI Secrets），仓库和构建脚本里不留口令。
            val keystoreFile = rootProject.file(System.getenv("LHASA_KEYSTORE") ?: "keystore/lhasa26.jks")
            val storePassword = System.getenv("LHASA_STORE_PASSWORD")
            val keyAlias = System.getenv("LHASA_KEY_ALIAS")
            val keyPassword = System.getenv("LHASA_KEY_PASSWORD") ?: storePassword

            if (keystoreFile.exists() && !storePassword.isNullOrEmpty()) {
                storeFile = keystoreFile
                this.storePassword = storePassword
                this.keyAlias = keyAlias ?: "lhasa26"
                this.keyPassword = keyPassword
            } else if (keystoreFile.exists()) {
                logger.lifecycle(
                    "LHASA_STORE_PASSWORD 未设置，release 构建不走签名（照常产出未签名 APK）。"
                )
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            signingConfigs.findByName("release")?.let { signing ->
                if (signing.storeFile != null) {
                    signingConfig = signing
                }
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        resources.excludes += setOf("META-INF/DEPENDENCIES", "META-INF/LICENSE*", "META-INF/NOTICE*")
    }
}

dependencies {
    implementation("dev.rikka.shizuku:api:13.1.5")
    implementation("dev.rikka.shizuku:provider:13.1.5")
    implementation("androidx.activity:activity:1.12.4")
    implementation(project(":design:miuix-console:ui"))

    testImplementation("junit:junit:4.13.2")
}
