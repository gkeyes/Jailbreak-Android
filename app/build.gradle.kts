plugins {
    id("com.android.application")
}

/** 读 keystore/keystore.properties；缺文件时返回空表。 */
fun readSigningProperties(): Map<String, String> {
    val file = rootProject.file("keystore/keystore.properties")
    if (!file.exists()) {
        return emptyMap()
    }
    val properties = java.util.Properties()
    file.inputStream().use { properties.load(it) }
    val result = mutableMapOf<String, String>()
    for (name in properties.stringPropertyNames()) {
        properties.getProperty(name)?.let { value -> result[name] = value }
    }
    return result
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
            // 取值顺序：环境变量 → keystore/keystore.properties → 不签名。
            // 环境变量优先，是为了以后想把口令挪到 Secrets 时不用改这里。
            val stored = readSigningProperties()
            val keystorePath = System.getenv("LHASA_KEYSTORE")
                ?: stored["storeFile"]
                ?: "keystore/lhasa26.jks"
            val keystoreFile = rootProject.file(keystorePath)
            val storePass = System.getenv("LHASA_STORE_PASSWORD") ?: stored["storePassword"]

            if (keystoreFile.exists() && !storePass.isNullOrEmpty()) {
                val keyPass = System.getenv("LHASA_KEY_PASSWORD")
                    ?: stored["keyPassword"]
                    ?: storePass
                storeFile = keystoreFile
                this.storePassword = storePass
                this.keyAlias = System.getenv("LHASA_KEY_ALIAS")
                    ?: stored["keyAlias"]
                    ?: "lhasa26"
                this.keyPassword = keyPass
            } else {
                logger.lifecycle(
                    "没有可用的签名材料（keystore 缺失或口令为空），release 构建产出未签名 APK。"
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
