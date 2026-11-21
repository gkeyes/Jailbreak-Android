plugins {
    id("com.android.application")
}

android {
    namespace = "com.gkeyes.lhasa26"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.gkeyes.lhasa26"
        minSdk = 26
        targetSdk = 35
        versionCode = 103
        versionName = "0.1.3"
    }

    // Fixed release key so later builds keep the same signature and can overwrite-install.
    // The keystore is created once by CI (see .github/workflows/build.yml) and then reused.
    signingConfigs {
        create("release") {
            val keystoreFile = rootProject.file(System.getenv("LHASA_KEYSTORE") ?: "keystore/lhasa26.jks")
            if (keystoreFile.exists()) {
                storeFile = keystoreFile
                storePassword = System.getenv("LHASA_STORE_PASSWORD") ?: "lhasa26pass"
                keyAlias = System.getenv("LHASA_KEY_ALIAS") ?: "lhasa26"
                keyPassword = System.getenv("LHASA_KEY_PASSWORD") ?: "lhasa26pass"
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            isShrinkResources = false
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
}
