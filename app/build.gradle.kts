plugins {
    id("com.android.application")
}

// Release signing is supplied only by the environment; debug builds need no release key.
val releaseSigningNames = listOf(
    "LHASA_KEYSTORE",
    "LHASA_STORE_PASSWORD",
    "LHASA_KEY_ALIAS",
    "LHASA_KEY_PASSWORD",
)
val releaseSigningValues = releaseSigningNames.associateWith { System.getenv(it).orEmpty() }
val releaseKeystoreFile = releaseSigningValues.getValue("LHASA_KEYSTORE")
    .takeIf { it.isNotBlank() }
    ?.let { rootProject.file(it).absoluteFile }

val verifyReleaseSigning = tasks.register("verifyReleaseSigning") {
    group = "verification"
    description = "Require externally supplied release signing credentials."
    doLast {
        val missing = releaseSigningNames.filter { releaseSigningValues.getValue(it).isBlank() }
        check(missing.isEmpty()) {
            "Missing release signing environment variables: ${missing.joinToString()}. " +
                "Release builds require the existing signing key; no fallback is permitted."
        }
        check(releaseKeystoreFile?.isFile == true) {
            "The configured release keystore does not exist or is not a regular file."
        }
    }
}

tasks.configureEach {
    if (name in setOf("preReleaseBuild", "packageRelease", "bundleRelease", "assembleRelease")) {
        dependsOn(verifyReleaseSigning)
    }
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
            storeFile = releaseKeystoreFile
            storePassword = releaseSigningValues.getValue("LHASA_STORE_PASSWORD").takeIf { it.isNotBlank() }
            keyAlias = releaseSigningValues.getValue("LHASA_KEY_ALIAS").takeIf { it.isNotBlank() }
            keyPassword = releaseSigningValues.getValue("LHASA_KEY_PASSWORD").takeIf { it.isNotBlank() }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            signingConfig = signingConfigs.getByName("release")
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
    implementation("androidx.activity:activity:1.12.4")
    implementation(project(":design:miuix-console:ui"))
}

