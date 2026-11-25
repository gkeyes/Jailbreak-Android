import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey

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
val expectedReleaseSignerSha256 = "bba588fabfdf9ed2b5652dc78b033822e1c39b162025be1d5e04e18e4f66bbac"
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
                "Release builds require the current fixed signing key; no fallback is permitted."
        }
        val keystoreFile = checkNotNull(releaseKeystoreFile) {
            "The configured release keystore is missing."
        }
        check(keystoreFile.isFile) {
            "The configured release keystore does not exist or is not a regular file."
        }
        val storePassword = releaseSigningValues.getValue("LHASA_STORE_PASSWORD").toCharArray()
        val keyPassword = releaseSigningValues.getValue("LHASA_KEY_PASSWORD").toCharArray()
        try {
            val keyStore = KeyStore.getInstance("JKS")
            keystoreFile.inputStream().use { keyStore.load(it, storePassword) }
            val alias = releaseSigningValues.getValue("LHASA_KEY_ALIAS")
            check(keyStore.getKey(alias, keyPassword) is PrivateKey) {
                "The configured release alias must contain an accessible private key."
            }
            val certificate = checkNotNull(keyStore.getCertificate(alias)) {
                "The configured release alias has no certificate."
            }
            val actualSigner = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
                .joinToString("") { "%02x".format(it.toInt() and 0xff) }
            check(actualSigner == expectedReleaseSignerSha256) {
                "Release signing certificate is retired or unexpected; use the current fixed release key."
            }
        } finally {
            storePassword.fill('\u0000')
            keyPassword.fill('\u0000')
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
        // 0.4.1-dev：新固定签名身份的首个发布版（折叠屏布局/系统栏对比度修复 + 自适应图标）。
        // 每次发布都要 bump，否则 Releases 里会一直覆盖同一个 tag。
        versionCode = 308
        versionName = "0.4.1-dev"
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
            // 测试阶段关掉 R8：压缩要 4–6 分钟，还把栈帧混淆到没法看。
            // 要正式发布时把下面两行改回 true，并确认 proguard-rules.pro 完整。
            isMinifyEnabled = false
            isShrinkResources = false
            signingConfig = signingConfigs.getByName("release")
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


