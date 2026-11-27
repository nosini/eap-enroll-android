import java.util.Properties

plugins {
    id("com.android.application")
}

val keystoreProperties = Properties().apply {
    val file = rootProject.file("keystore.properties")
    if (file.exists()) file.inputStream().use(::load)
}

fun signingValue(property: String, env: String): String? =
    System.getenv(env)?.takeIf { it.isNotBlank() }
        ?: keystoreProperties.getProperty(property)?.takeIf { it.isNotBlank() }

android {
    namespace = "eu.appwerf.eapenroll"
    // Pinned, also for apksigner in CI (.github/workflows/build.yml).
    buildToolsVersion = "37.0.0"
    compileSdk {
        version = release(37) {
            minorApiLevel = 2
        }
    }

    defaultConfig {
        applicationId = "eu.appwerf.eapenroll"
        minSdk = 31
        targetSdk = 37
        versionCode = 8
        versionName = "0.4.0"
    }

    signingConfigs {
        // Self-signed release key for sideloading. CI passes it through SIGNING_*
        // environment variables; local builds read the gitignored
        // keystore.properties, with environment variables taking precedence.
        // Without a storeFile the release APK is left unsigned. Once a storeFile
        // is given, the file and the other values are required.
        val storeFile = signingValue("storeFile", "SIGNING_STORE_FILE")
        if (storeFile != null) {
            val file = rootProject.file(storeFile)
            if (!file.exists()) {
                throw GradleException(
                    "keystore.properties / SIGNING_* incomplete: storeFile not found: ${file.path}",
                )
            }
            val storePassword = signingValue("storePassword", "SIGNING_STORE_PASSWORD")
                ?: throw GradleException(
                    "keystore.properties / SIGNING_* incomplete: storePassword not set",
                )
            val keyAlias = signingValue("keyAlias", "SIGNING_KEY_ALIAS")
                ?: throw GradleException(
                    "keystore.properties / SIGNING_* incomplete: keyAlias not set",
                )
            create("release") {
                this.storeFile = file
                this.storePassword = storePassword
                this.keyAlias = keyAlias
                keyPassword = signingValue("keyPassword", "SIGNING_KEY_PASSWORD") ?: storePassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    // Android has org.json built in; the unit tests run on the JVM against a stub android.jar.
    testImplementation("org.json:json:20260814")
}
