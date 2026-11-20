plugins {
    id("com.android.application")
}

android {
    namespace = "eu.appwerf.eapenroll"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "eu.appwerf.eapenroll"
        minSdk = 31
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
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
