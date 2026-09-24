import java.util.Properties

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
}

// Baked secrets now live in :core (SecretsConfig moved here). Same gitignored
// secrets.properties at the repo root; missing file -> all values empty. The
// generated BuildConfig is com.openzeekr.core.BuildConfig.
val secretsProps = Properties().apply {
    val f = rootProject.file("secrets.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}
fun bakedSecret(key: String): String =
    (secretsProps.getProperty(key) ?: "").replace("\\", "\\\\").replace("\"", "\\\"")

android {
    namespace = "com.openzeekr.core"
    compileSdk = 34

    defaultConfig {
        minSdk = 26

        // ONLY the six/seven app-global secrets are baked (never the account).
        buildConfigField("String", "SEC_HMAC_ACCESS_KEY", "\"${bakedSecret("HMAC_ACCESS_KEY")}\"")
        buildConfigField("String", "SEC_HMAC_SECRET_KEY", "\"${bakedSecret("HMAC_SECRET_KEY")}\"")
        buildConfigField("String", "SEC_PASSWORD_PUBLIC_KEY", "\"${bakedSecret("PASSWORD_PUBLIC_KEY")}\"")
        buildConfigField("String", "SEC_PROD_SECRET", "\"${bakedSecret("PROD_SECRET")}\"")
        buildConfigField("String", "SEC_VIN_KEY", "\"${bakedSecret("VIN_KEY")}\"")
        buildConfigField("String", "SEC_VIN_IV", "\"${bakedSecret("VIN_IV")}\"")
        buildConfigField("String", "SEC_XCHANGER_SIGN_SECRET", "\"${bakedSecret("XCHANGER_SIGN_SECRET")}\"")
        // Overseas-app (Azure gateway) HMAC AK/SK — for the message inbox. Native
        // (getNativeApplicationId / getNativeSecret in libenv.so), Frida-dumped per region/env.
        buildConfigField("String", "SEC_OVERSEAS_ACCESS_KEY", "\"${bakedSecret("OVERSEAS_ACCESS_KEY")}\"")
        buildConfigField("String", "SEC_OVERSEAS_SECRET_KEY", "\"${bakedSecret("OVERSEAS_SECRET_KEY")}\"")
        // Inbox Authorization HS256 secret — signs the client-minted /overseas-app/* token
        // (InboxAuthToken). String-obfuscated in the stock APK, so Frida-dumped at runtime.
        buildConfigField("String", "SEC_INBOX_AUTH_SECRET", "\"${bakedSecret("INBOX_AUTH_SECRET")}\"")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { buildConfig = true }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

dependencies {
    // Exposed to :app and :wear (they use these types directly), hence `api`.
    api("androidx.core:core-ktx:1.13.1")
    api("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // Networking (cloud TSP)
    api("com.squareup.okhttp3:okhttp:4.12.0")
    api("com.squareup.okhttp3:logging-interceptor:4.12.0")
    api("com.squareup.retrofit2:retrofit:2.11.0")
    api("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    api("com.jakewharton.retrofit:retrofit2-kotlinx-serialization-converter:1.0.0")

    // Encrypted config storage
    api("androidx.security:security-crypto:1.1.0-alpha06")

    // Activity Recognition (proximity motion fallback when there's no hardware motion sensor)
    api("com.google.android.gms:play-services-location:21.3.0")

    // FCM push (car message-centre alarms while the screen is off). NO google-services plugin /
    // google-services.json — the default FirebaseApp auto-inits from the stock project's string
    // resources (core/src/main/res/values/secrets_firebase.xml) via FirebaseInitProvider, which
    // firebase-messaging pulls in transitively (firebase-common). `api` so :app inherits it.
    api(platform("com.google.firebase:firebase-bom:33.5.1"))
    api("com.google.firebase:firebase-messaging")

    // DK BLE crypto
    api("org.bouncycastle:bcprov-jdk18on:1.78.1")
    api("org.bouncycastle:bcpkix-jdk18on:1.78.1")

    // Offline crypto unit tests (RPA CMAC / ECIES key unwrap)
    testImplementation("junit:junit:4.13.2")
    // Exercise Android Base64.DEFAULT, including folding and the final LF.
    testImplementation("org.robolectric:robolectric:4.13")
}
