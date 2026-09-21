package com.openzeekr.app.net

import com.jakewharton.retrofit2.converter.kotlinx.serialization.asConverterFactory
import com.openzeekr.app.config.ConfigStore
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import java.util.concurrent.TimeUnit

/**
 * Builds the [TspApi]. The base URL is read from config at build time; if the
 * user changes it, call [rebuild]. Interceptor order:
 *   1. HeaderInterceptor  (adds x-api/device/auth headers)
 *   2. SignInterceptor    (signs the fully-decorated request)
 *   3. logging            (last, so it prints the signed request)
 */
class ApiClient private constructor(private val store: ConfigStore) {

    // NOTE: declared BEFORE retrofit/api so it is initialized before build() runs.
    // (Kotlin initializes properties top-to-bottom; build() uses `json`.)
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = false; isLenient = true }

    @Volatile private var retrofit: Retrofit = build()
    @Volatile var api: TspApi = retrofit.create(TspApi::class.java)
        private set

    // Separate client: Labs raw payloads must never enter the optional BODY logger.
    @Volatile internal var labsApi: TspApi = build(logBodies = false).create(TspApi::class.java)
        private set

    private fun build(logBodies: Boolean = true): Retrofit {
        // Route OkHttp logging into the on-device log (Logx) at BODY level so cloud
        // request/response bodies are visible on-device while debugging. The level is
        // flipped to NONE when debug logging is off, so with the toggle off OkHttp never
        // even formats request/response bodies (no tokens built into strings, nothing to leak).
        val logging = HttpLoggingInterceptor { m -> com.openzeekr.app.util.Logx.d("http", m) }
        val builder = OkHttpClient.Builder()
            .connectTimeout(20, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            // Watches every response for the 079021 "logged in elsewhere" kick-out.
            .addInterceptor(KickoutInterceptor(store))
            .addInterceptor(HeaderInterceptor(store))
            .addInterceptor(SignInterceptor(store))
            // Signs the overseas-app inbox host with its own HMAC AK/SK (the two above
            // passthrough for that host); no-op for every other request.
            .addInterceptor(OverseasAppAuthInterceptor(store))
        if (logBodies) builder
            // Gate the logging level per-request (interceptor runs just before `logging`,
            // which reads its level at the start of its own intercept()).
            .addInterceptor { chain ->
                logging.level = if (com.openzeekr.app.util.Logx.isHttpEnabled)
                    HttpLoggingInterceptor.Level.BODY else HttpLoggingInterceptor.Level.NONE
                chain.proceed(chain.request())
            }
            .addInterceptor(logging)
        val ok = builder.build()

        val base = store.current().baseUrl.trimEnd('/') + "/"
        return Retrofit.Builder()
            .baseUrl(base)
            .client(ok)
            .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
            .build()
    }

    /** Re-create the client after the base URL (or algo) changes. */
    fun rebuild() {
        retrofit = build()
        api = retrofit.create(TspApi::class.java)
        labsApi = build(logBodies = false).create(TspApi::class.java)
    }

    companion object {
        @Volatile private var INSTANCE: ApiClient? = null
        fun get(store: ConfigStore): ApiClient =
            INSTANCE ?: synchronized(this) { INSTANCE ?: ApiClient(store).also { INSTANCE = it } }
    }
}
