package com.openzeekr.app.net

import android.util.Base64
import com.openzeekr.app.config.ConfigStore
import com.openzeekr.app.util.Logx
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

/**
 * The real Zeekr account login, ported from `zeekr_ev_api` (EU). Runs the
 * multi-step flow across the user-center host (X-HMAC signed) and the TSP
 * gateway (X-SIGNATURE signed), and writes accessToken + userId + vin into config.
 *
 *   checkUserV2 -> loginByEmailEncrypt -> user/info -> tspCode -> bearer_login
 *   -> vehicle-list (for VIN)
 *
 * (EU hosts are used directly; the region/url discovery step is skipped since
 * this build is EU-only. Add it back for multi-region.)
 */
class AccountLogin(private val store: ConfigStore) {

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }
    private val jsonMedia = "application/json; charset=UTF-8".toMediaType()

    /** user-center session token (from loginByEmailEncrypt), added to later UC calls. */
    @Volatile private var ucToken: String = ""

    // Login clients deliberately have no HTTP logger: headers and responses contain credentials.
    // user-center client: DEFAULT_HEADERS + X-HMAC-* (key = hmac_access/secret)
    private val ucClient = OkHttpClient.Builder()
        .addInterceptor(UcInterceptor())
        .build()
    // TSP client: LOGGED_IN_HEADERS + X-SIGNATURE (key = prod_secret) — reuses the app transport
    private val tspClient = OkHttpClient.Builder()
        .addInterceptor(HeaderInterceptor(store))
        .addInterceptor(SignInterceptor(store))
        .build()
    // xchanger (ECARX DK backend) client — plain; the authCode in the body is the auth.
    private val xchangerClient = OkHttpClient.Builder()
        .build()

    private inner class UcInterceptor : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val cfg = store.current()
            val req = chain.request()
            val b = req.newBuilder()
            userCenterHeaders(cfg.countryCode, req.url.encodedPath).forEach { (k, v) -> if (req.header(k) == null) b.header(k, v) }
            if (ucToken.isNotBlank()) b.header("authorization", ucToken)
            val bodyBytes = req.body?.let { okio.Buffer().use { buf -> it.writeTo(buf); buf.readByteArray() } }
            val h = Signing.usercenterHmac(req.method, req.url.toString(), cfg.hmacAccessKey, cfg.hmacSecretKey, bodyBytes)
            b.header("X-HMAC-ALGORITHM", h.algorithm)
                .header("X-HMAC-SIGNATURE", h.signature)
                .header("X-HMAC-ACCESS-KEY", h.accessKey)
                .header("X-HMAC-DIGEST", h.digest)
                .header("X-DATE", h.date)
            return chain.proceed(b.build())
        }
    }

    suspend fun login(): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val cfg = store.current()
            Logx.d("login", "=== login start ===")

            require(cfg.email.isNotBlank() && cfg.password.isNotBlank()) { "email/password not set (enter them in Settings → Account)" }
            require(cfg.hmacAccessKey.isNotBlank() && cfg.hmacSecretKey.isNotBlank()) { "hmac keys not set" }
            require(cfg.prodSecret.isNotBlank()) { "prod_secret not set" }
            val uc = cfg.usercenterUrl
            val tsp = cfg.baseUrl.trimEnd('/') + "/"

            // 1. check user exists (CANARY: validates the user-center HMAC before
            //    any password is ever submitted, so a transport bug can't cause a
            //    failed-password lockout).
            Logx.d("login", "step 1/6 checkUserV2 …")
            ucPost("$uc${ZeekrConst.CHECKUSER_URL}", buildJsonObject {
                put("email", cfg.email); put("checkType", "1")
            })
            Logx.d("login", "step 1/6 checkUserV2 OK")

            // 2. login (RSA-encrypted password) -> user-center token
            Logx.d("login", "step 2/6 loginByEmailEncrypt …")
            val encPw = encryptPassword(cfg.password, cfg.passwordPublicKey)
            val loginData = ucPost("$uc${ZeekrConst.LOGIN_URL}", buildJsonObject {
                put("code", ""); put("codeId", ""); put("email", cfg.email); put("password", encPw)
            })
            val tokenName = loginData?.get("tokenName")?.jsonPrimitive?.contentOrNull
            val tokenValue = loginData?.get("tokenValue")?.jsonPrimitive?.contentOrNull
            require(tokenName == "Authorization" && !tokenValue.isNullOrBlank()) { "login token missing ($tokenName)" }
            ucToken = tokenValue
            // Persist it: this server-issued token IS the Authorization for every azure/overseas
            // call (inbox/notifications). Not the TSP bearer, not client-minted. (Confirmed 2026-09-16.)
            store.update { it.copy(azureToken = tokenValue) }

            // 3. user info -> numeric userId
            Logx.d("login", "step 3/6 user/info …")
            val info = ucPost("$uc${ZeekrConst.USERINFO_URL}", null)
            val userId = info?.get("userId")?.jsonPrimitive?.contentOrNull
                ?: info?.get("id")?.jsonPrimitive?.contentOrNull
            val accountUuid = info?.get("uuid")?.jsonPrimitive?.contentOrNull

            // 4. tsp code
            Logx.d("login", "step 4/6 tspCode …")
            val tspCodeData = ucGet("$uc${ZeekrConst.TSPCODE_URL}?tspClientId=${ZeekrConst.CLIENT_ID}")
            val tspCode = tspCodeData?.get("code")?.jsonPrimitive?.contentOrNull
                ?: error("no tsp code")

            // 4b. xchanger (ECARX) DK-backend session. The stock app authenticates here after
            //     login; this is the registration path that makes the VEHICLE accept our device
            //     for BLE DK. Without it the car answers 0x0102 with EEC_confirmFailed (0x1010)
            //     instead of EEC_notAuthenticated (0x1011). Uses a SECOND OAuth client
            //     (app-authorization 1009). Best-effort — never blocks TSP login.
            runCatching {
                Logx.d("login", "step 4b xchanger tspCode (client ${ZeekrConst.XCHANGER_CLIENT_ID}) …")
                val xCodeData = exec(ucClient, Request.Builder()
                    .url("$uc${ZeekrConst.TSPCODE_URL}?tspClientId=${ZeekrConst.XCHANGER_CLIENT_ID}")
                    .header("app-authorization", "1009")
                    .header("client-id", ZeekrConst.XCHANGER_CLIENT_ID)
                    .get().build())
                val xAuthCode = xCodeData?.get("code")?.jsonPrimitive?.contentOrNull ?: error("no xchanger authCode")
                // Full HF headers: device-identity (HFOkHttpClientUtil$RequestInterceptor) PLUS the
                // X-SIGNATURE/X-TIMESTAMP the SignInterceptor adds (see hfSign). X-DEVICE-IDENTIFIER
                // is normally native getMobileId — we supply our own stable value.
                val nonce = java.util.UUID.randomUUID().toString()
                val devId = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(cfg.deviceIdentifier.ifBlank { "openzeekr" }.toByteArray())
                    .copyOf(16).joinToString("") { "%02x".format(it) }
                // HF signature (SignInterceptor / SignUtil.sign): HMAC-SHA1 over a canonical
                // string, keyed by getSignSecret()==appSecret==NativeSecretLib.getTSPSecretValue
                // ("EU","ONLINE") — the SAME value as our prod_secret (both TSP + HF stacks share
                // this SignInterceptor). Without X-SIGNATURE the server returns 1440 "验签签名不存在".
                val bodyStr = buildJsonObject { put("authCode", xAuthCode) }.toString()
                val ts = System.currentTimeMillis().toString()
                val hfKey = cfg.xchangerSignSecret.ifBlank {
                    Logx.w("login", "step 4b: xchanger_sign_secret not set — signature will fail (add it to secrets)")
                    cfg.xchangerSignSecret
                }
                val sig = hfSign(
                    signSecret = hfKey,
                    url = cfg.xchangerSessionUrl,
                    method = "POST",
                    body = bodyStr,
                    nonce = nonce,
                    sigVersion = "1.0",
                    timestamp = ts,
                    accept = ZeekrConst.XCHANGER_ACCEPT,
                )
                // xchanger uses its own envelope {code:1000, data:{…}} (not the 000000/success one),
                // so read the raw root and accept 1000 as success.
                // Header set mirrors stock's HFOkHttpClientUtil$RequestInterceptor for ZEEKR.
                // Only Accept + X-api-* participate in the signature; the rest are unsigned.
                // (No PLATFORM header — stock adds it only for GEELY/CMA operators, not ZEEKR.)
                val xRoot = execRoot(xchangerClient, Request.Builder()
                    .url(cfg.xchangerSessionUrl)
                    .header("urlname", "user-api")
                    .header("X-APP-ID", ZeekrConst.XCHANGER_APP_ID)
                    .header("Accept", ZeekrConst.XCHANGER_ACCEPT)
                    .header("Connection", "close")
                    .header("X-AGENT-TYPE", "android")
                    .header("X-DEVICE-TYPE", "mobile")
                    .header("X-OPERATOR-CODE", ZeekrConst.XCHANGER_OPERATOR)
                    .header("X-DEVICE-IDENTIFIER", devId)
                    .header("X-ENV-TYPE", "production")
                    .header("Accept-Encoding", "identity")
                    .header("X-VERSION", "zeekrNew")
                    .header("X-TIMEZONE", java.util.TimeZone.getDefault().id)
                    .header("Accept-Language", "en_US")
                    .header("X-api-signature-version", "1.0")
                    .header("X-api-signature-nonce", nonce)
                    .header("X-DEVICE-MANUFACTURE", ZeekrConst.XCHANGER_DEVICE_MANUFACTURE)
                    .header("X-DEVICE-BRAND", ZeekrConst.XCHANGER_DEVICE_BRAND)
                    .header("X-DEVICE-MODEL", ZeekrConst.XCHANGER_DEVICE_MODEL)
                    .header("X-DEVICE-RELEASE-DATE", "")
                    .header("X-AGENT-VERSION", ZeekrConst.XCHANGER_AGENT_VERSION)
                    .header("X-SIGNATURE", sig)
                    .header("X-TIMESTAMP", ts)
                    .post(bodyStr.toRequestBody(jsonMedia))
                    .build())
                val xCode = xRoot?.get("code")?.jsonPrimitive?.contentOrNull
                val xData = xRoot?.get("data")?.let { if (it is JsonObject) it else null }
                if (xCode != "1000" || xData == null) {
                    val xErr = xRoot?.get("error")?.let { if (it is JsonObject) it else null }
                    error("xchanger session code=$xCode err=${xErr?.get("code")?.jsonPrimitive?.contentOrNull} ${xErr?.get("message")?.jsonPrimitive?.contentOrNull ?: ""}")
                }
                val xClientId = xData["clientId"]?.jsonPrimitive?.contentOrNull
                val xToken = xData["accessToken"]?.jsonPrimitive?.contentOrNull
                store.update { it.copy(xchangerClientId = xClientId ?: "", xchangerToken = xToken ?: "") }
            }.onFailure { Logx.w("login", "step 4b xchanger session FAILED: details omitted") }

            // 4c. Register THIS device as the account's active push endpoint (zom-message-core).
            //     Stock does this on login; it is what claims the single-device session — logging
            //     the app on any OTHER device out. We believe "active device" is also what the
            //     car routes its DK to, so without this openzeekr never displaces the old device.
            //     Best-effort. deviceToken is a stable dummy (we don't receive FCM pushes); the
            //     backend registers it as this account's SNS endpoint regardless.
            runCatching {
                val deviceToken = "OZ" + cfg.deviceIdentifier.replace("-", "").take(140)
                val eqBody = buildJsonObject {
                    put("appId", "10008"); put("deviceToken", deviceToken)
                    put("platformType", 1); put("receive", accountUuid ?: ""); put("region", cfg.snsRegion)
                }
                Logx.d("login", "step 4c equipment/relation register (push device, claims session) …")
                val eqRoot = execRoot(ucClient, Request.Builder()
                    .url("${cfg.messageCoreUrl}/open-api/v1/mcs/notice/receiver/equipment/relation/sycn")
                    .header("app-authorization", "1009")
                    .header("client-id", ZeekrConst.XCHANGER_CLIENT_ID)
                    .header("msgClientId", "1009")
                    .header("msgAppId", "10008")
                    .header("Brand", "ZEEKR")
                    .post(eqBody.toString().toRequestBody(jsonMedia))
                    .build())
                Logx.d("login", "step 4c equipment register completed")
            }.onFailure { Logx.w("login", "step 4c equipment register FAILED: details omitted") }

            // 5. bearer login (TSP) -> accessToken
            Logx.d("login", "step 5/6 bearer_login (TSP) …")
            // The device-session fields MUST be in the stock format "brand-model-sdkInt-release"
            // (e.g. "google-Pixel 6a-30-11"). The backend registers/evicts device sessions by
            // loginDeviceId; a non-standard value is not treated as a real device (so it neither
            // claims the active-device slot nor logs other devices out). We present as the same
            // Pixel 6a identity we already spoof to xchanger, so the whole login is one device.
            val loginDeviceId = "${ZeekrConst.XCHANGER_DEVICE_MANUFACTURE}-${ZeekrConst.XCHANGER_DEVICE_MODEL}-30-${ZeekrConst.XCHANGER_AGENT_VERSION}"
            val bearerData = tspPost("$tsp${ZeekrConst.BEARERLOGIN_URL}", buildJsonObject {
                put("identifier", tspCode); put("identityType", 10)
                put("loginDeviceId", loginDeviceId)
                put("loginDeviceJgId", ""); put("loginDeviceType", 1)
                put("loginPhoneBrand", ZeekrConst.XCHANGER_DEVICE_MANUFACTURE)
                put("loginPhoneModel", ZeekrConst.XCHANGER_DEVICE_MODEL)
                put("loginSystem", "Android")
            })
            val bearer = bearerData?.get("accessToken")?.jsonPrimitive?.contentOrNull
                ?: error("no bearer token")

            // The numeric userId (needed for DK signing = userId+deviceId+vin) is NOT
            // in user/info (that returns only the uuid) — it's a claim in the TSP
            // bearer JWT. Extract it from there.
            val jwtUserId = jwtClaim(bearer, "userId")

            // persist token+userId (+ account openId for the inbox HS256 token, see
            // InboxAuthToken) BEFORE the vehicle-list call (it needs auth)
            store.update { it.copy(
                accessToken = bearer,
                userId = jwtUserId ?: userId ?: it.userId,
                accountUuid = accountUuid ?: it.accountUuid,
            ) }

            // 6. vehicle list -> VIN (first vehicle)
            Logx.d("login", "step 6/6 vehicle-list …")
            runCatching {
                val vehData = tspGetArray("$tsp${ZeekrConst.VEHLIST_URL}")
                val first = vehData?.firstOrNull()?.jsonObject
                val vin = first?.get("vin")?.jsonPrimitive?.contentOrNull
                val isOwner = first?.get("isOwner")?.jsonPrimitive?.booleanOrNull ?: false
                if (!vin.isNullOrBlank()) {
                    store.update { it.copy(vin = vin, isOwner = isOwner) }
                } else {
                    Logx.w("login", "step 6/6 vehicle-list returned no vin (enter it manually if needed)")
                }
            }.onFailure { Logx.w("login", "step 6/6 vehicle-list failed: details omitted") }

            // 7. app online heartbeat — marks THIS device (app-instance UUID) as the account's
            //    ONLINE device in ms-app-online-manager. Stock heartbeats this continuously; being
            //    the online device is very likely what makes the vehicle route/accept its DK to us.
            runCatching { heartbeat() }.onFailure { Logx.w("login", "step 7 app/hb failed: details omitted") }

            Logx.d("login", "=== login SUCCESS ===")
            Unit
        }.onFailure { Logx.e("login", "=== login FAILED (see safe status code) ===") }
    }

    // ---- helpers ----

    /**
     * Mark this device as the account's ONLINE device (ms-app-online-manager/app/hb). Uses the
     * app-instance UUID (same as X-DEVICE-ID). Stock sends this continuously; being "online" is
     * likely what makes the vehicle route/accept its DK to us. Safe to call repeatedly.
     */
    suspend fun heartbeat(): Unit = withContext(Dispatchers.IO) {
        val cfg = store.current()
        val tsp = cfg.baseUrl.trimEnd('/') + "/"
        val body = buildJsonObject {
            put("deviceId", cfg.appInstanceId); put("deviceType", 1)
            put("hbType", 3); put("ts", System.currentTimeMillis())
        }
        tspPost("${tsp}ms-app-online-manager/api/v1.0/app/hb", body)
    }

    /** Extract a string claim from a JWT bearer token ("Bearer <header>.<payload>.<sig>"). */
    private fun jwtClaim(token: String, claim: String): String? = runCatching {
        val jwt = token.removePrefix("Bearer ").trim()
        val payload = jwt.split(".").getOrNull(1) ?: return null
        val decoded = String(Base64.decode(payload, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING), Charsets.UTF_8)
        json.parseToJsonElement(decoded).jsonObject[claim]?.jsonPrimitive?.contentOrNull
    }.getOrNull()


    /**
     * Replicates `com/baselinelibrary/sign/SignUtil.sign` (the HF/xchanger `SignInterceptor`).
     * HMAC-SHA1, keyed by getSignSecret() == appSecret == NativeSecretLib.getTSPSecretValue
     * ("EU","ONLINE") == our prod_secret (TSP + HF stacks share this one SignInterceptor).
     * stringToSign = getHeaders + "\n" + getParam + "\n" + getMD5(body) + timestamp + "\n"
     *                + method + "\n" + getUrl   ; result = Base64(HMAC).trim().
     * getMD5 uses android Base64.DEFAULT (keeps a trailing '\n') — matched exactly here.
     * We send only X-api-* headers (no Accept), so getHeaders is just those two lines.
     */
    private fun hfSign(
        signSecret: String, url: String, method: String, body: String,
        nonce: String, sigVersion: String, timestamp: String, accept: String,
    ): String {
        // getHeaders: FIRST the "Accept" header's trimmed VALUE + '\n' (if present), THEN every
        // request header whose name startsWith "X-api", TreeMap-sorted by name, emitted as
        // name.lowercase() + ':' + value.trim() + '\n' (nonce sorts before version).
        val headerLines = sortedMapOf(
            "X-api-signature-nonce" to nonce,
            "X-api-signature-version" to sigVersion,
        )
        val headersPart = buildString {
            if (accept.isNotEmpty()) { append(accept.trim()); append('\n') }
            for ((k, v) in headerLines) { append(k.lowercase()); append(':'); append(v.trim()); append('\n') }
        }
        // getParam: query params sorted "k=v&k2=v2" (leading '&' dropped), value replacements.
        val query = url.substringAfter('?', "")
        val params = sortedMapOf<String, String>()
        if (query.isNotEmpty()) for (pair in query.split("&")) {
            val i = pair.indexOf('='); if (i >= 0) params[pair.substring(0, i)] = pair.substring(i + 1)
        }
        val paramsPart = params.entries.joinToString("&") { (k, v) ->
            val ev = v.replace("+", "%20").replace("*", "%2A").replace("%7E", "~").replace(",", "%2C")
            "$k=$ev"
        }
        // getMD5(body): android Base64.DEFAULT of MD5(utf-8) — DEFAULT appends a trailing '\n'.
        val md5 = java.security.MessageDigest.getInstance("MD5").digest(body.toByteArray(Charsets.UTF_8))
        val md5Part = Base64.encodeToString(md5, Base64.DEFAULT)
        // getUrl: path only (strip scheme+host, up to '?').
        val afterScheme = url.substringAfter("://")
        val slash = afterScheme.indexOf('/')
        val path = if (slash < 0) "" else afterScheme.substring(slash).substringBefore('?')

        val stringToSign = headersPart + "\n" + paramsPart + "\n" + md5Part + timestamp + "\n" + method + "\n" + path
        val mac = javax.crypto.Mac.getInstance("HmacSHA1")
        mac.init(javax.crypto.spec.SecretKeySpec(signSecret.toByteArray(Charsets.UTF_8), "HmacSHA1"))
        return Base64.encodeToString(mac.doFinal(stringToSign.toByteArray(Charsets.UTF_8)), Base64.DEFAULT).trim()
    }

    private fun ucPost(url: String, body: JsonObject?): JsonObject? =
        exec(ucClient, Request.Builder().url(url).post((body?.toString() ?: "{}").toRequestBody(jsonMedia)).build())
    private fun ucGet(url: String): JsonObject? =
        exec(ucClient, Request.Builder().url(url).get().build())
    private fun tspPost(url: String, body: JsonObject): JsonObject? =
        exec(tspClient, Request.Builder().url(url).post(body.toString().toRequestBody(jsonMedia)).build())
    private fun tspGetArray(url: String): List<JsonElement>? {
        val root = execRoot(tspClient, Request.Builder().url(url).get().build()) ?: return null
        requireSuccess(root, url)
        return root["data"]?.jsonArray
    }

    /** Execute, require success, return the `data` object. */
    private fun exec(client: OkHttpClient, req: Request): JsonObject? {
        val root = execRoot(client, req) ?: error("Empty login response")
        requireSuccess(root, req.url.toString())
        return root["data"]?.let { if (it is JsonObject) it else null }
    }

    private fun execRoot(client: OkHttpClient, req: Request): JsonObject? {
        val ep = req.url.encodedPath.substringAfterLast('/')
        client.newCall(req).execute().use { resp ->
            val text = resp.body?.string().orEmpty()
            Logx.d("login", "<- $ep HTTP ${resp.code}")
            if (text.isBlank()) error("HTTP ${resp.code} empty response")
            val root = try { json.parseToJsonElement(text).jsonObject }
            catch (_: Exception) { error("Invalid login response format") }
            if (req.url.encodedPath.endsWith("/" + ZeekrConst.LOGIN_URL) &&
                root["success"]?.jsonPrimitive?.contentOrNull != "true" &&
                root["code"]?.jsonPrimitive?.contentOrNull != "000000") {
                val cfg = store.current()
                // Redaction inputs only: never log headers, credentials, or the request body.
                val body = req.body?.let { okio.Buffer().use { b -> it.writeTo(b); b.readUtf8() } }
                val bodyValues = body?.let {
                    runCatching { json.parseToJsonElement(it).jsonObject.values.mapNotNull { v ->
                        (v as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull
                    } }.getOrDefault(emptyList())
                }.orEmpty()
                val privateValues = listOf(cfg.email, cfg.password, cfg.vin, cfg.hmacAccessKey,
                    cfg.hmacSecretKey, cfg.prodSecret, cfg.vinKey, cfg.vinIv, cfg.passwordPublicKey,
                    cfg.xchangerSignSecret, cfg.overseasAccessKey, cfg.overseasSecretKey,
                    cfg.inboxAuthSecret, cfg.accessToken, cfg.azureToken, cfg.xchangerToken, ucToken) +
                    resp.request.headers.map { it.second } + bodyValues
                requireSuccess(root, req.url.toString(), sanitizedLoginMessage(root, privateValues))
            }
            return root
        }
    }

    private fun requireSuccess(root: JsonObject, url: String, safeMessage: String? = null) {
        val success = root["success"]?.jsonPrimitive?.let { runCatching { it.contentOrNull == "true" }.getOrDefault(false) }
            ?: false
        val code = root["code"]?.jsonPrimitive?.contentOrNull
        if (!success && code != "000000") {
            val safeCode = code?.takeIf { it.matches(Regex("[0-9]{1,12}")) } ?: "unknown"
            Logx.d("login", "Request rejected (code=$safeCode)")
            error("request failed (code=$safeCode)" + (safeMessage?.let { ": $it" } ?: ""))
        }
    }
    companion object {
        /** Only top-level message text is displayed; everything else is a redaction input. */
        internal fun sanitizedLoginMessage(root: JsonObject, privateValues: List<String>): String? {
            val message = listOf("msg", "message").firstNotNullOfOrNull { key ->
                (root[key] as? kotlinx.serialization.json.JsonPrimitive)
                    ?.takeIf { it.isString }?.contentOrNull?.takeIf { it.isNotBlank() }
            } ?: return null
            // Suppress structured dumps rather than risk presenting headers or response data.
            if (message.any { it == '{' || it == '}' } ||
                Regex("(?i)\\b(?:headers?|data|authorization|password|ciphertext|token|x-hmac-[a-z-]+|x-vin)[\"']?\\s*[:=]").containsMatchIn(message))
                return "[redacted]"
            fun leaves(value: JsonElement?): List<String> = when (value) {
                is JsonObject -> value.values.flatMap { leaves(it) }
                is kotlinx.serialization.json.JsonArray -> value.flatMap { leaves(it) }
                is kotlinx.serialization.json.JsonPrimitive -> listOfNotNull(value.contentOrNull)
                else -> emptyList()
            }
            val values = (privateValues + leaves(root["data"])).filter { it.isNotBlank() }
                .flatMap { listOf(it, kotlinx.serialization.json.JsonPrimitive(it).toString().removeSurrounding("\"")) }
                .distinct().sortedByDescending { it.length }
            var safe = message
            if (values.isNotEmpty()) safe = Regex(values.joinToString("|") { Regex.escape(it) },
                RegexOption.IGNORE_CASE).replace(safe) { "[redacted]" }
            safe = Regex("(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}").replace(safe, "[redacted]")
            safe = Regex("(?i)\\b[A-HJ-NPR-Z0-9]{17}\\b").replace(safe, "[redacted]")
            safe = Regex("[A-Za-z0-9_+/=-]{24,}").replace(safe, "[redacted]")
            return safe.replace(Regex("[\\p{Cc}\\p{Cf}]"), " ").trim().take(160).ifBlank { null }
        }

        /** Only the failing password-login request adopts the official overseas 3.0.7 identity. */
        internal fun userCenterHeaders(countryCode: String, path: String): Map<String, String> {
            val headers = ZeekrConst.defaultHeaders(countryCode)
            return if (path.endsWith("/" + ZeekrConst.LOGIN_URL)) headers + mapOf(
                "app-authorization" to "1009",
                "app-code" to "1JwLroFkFFIpgFGdTRrm4_nzkkwDkfHj7RxJQb7J8tc",
                "appcode" to "eu-app",
                "appid" to "TSP",
                "appsecret" to "zeekr_tis",
                "appversion" to "3.0.7",
                "client-id" to "1d1921ad4d314ab7b0042a2fe0f479c3",
                "msgappid" to "10008",
                "msgclientid" to "1009",
                "tmp-tenant-code" to "3300671070785540000",
                "Brand" to "ZEEKR",
                "user-agent" to "Device/GoogleAppName/com.zeekr.overseasAppVersion/3.0.7Platform/androidOSVersion/16Ditto/true",
            ) else headers
        }

        /** Android 3.0.7 retains Base64 line folding and the trailing LF in the JSON password. */
        internal fun encryptPassword(password: String, pubKeyB64: String): String {
            if (pubKeyB64.isBlank()) return password
            val key = KeyFactory.getInstance("RSA")
                .generatePublic(X509EncodedKeySpec(Base64.decode(pubKeyB64, Base64.DEFAULT)))
            val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding").apply { init(Cipher.ENCRYPT_MODE, key) }
            return Base64.encodeToString(cipher.doFinal(password.toByteArray(Charsets.UTF_8)), Base64.DEFAULT)
        }

    }
}
