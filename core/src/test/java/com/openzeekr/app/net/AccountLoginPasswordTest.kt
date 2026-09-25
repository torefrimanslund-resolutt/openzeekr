package com.openzeekr.app.net

import android.util.Base64
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyPairGenerator
import javax.crypto.Cipher

/** Ephemeral test keys only; no production credentials or network login. */
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE, sdk = [28])
class AccountLoginPasswordTest {
    private fun keys() = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    @Test fun androidDefaultPreservesWrappingPaddingAndFinalLf() {
        val pair = keys()
        val password = "synthetic-test-ø-密码"
        val encoded = AccountLogin.encryptPassword(password, Base64.encodeToString(pair.public.encoded, Base64.NO_WRAP))
        val bytes = Base64.decode(encoded, Base64.DEFAULT)
        assertTrue("Expected one 2048-bit RSA block", bytes.size == 256)
        val expected = java.util.Base64.getMimeEncoder(76, byteArrayOf(10)).encodeToString(bytes) + "\n"
        assertTrue("Must match Android DEFAULT folding and trailing LF", expected == encoded)
        assertTrue("Padding must remain present", encoded.endsWith("==\n"))
        assertFalse("Android DEFAULT uses LF, not CRLF", encoded.contains('\r'))
        val lines = encoded.dropLast(1).split('\n')
        assertTrue("All full lines must contain 76 characters", lines.dropLast(1).all { it.length == 76 })
        val plain = Cipher.getInstance("RSA/ECB/PKCS1Padding").apply {
            init(Cipher.DECRYPT_MODE, pair.private)
        }.doFinal(bytes)
        assertTrue("RSA must preserve UTF-8 password bytes", plain.contentEquals(password.toByteArray(Charsets.UTF_8)))
    }

    @Test fun noWrapIsDifferentAndPkcs1EncryptionRemainsRandomized() {
        val pair = keys()
        val pub = Base64.encodeToString(pair.public.encoded, Base64.DEFAULT)
        val first = AccountLogin.encryptPassword("synthetic-test", pub)
        val second = AccountLogin.encryptPassword("synthetic-test", pub)
        val noWrap = Base64.encodeToString(Base64.decode(first, Base64.DEFAULT), Base64.NO_WRAP)
        assertTrue("Login must retain line breaks", first != noWrap)
        assertTrue("Only Base64 line breaks distinguish DEFAULT from NO_WRAP", first.replace("\n", "") == noWrap)
        assertTrue("PKCS#1 v1.5 ciphertext must remain randomized", first != second)
    }

    @Test fun jsonTransportPreservesCiphertextLineBreaks() {
        val pair = keys()
        val encoded = AccountLogin.encryptPassword("synthetic-test", Base64.encodeToString(pair.public.encoded, Base64.NO_WRAP))
        val body = buildJsonObject { put("password", encoded) }.toString()
        assertTrue("JSON must escape embedded newlines", body.contains("\\n"))
        val decoded = Json.parseToJsonElement(body).jsonObject.getValue("password").jsonPrimitive.content
        assertTrue("JSON round trip must not trim or normalize ciphertext", decoded == encoded)
    }

    @Test fun passwordLoginUsesCompleteOverseas307Identity() {
        val expected = mapOf(
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
        )
        val original = ZeekrConst.defaultHeaders("NO")
        val login = AccountLogin.userCenterHeaders("NO", "/zeekr-cuc-idaas/" + ZeekrConst.LOGIN_URL)
        assertEquals("Complete observed identity, with all other headers preserved", original + expected, login)
    }

    @Test fun otherEndpointsRetainExactlyTheirOriginalHeaders() {
        val paths = listOf(
            ZeekrConst.CHECKUSER_URL, ZeekrConst.TSPCODE_URL, ZeekrConst.USERINFO_URL,
            ZeekrConst.BEARERLOGIN_URL, ZeekrConst.VEHLIST_URL,
            "auth/loginByEmailEncryptExtra", "auth/loginByEmailEncrypt/child",
        )
        for (country in listOf("NO", "SE")) {
            val original = ZeekrConst.defaultHeaders(country)
            for (path in paths) {
                assertEquals("No identity override for $path",
                    original, AccountLogin.userCenterHeaders(country, "/zeekr-cuc-idaas/$path"))
            }
            // A login call must not mutate the shared defaults or affect the next canary.
            AccountLogin.userCenterHeaders(country, "/zeekr-cuc-idaas/" + ZeekrConst.LOGIN_URL)
            assertEquals(original, ZeekrConst.defaultHeaders(country))
            assertEquals(original, AccountLogin.userCenterHeaders(country, "/zeekr-cuc-idaas/" + ZeekrConst.CHECKUSER_URL))
        }
    }
}
