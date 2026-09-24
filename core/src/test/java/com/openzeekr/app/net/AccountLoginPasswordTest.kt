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

    @Test fun identityOverrideIsLimitedToPasswordLogin() {
        val original = ZeekrConst.defaultHeaders("NO")
        val login = AccountLogin.userCenterHeaders("NO", "/zeekr-cuc-idaas/" + ZeekrConst.LOGIN_URL)
        assertEquals("3.0.7", login["appversion"])
        assertTrue(login.getValue("user-agent").contains("com.zeekr.overseasAppVersion/3.0.7"))
        assertTrue("Only presentation identity headers may change",
            login.filterKeys { it !in setOf("appversion", "user-agent") } ==
                original.filterKeys { it !in setOf("appversion", "user-agent") })
        for (path in listOf(ZeekrConst.CHECKUSER_URL, ZeekrConst.TSPCODE_URL, ZeekrConst.USERINFO_URL)) {
            assertTrue("Other user-center requests must retain their headers",
                AccountLogin.userCenterHeaders("NO", "/zeekr-cuc-idaas/$path") == original)
        }
    }
}
