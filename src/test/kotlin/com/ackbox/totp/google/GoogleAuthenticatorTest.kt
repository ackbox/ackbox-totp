package com.ackbox.totp.google

import com.ackbox.totp.TOTPSecretKey
import org.junit.Assert.assertEquals
import org.junit.Test
import java.time.Duration
import java.time.Instant

class GoogleAuthenticatorTest {

    @Test
    fun testWithRFC6238TestVectors() {
        val config = GoogleAuthenticatorConfig(
            codeDigits = 8,
            timeStepSize = Duration.ofSeconds(30)
        )

        val authenticator = GoogleAuthenticator(config)

        RFC6238_OTP_TIME_PAIRS.forEach { otp, timeInSeconds ->
            val timestamp = Instant.ofEpochMilli(timeInSeconds * 1000)
            assertEquals(otp, authenticator.createOneTimePassword(RFC6238_OTP_KEY, timestamp))
        }
    }

    companion object {
        val RFC6238_OTP_KEY = TOTPSecretKey(hexToByteArray("3132333435363738393031323334353637383930"))
        val RFC6238_OTP_TIME_PAIRS = mapOf(
            94287082 to 59L,
            7081804 to 1111111109L,
            14050471 to 1111111111L,
            89005924 to 1234567890L,
            69279037 to 2000000000L,
            65353130 to 20000000000L
        )

        fun hexToByteArray(string: String): ByteArray {
            val HEX_CHARS = "0123456789ABCDEF"
            val result = ByteArray(string.length / 2)

            for (i in 0 until string.length step 2) {
                val firstIndex = HEX_CHARS.indexOf(string[i]);
                val secondIndex = HEX_CHARS.indexOf(string[i + 1]);
                val octet = firstIndex.shl(4).or(secondIndex)
                result[i.shr(1)] = octet.toByte()
            }
            return result
        }
    }
}
