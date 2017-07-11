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

//    @Test
//    fun testCreateCredentials() {
//        val gacb = GoogleAuthenticatorConfigBuilder()
//            .setKeyRepresentation(OTPSecretKey.KeyRepresentation.BASE64)
//        val googleAuthenticator = GoogleAuthenticator(gacb.build())
//
//        val key = googleAuthenticator.createCredentials()
//        val secret = key.getKey()
//        val scratchCodes = key.getScratchCodes()
//
//        val otpAuthURL = GoogleAuthenticatorQRGenerator.getOtpAuthURL("Test Org.", "test@prova.org", key)
//
//        println("Please register (otpauth uri): " + otpAuthURL)
//        println("Base64-encoded secret key is " + secret)
//
//        for (i in scratchCodes) {
//            if (!googleAuthenticator.validateScratchCode(i)) {
//                throw IllegalArgumentException("An invalid code has been " + "generated: this is an application bug.")
//            }
//            println("Scratch code: " + i!!)
//        }
//    }
//
//    @Test
//    fun createAndAuthenticate() {
//        val ga = GoogleAuthenticator()
//        val key = ga.createCredentials()
//
//        assertTrue(ga.authorize(key.getKey(), ga.getTotpPassword(key.getKey())))
//    }
//
//    @Test
//    fun createCredentialsForUser() {
//        val googleAuthenticator = GoogleAuthenticator()
//
//        val key = googleAuthenticator.createCredentials("testName")
//        val secret = key.getKey()
//        val scratchCodes = key.getScratchCodes()
//
//        val otpAuthURL = GoogleAuthenticatorQRGenerator.getOtpAuthURL("Test Org.", "test@prova.org", key)
//
//        println("Please register (otpauth uri): " + otpAuthURL)
//        println("Secret key is " + secret)
//
//        for (i in scratchCodes) {
//            if (!googleAuthenticator.validateScratchCode(i)) {
//                throw IllegalArgumentException("An invalid code has been " + "generated: this is an application bug.")
//            }
//            println("Scratch code: " + i!!)
//        }
//    }
//
//    @Test
//    fun authorise() {
//        val gacb = GoogleAuthenticatorConfigBuilder()
//            .setTimeStepSizeInMillis(TimeUnit.SECONDS.toMillis(30))
//            .setWindowSize(5)
//        val ga = GoogleAuthenticator(gacb.build())
//
//        val isCodeValid = ga.authorize(SECRET_KEY, VALIDATION_CODE)
//
//        println("Check VALIDATION_CODE = " + isCodeValid)
//    }
//
//    @Test
//    fun authoriseUser() {
//        val gacb = GoogleAuthenticatorConfigBuilder()
//            .setTimeStepSizeInMillis(TimeUnit.SECONDS.toMillis(30))
//            .setWindowSize(5)
//            .setCodeDigits(6)
//        val ga = GoogleAuthenticator(gacb.build())
//
//        val isCodeValid = ga.authorizeUser("testName", VALIDATION_CODE)
//
//        println("Check VALIDATION_CODE = " + isCodeValid)
//    }
//
//    companion object {
//
//        private val SECRET_KEY = "KR52HV2U5Z4DWGLJ"
//        private val VALIDATION_CODE = 598775
//    }

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
