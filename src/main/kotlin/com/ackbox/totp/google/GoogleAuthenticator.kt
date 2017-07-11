package com.ackbox.totp.google

import com.ackbox.totp.TOTPAuthenticator
import com.ackbox.totp.TOTPException
import com.ackbox.totp.TOTPSecretKey
import com.ackbox.totp.ReseedingSecureRandom
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.time.Instant
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and

/**
 * This class implements the functionality described in RFC 6238 (TOTP: Time
 * based one-time password algorithm) and has been tested again Google's
 * implementation of such algorithm in its Google Authenticator application.
 *
 * This class lets users create a new 16-bit base32-encoded secret key with
 * the validation code calculated at `time = 0` (the UNIX epoch) and the
 * URL of a Google-provided QR barcode to let an user load the generated
 * information into Google Authenticator.
 *
 * Java Server side class for Google Authenticator's TOTP generator was inspired by an author's blog post.
 *
 * @see [Blog Post](http://thegreyblog.blogspot.com/2011/12/google-authenticator-using-it-in-your.html)
 * @see [Google Authenticator](http://code.google.com/p/google-authenticator)
 * @see [HOTP Time Based](http://tools.ietf.org/id/draft-mraihi-totp-timebased-06.txt)
 */
class GoogleAuthenticator(private val config: GoogleAuthenticatorConfig = GoogleAuthenticatorConfig()) : TOTPAuthenticator {

    private val secureRandom = ReseedingSecureRandom()

    override fun createCredentials(): GoogleTOTPCredentials {
        // Allocating a buffer sufficiently large to hold the bytes required by the secret key and the scratch codes.
        val buffer = ByteArray(SECRET_BITS / 8 + SCRATCH_CODES * BYTES_PER_SCRATCH_CODE)
        secureRandom.nextBytes(buffer)

        // Extracting the bytes making up the secret key.
        val key = Arrays.copyOf(buffer, SECRET_BITS / 8)
        val validationCode = calculateValidationCode(key)
        val scratchCodes = calculateScratchCodes(buffer)

        return GoogleTOTPCredentials(TOTPSecretKey(key), validationCode, scratchCodes)
    }

    override fun authorize(secretKey: TOTPSecretKey, totp: Int, time: Instant): Boolean {
        // Checking if the verification code is between the legal bounds.
        if (totp <= 0 || totp >= config.keyModulus) {
            return false
        }
        return checkCode(secretKey.value, totp, time, config.windowSize)
    }

    override fun createOneTimePassword(secretKey: TOTPSecretKey, time: Instant): Int {
        return calculateCode(secretKey.value, getTimeWindowFromTime(time))
    }

    /**
     * Calculates the verification code of the provided key at the specified
     * instant of time using the algorithm specified in RFC 6238.
     *
     * @param key the secret key in binary format.
     * @param timestamp the instant of time.
     * @return the validation code for the provided key at the specified instant of time.
     */
    private fun calculateCode(key: ByteArray, timestamp: Long): Int {
        // Converting the instant of time from the long representation to a  big-endian array of bytes (RFC4226, 5.2. Description).
        val bigEndianTimestamp = ByteArray(8)
        var value = timestamp
        var byte = 8
        while (byte-- > 0) {
            bigEndianTimestamp[byte] = value.toByte()
            value = value ushr 8
        }

        // Building the secret key specification for the HmacSHA1 algorithm.
        val signKey = SecretKeySpec(key, HMAC_HASH_FUNCTION)

        try {
            // Getting an HmacSHA1 algorithm implementation from the JCE.
            val mac = Mac.getInstance(HMAC_HASH_FUNCTION)
            mac.init(signKey)

            // Processing the instant of time and getting the encrypted data.
            val hash = mac.doFinal(bigEndianTimestamp)

            // Building the validation code performing dynamic truncation (RFC4226, 5.3. Generating an HOTP value)
            val offset = hash[hash.size - 1] and 0xF

            // We are using a long because Java hasn't got an unsigned integer type and we need 32 unsigned bits).
            var truncatedHash: Long = 0

            for (i in 0..3) {
                truncatedHash = truncatedHash shl 8

                // Java bytes are signed but we need an unsigned integer: cleaning off all but the LSB.
                truncatedHash = truncatedHash or (hash[offset + i].toInt() and 0xFF).toLong()
            }

            // Clean bits higher than the 32nd (inclusive) and calculate the module with the maximum validation code value.
            truncatedHash = truncatedHash and 0x7FFFFFFF
            truncatedHash %= config.keyModulus

            return truncatedHash.toInt()
        } catch (e: NoSuchAlgorithmException) {
            throw TOTPException("The operation cannot be performed now.", e)
        } catch (e: InvalidKeyException) {
            throw TOTPException("The operation cannot be performed now.", e)
        }
    }

    /**
     * This method implements the algorithm specified in RFC 6238 to check if a
     * validation code is valid in a given instant of time for the given secret key.
     *
     * @param key encoded secret key.
     * @param code the code to validate.
     * @param timestamp the instant of time to use during the validation process.
     * @param window the window size to use during the validation process.
     * @return `true` if the validation code is valid, `false` otherwise.
     */
    private fun checkCode(key: ByteArray, code: Int, timestamp: Instant, window: Int): Boolean {
        // convert unix time into a 30 second "window" as specified by the
        // TOTP specification. Using Google's default interval of 30 seconds.
        val timeWindow = getTimeWindowFromTime(timestamp)

        // Calculating the verification code of the given key in each of the
        // time intervals and returning true if the provided code is equal to
        // one of them.
        val start =  -((window - 1) / 2)
        val end = window / 2
        for (i in start..end) {
            // Calculating the verification code for the current time interval.
            val hash = calculateCode(key, timeWindow + i)
            // Checking if the provided code is equal to the calculated one.
            if (hash == code) {
                return true
            }
        }
        return false
    }

    /**
     * This method calculates the validation code at time 0.
     *
     * @param key The secret key to use.
     * @return the validation code at time 0.
     */
    private fun calculateValidationCode(key: ByteArray): Int = calculateCode(key, 0)

    private fun getTimeWindowFromTime(time: Instant) = time.toEpochMilli() / config.timeStepSize.toMillis()

    private fun calculateScratchCodes(buffer: ByteArray): List<Int> {
        val scratchCodes = ArrayList<Int>()
        while (scratchCodes.size < SCRATCH_CODES) {
            val scratchCodeBuffer = Arrays.copyOfRange(
                buffer,
                SECRET_BITS / 8 + BYTES_PER_SCRATCH_CODE * scratchCodes.size,
                SECRET_BITS / 8 + BYTES_PER_SCRATCH_CODE * scratchCodes.size + BYTES_PER_SCRATCH_CODE)

            val scratchCode = calculateScratchCode(scratchCodeBuffer)
            if (scratchCode != SCRATCH_CODE_INVALID) {
                scratchCodes.add(scratchCode)
            } else {
                scratchCodes.add(generateScratchCode())
            }
        }
        return scratchCodes
    }

    /**
     * This method creates a new random byte buffer from which a new scratch
     * code is generated. This function is invoked if a scratch code generated
     * from the main buffer is invalid because it does not satisfy the scratch
     * code restrictions.
     *
     * @return A valid scratch code.
     */
    private fun generateScratchCode(): Int {
        while (true) {
            val scratchCodeBuffer = ByteArray(BYTES_PER_SCRATCH_CODE)
            secureRandom.nextBytes(scratchCodeBuffer)
            val scratchCode = calculateScratchCode(scratchCodeBuffer)
            if (scratchCode != SCRATCH_CODE_INVALID) {
                return scratchCode
            }
        }
    }

    /**
     * This method calculates a scratch code from a random byte buffer of
     * suitable size `#BYTES_PER_SCRATCH_CODE`.
     *
     * @param scratchCodeBuffer a random byte buffer whose minimum size is `#BYTES_PER_SCRATCH_CODE`.
     * @return the scratch code.
     */
    private fun calculateScratchCode(scratchCodeBuffer: ByteArray): Int {
        if (scratchCodeBuffer.size < BYTES_PER_SCRATCH_CODE) {
            throw IllegalArgumentException("The provided random byte buffer is too small ${scratchCodeBuffer.size}.")
        }

        var scratchCode = 0
        for (i in 0..BYTES_PER_SCRATCH_CODE - 1) {
            scratchCode = (scratchCode shl 8) + (scratchCodeBuffer[i] and 0xff.toByte())
        }

        scratchCode = (scratchCode and 0x7FFFFFFF) % SCRATCH_CODE_MODULUS

        // Accept the scratch code only if it has exactly SCRATCH_CODE_LENGTH digits.
        if (validateScratchCode(scratchCode)) {
            return scratchCode
        }
        return SCRATCH_CODE_INVALID
    }

    private fun validateScratchCode(scratchCode: Int) = scratchCode >= SCRATCH_CODE_MODULUS / 10

    companion object {

        /**
         * The number of bits of a secret key in binary form. Since the Base32
         * encoding with 8 bit characters introduces an 160% overhead, we just need
         * 80 bits (10 bytes) to generate a 16 bytes Base32-encoded secret key.
         */
        private val SECRET_BITS = 80

        /**
         * Number of scratch codes to generate during the key generation.
         * We are using Google's default of providing 5 scratch codes.
         */
        private val SCRATCH_CODES = 5

        /**
         * Number of digits of a scratch code represented as a decimal integer.
         */
        private val SCRATCH_CODE_LENGTH = 8

        /**
         * Modulus used to truncate the scratch code.
         */
        private val SCRATCH_CODE_MODULUS = Math.pow(10.0, SCRATCH_CODE_LENGTH.toDouble()).toInt()

        /**
         * Magic number representing an invalid scratch code.
         */
        private val SCRATCH_CODE_INVALID = -1

        /**
         * Length in bytes of each scratch code. We're using Google's default of
         * using 4 bytes per scratch code.
         */
        private val BYTES_PER_SCRATCH_CODE = 4

        private val HMAC_HASH_FUNCTION = "HmacSHA1"
    }
}
