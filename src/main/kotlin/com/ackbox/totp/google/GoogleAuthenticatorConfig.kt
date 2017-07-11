package com.ackbox.totp.google

import java.time.Duration

/**
 * Configuration class for Google OTP Authenticator.
 *
 * @param timeStepSize time step size as specified by RFC 6238. The default value is 30.000.
 * @param windowSize value representing the number of windows of size timeStepSize that are checked during the
 * validation process, to account for differences between the server and the client clocks. The bigger the window,
 * the more tolerant the library code is about clock skews.
 * @param codeDigits number of digits in the generated code.
 * @param keyModulus key module.
 */
data class GoogleAuthenticatorConfig(
    val timeStepSize: Duration = Duration.ofSeconds(30),
    val windowSize: Int = 3,
    val codeDigits: Int = 6,
    val keyModulus: Long = Math.pow(10.0, codeDigits.toDouble()).toLong()
) {

    init {
        require(windowSize > 0, { "Window number must be positive." })
        require(codeDigits >= 6, { "The minimum number of digits is 6." })
        require(codeDigits <= 8, { "The maximum number of digits is 8." })
        require(!timeStepSize.isNegative && !timeStepSize.isZero, { "Time step size must be positive." })
    }
}
