package com.ackbox.totp

/**
 * TOTP authenticator credentials.
 */
interface TOTPCredentials {

    val secretKey: TOTPSecretKey

    val verificationCode: Int

    val scratchCodes: List<Int>
}
