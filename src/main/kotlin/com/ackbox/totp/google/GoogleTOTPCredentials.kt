package com.ackbox.totp.google

import com.ackbox.totp.TOTPCredentials
import com.ackbox.totp.TOTPSecretKey

/**
 * GoogleAuthenticator credentials.
 *
 * @param secretKey the secret key.
 * @param verificationCode the verification code at time = 0 (the UNIX epoch).
 * @param scratchCodes the list of scratch codes.
 */
data class GoogleTOTPCredentials(
    override val secretKey: TOTPSecretKey,
    override val verificationCode: Int,
    override val scratchCodes: List<Int> = emptyList()
) : TOTPCredentials
