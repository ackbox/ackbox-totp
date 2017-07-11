package com.ackbox.totp

import java.time.Instant

/**
 * OTP authenticator library interface.
 */
interface TOTPAuthenticator {

    /**
     * This method generates a new set of credentials including:
     *
     *  - TOTP secret key.
     *  - Validation code.
     *  - A list of scratch codes.
     *
     * The user must register this secret on their device.
     * @return OTP credentials
     */
    fun createCredentials(): TOTPCredentials

    /**
     * Checks a verification code against a secret key using the specified time.
     * The algorithm also checks in a time window whose size determined by the
     * `windowSize` property of this class.
     *
     * The default value of 30 seconds recommended by RFC 6238 is used for the
     * interval size.
     *
     * @param secretKey The TOTP secret key.
     * @param totp One-tim password code.
     * @param time The time to use to calculate the time based totp.
     * @return `true` if the validation code is valid, `false` otherwise.
     *
     * @throws TOTPException if a failure occurs during the calculation of the validation code.
     * The only failures that should occur are related with the cryptographic functions provided by the JCE.
     */
    @Throws(TOTPException::class)
    fun authorize(secretKey: TOTPSecretKey, totp: Int, time: Instant = Instant.now()): Boolean

    /**
     * This method generates the TOTP password at the specified time.
     *
     * @param secretKey The OTP secret key.
     * @param time The time to use to calculate the password.
     * @return the TOTP password at the specified time.
     *
     * @throws TOTPException if a failure occurs during the calculation of the validation code.
     * The only failures that should occur are related with the cryptographic functions provided by the JCE.
     */
    @Throws(TOTPException::class)
    fun createOneTimePassword(secretKey: TOTPSecretKey, time: Instant = Instant.now()): Int

    /**
     * Returns the URL to generate a QR barcode to be loaded into the OTP authenticator application. The user
     * scans this bar code with the application on their smart phones or enters the secret manually.
     *
     * @param issuer The issuer name. This parameter cannot contain the colon (:) character.
     * @param accountName The account name.
     * @param secretKey The OTP secret key.
     * @return the URL to generate a QR barcode to be loaded into the OTP authenticator application.
     */
    fun createQRCode(issuer: String?, accountName: String, secretKey: TOTPSecretKey) = QRCodeFactory.createQRCodeURL(issuer, accountName, secretKey)
}
