package com.ackbox.totp

import java.net.URI
import java.net.URLEncoder

object QRCodeFactory {

    private val QR_GENERATOR_URI_FORMAT = "https://chart.googleapis.com/chart?chs=200x200&chld=M%%7C0&cht=qr&chl=%s"

    /**
     * Returns the URL of a Google Chart API call to generate a QR barcode to be loaded into the
     * OTP Authenticator application. The user scans this bar code with the application on their
     * smart phones or enters the secret manually.
     *
     * @param issuer The issuer name. This parameter cannot contain the colon (:) character.
     * @param accountName The account name.
     * @param secretKey The OTP secret key.
     * @return the Google Chart API call URL to generate a QR code containing the provided information.
     */
    fun createQRCodeURL(issuer: String?, accountName: String, secretKey: TOTPSecretKey): String {
        val encodedCode = createOTPURL(issuer, accountName, secretKey)
        return String.format(QR_GENERATOR_URI_FORMAT, URLEncoder.encode(encodedCode, "UTF-8"))
    }

    /**
     * Returns the basic otpauth TOTP URI. This URI might be sent to the user via email, QR code or some other method.
     * Use a secure transport since this URI contains the secret.
     *
     * The current implementation supports the following features:
     * - Label, made up of an optional issuer and an account name.
     * - Secret parameter.
     * - Issuer parameter.
     *
     * @param issuer The issuer name. This parameter cannot contain the colon (:) character.
     * @param accountName The account name.
     * @param secretKey The OTP secret key.
     * @return an otpauth scheme URI for loading into a client application.
     * *
     * @see [Google Authenticator - KeyUriFormat](https://code.google.com/p/google-authenticator/wiki/KeyUriFormat)
     */
    internal fun createOTPURL(issuer: String?, accountName: String, secretKey: TOTPSecretKey): String {
        require(!accountName.isNullOrBlank(), { "Account name must not be not null or empty." })
        issuer?.let {
            require(!issuer.contains(":"), { "Issuer cannot contain the \':\' character." })
        }
        val uri = URLBuilder("otpauth", "totp")
            .addPath("/${formatLabel(issuer, accountName)}")
            .addParameter("secret", secretKey.to(TOTPSecretKey.KeyRepresentation.BASE32))
        issuer?.let { uri.addParameter("issuer", issuer) }
        return uri.build().toString()
    }

    /**
     * The label is used to identify which account a key is associated with. It contains an account name, which
     * is a URI-encoded string, optionally prefixed by an issuer string identifying the provider or service managing
     * that account. This issuer prefix can be used to prevent collisions between different accounts with different
     * providers that might be identified using the same account name, e.g. the user's email address.
     * The issuer prefix and account name should be separated by a literal or url-encoded colon, and optional spaces
     * may precede the account name. Neither issuer nor account name may themselves contain a colon. Represented in
     * ABNF according to RFC 5234:
     *
     * <pre>
     * label = accountname / issuer (“:” / “%3A”) *”%20” accountname
     * </pre>
     */
    private fun formatLabel(issuer: String?, accountName: String): String {
        return listOf(issuer, accountName).filterNotNull().joinToString(":")
    }

    internal class URLBuilder(private val protocol: String, private val host: String) {

        private val paths = StringBuilder()
        private val params = StringBuilder()

        fun addPath(path: String): URLBuilder {
            paths.append("/").append(path)
            return this
        }

        fun addParameter(parameter: String, value: String): URLBuilder {
            if (params.toString().isNotEmpty()) {
                params.append("&")
            }
            params.append(parameter).append("=").append(value)
            return this
        }

        fun build() = URI(protocol, host, paths.toString(), params.toString(), null).toURL()!!
    }
}
