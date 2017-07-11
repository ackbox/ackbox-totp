package com.ackbox.totp

import com.ackbox.totp.google.GoogleAuthenticator
import com.ackbox.totp.google.GoogleAuthenticatorConfig

object TOTPProviders {

    fun googleAuthenticator(config: GoogleAuthenticatorConfig = GoogleAuthenticatorConfig()) = GoogleAuthenticator(config)
}
