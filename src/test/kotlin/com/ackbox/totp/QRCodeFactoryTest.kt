package com.ackbox.totp

import org.junit.Assert.assertEquals
import org.junit.Test

class QRCodeFactoryTest {

    private var secretKey = TOTPSecretKey.from(TOTPSecretKey.KeyRepresentation.BASE32, "ONSWG4TFORFWK6IK")

    @Test
    fun testCreateQRCodeURL() {
        assertEquals(
            "https://chart.googleapis.com/chart?chs=200x200&chld=M%7C0&cht=qr&chl=otpauth%3A%2F%2Ftotp%2FAcme%3Aalice%40example.com%3Fsecret%3DONSWG4TFORFWK6IK%26issuer%3DAcme",
            QRCodeFactory.createQRCodeURL("Acme", "alice@example.com", secretKey)
        )
    }

    @Test
    fun testCreateOTPURL() {
        assertEquals(
            "otpauth://totp/Acme:alice@example.com?secret=ONSWG4TFORFWK6IK&issuer=Acme",
            QRCodeFactory.createOTPURL("Acme", "alice@example.com", secretKey)
        )

        // issuer and user with spaces
        assertEquals(
            "otpauth://totp/Acme%20Inc:alice%20at%20Inc?secret=ONSWG4TFORFWK6IK&issuer=Acme+Inc",
            QRCodeFactory.createOTPURL("Acme Inc", "alice at Inc", secretKey)
        )

        assertEquals(
            "otpauth://totp/Acme%20&%20%3Cfriends%3E:alice%2523?secret=ONSWG4TFORFWK6IK&issuer=Acme+%26+%3Cfriends%3E",
            QRCodeFactory.createOTPURL("Acme & <friends>", "alice%23", secretKey)
        )
    }
}
