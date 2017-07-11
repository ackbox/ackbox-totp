package com.ackbox.totp

import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicInteger

class ReseedingSecureRandom {

    private val count = AtomicInteger(0)
    private var secureRandom = createSecureRandom()

    fun nextBytes(bytes: ByteArray) {
        if (count.incrementAndGet() > MAX_OPERATIONS) {
            synchronized(this) {
                if (count.get() > MAX_OPERATIONS) {
                    secureRandom = createSecureRandom()
                    count.set(0)
                }
            }
        }
        secureRandom.nextBytes(bytes)
    }

    private fun createSecureRandom() = SecureRandom()

    companion object {

        private val MAX_OPERATIONS = 1000000
    }
}
