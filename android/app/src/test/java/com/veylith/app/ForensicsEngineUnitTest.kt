package com.veylith.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.abs

class ForensicsEngineUnitTest {

    @Test
    fun testEntropyCalculation_uniformBytes() {
        // 256 bytes with each byte 0..255 exactly once -> Maximum entropy of 8.0
        val uniform = ByteArray(256) { it.toByte() }
        val entropy = calculateTestEntropy(uniform)
        assertTrue("Entropy of uniform distribution should be 8.0", abs(entropy - 8.0) < 0.001)
    }

    @Test
    fun testEntropyCalculation_identicalBytes() {
        // Zero entropy for all identical bytes
        val identical = ByteArray(100) { 0x41.toByte() }
        val entropy = calculateTestEntropy(identical)
        assertEquals("Entropy of uniform data must be 0.0", 0.0, entropy, 0.001)
    }

    private fun calculateTestEntropy(bytes: ByteArray): Double {
        if (bytes.isEmpty()) return 0.0
        val frequencies = IntArray(256)
        for (b in bytes) {
            frequencies[b.toInt() and 0xFF]++
        }
        var entropy = 0.0
        val total = bytes.size.toDouble()
        for (count in frequencies) {
            if (count > 0) {
                val p = count / total
                entropy -= p * (kotlin.math.log2(p))
            }
        }
        return Math.round(entropy * 10000.0) / 10000.0
    }
}
