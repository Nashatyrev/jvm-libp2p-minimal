package io.libp2p.simulate

import io.libp2p.simulate.util.ReadableSize
import java.util.concurrent.CompletableFuture
import kotlin.time.Duration
import kotlin.time.Duration.Companion.microseconds

const val BANDWIDTH_BITS_IN_BYTE_PER_SECOND = 8

data class Bandwidth(val bytesPerSecond: Long) : Comparable<Bandwidth> {
    private fun getTransmitTimeMicrosec(size: Long): Long = (size * 1_000_000 / bytesPerSecond)
    fun getTransmitTime(size: Long): Duration = getTransmitTimeMicrosec(size).microseconds

    fun getTransmitSize(timeMillis: Long): Long =
        bytesPerSecond * timeMillis / 1000

    operator fun div(d: Int) = Bandwidth(bytesPerSecond / d)

    override fun compareTo(other: Bandwidth) = bytesPerSecond.compareTo(other.bytesPerSecond)

    override fun toString() =
        "${ReadableSize.create(bytesPerSecond * BANDWIDTH_BITS_IN_BYTE_PER_SECOND)}its/s"

    fun toStringShort() =
        ReadableSize.create(bytesPerSecond * BANDWIDTH_BITS_IN_BYTE_PER_SECOND)
            .let { "${it.valueString}${it.units.shortPrefix}" }

    companion object {
        private fun Long.min1() = if (this < 1) 1 else this
        val UNLIM = Bandwidth(Long.MAX_VALUE)
        fun mbitsPerSec(mbsec: Int) =
            Bandwidth(mbsec.toLong() * (1 shl 20) / BANDWIDTH_BITS_IN_BYTE_PER_SECOND)
        fun gbitsPerSec(gbsec: Int) = mbitsPerSec(gbsec * (1 shl 10))
        fun fromSize(sizeBytes: Long, period: Duration) =
            Bandwidth(sizeBytes * 1000 / period.inWholeMilliseconds.min1())
    }
}

val Int.mbitsPerSecond get() = Bandwidth.mbitsPerSec(this)

fun bandwidthDistribution(vararg entries: Pair<Bandwidth, Int>): RandomDistribution<Bandwidth> {
    val name = entries.joinToString("/") { it.first.toStringShort() } + "bits/s " +
            "@ " + entries.joinToString("/") { it.second.toString() } + "%"
    return RandomDistribution
        .discreteEven(entries.toList())
        .named(name)
}

interface BandwidthDelayer {

    val totalBandwidth: Bandwidth

    fun delay(remotePeer: SimPeerId, messageSize: Long): CompletableFuture<Unit>

    companion object {
        val UNLIM_BANDWIDTH = object : BandwidthDelayer {
            override val totalBandwidth = Bandwidth.UNLIM
            override fun delay(remotePeer: SimPeerId, messageSize: Long) = CompletableFuture.completedFuture(Unit)
        }
    }
}

