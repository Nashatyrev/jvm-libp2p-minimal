package io.libp2p.simulate.stream

import io.libp2p.core.PeerId
import io.libp2p.core.Stream
import io.libp2p.core.StreamHandler
import io.libp2p.core.crypto.KEY_TYPE
import io.libp2p.core.crypto.generateKeyPair
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.MultiaddrComponent
import io.libp2p.core.multiformats.Protocol
import io.libp2p.core.multistream.ProtocolId
import io.libp2p.etc.types.lazyVar
import io.libp2p.etc.types.toBytesBigEndian
import io.libp2p.simulate.*
import io.libp2p.simulate.util.GeneralSizeEstimator
import io.libp2p.simulate.util.MsgSizeEstimator
import io.netty.handler.logging.LogLevel
import java.security.SecureRandom
import java.util.*
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.atomic.AtomicInteger

abstract class StreamSimPeer<TProtocolController>(
    val isSemiDuplex: Boolean = false,
    val streamProtocol: ProtocolId
) : SimPeer, StreamHandler<TProtocolController> {

    override val simPeerId = counter.getAndIncrement()

    override val connections: MutableList<SimConnection> = Collections.synchronizedList(ArrayList())

    override var inboundBandwidth: BandwidthDelayer = BandwidthDelayer.UNLIM_BANDWIDTH
    override var outboundBandwidth: BandwidthDelayer = BandwidthDelayer.UNLIM_BANDWIDTH

    val protocolController: CompletableFuture<TProtocolController> = CompletableFuture()

    var address = Multiaddr(
        listOf(
            MultiaddrComponent(Protocol.IP4, counter.incrementAndGet().toBytesBigEndian()),
            MultiaddrComponent(Protocol.TCP, byteArrayOf(0, 0xFF.toByte()))
        )
    )

    abstract val random: Random

    lateinit var simExecutor: ScheduledExecutorService
    lateinit var currentTime: () -> Long
    var keyPair by lazyVar {
        generateKeyPair(
            KEY_TYPE.ECDSA,
            random = SecureRandom(ByteArray(4).also { random.nextBytes(it) })
        )
    }
    override val peerId by lazy { PeerId.fromPubKey(keyPair.second) }

    var msgSizeEstimator: MsgSizeEstimator = GeneralSizeEstimator
    var wireLogs: LogLevel? = null

    override fun connect(other: SimPeer): CompletableFuture<SimConnection> {
        return connectImpl(other).thenApply { conn ->
            val otherAbs = other as? StreamSimPeer<*>
            connections += conn
            otherAbs?.connections?.add(conn)
            conn.closed.thenAccept {
                connections -= conn
                otherAbs?.connections?.remove(conn)
            }
            conn
        }
    }

    private fun connectImpl(other: SimPeer): CompletableFuture<SimConnection> {
        other as StreamSimPeer<*>

        val conn = StreamSimConnection(this, other)
        conn.createStream(SimStream.StreamInitiator.CONNECTION_DIALER, streamProtocol, wireLogs)
        if (isSemiDuplex) {
            conn.createStream(SimStream.StreamInitiator.CONNECTION_LISTENER, streamProtocol, wireLogs)
        }
        return CompletableFuture.completedFuture(conn)
    }

    fun simHandleStream(stream: Stream): CompletableFuture<TProtocolController> =
        handleStream(stream)
            .thenApply {
                protocolController.complete(it)
                it
            }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as SimPeer
        return name == other.name
    }

    override fun hashCode(): Int = name.hashCode()

    companion object {
        val counter = AtomicInteger()
    }
}
