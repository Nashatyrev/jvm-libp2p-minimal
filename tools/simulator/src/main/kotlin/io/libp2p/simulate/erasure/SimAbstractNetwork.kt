package io.libp2p.simulate.erasure

import io.libp2p.simulate.Network
import io.libp2p.simulate.SimPeerId
import io.libp2p.simulate.delay.TimeDelayer
import io.libp2p.simulate.delay.bandwidth.AccurateBandwidthTracker
import io.libp2p.simulate.erasure.router.SimAbstractRouterBuilder
import io.libp2p.simulate.generateAndConnect
import io.libp2p.simulate.stream.StreamSimConnection
import io.libp2p.tools.schedulers.ControlledExecutorServiceImpl
import io.libp2p.tools.schedulers.TimeControllerImpl
import java.util.Random

typealias ErasureRouterBuilderFactory = (SimPeerId) -> SimAbstractRouterBuilder
typealias ErasureSimPeerModifier = (SimPeerId, SimAbstractPeer) -> Unit

class SimAbstractNetwork(
    val cfg: SimAbstractConfig,
    val routerBuilderFactory: ErasureRouterBuilderFactory,
    val simPeerModifier: ErasureSimPeerModifier = { _, _ -> }
) {
    val peers = sortedMapOf<SimPeerId, SimAbstractPeer>()
    lateinit var network: Network

    val timeController = TimeControllerImpl()
    val commonRnd = Random(cfg.randomSeed)
    val commonExecutor = ControlledExecutorServiceImpl(timeController)

    protected fun createSimPeer(number: SimPeerId): SimAbstractPeer {
        val peerConfig = cfg.peerConfigs[number]

        val routerBuilder = routerBuilderFactory(number).also {
            it.protocol = peerConfig.pubsubProtocol
        }

        val simPeer =
            SimAbstractPeer(number, commonRnd, peerConfig.pubsubProtocol, routerBuilder)
                .also { simPeer ->
                    simPeer.simExecutor = commonExecutor
                    simPeer.currentTime = { timeController.time }
                    simPeer.msgSizeEstimator = cfg.messageGenerator.sizeEstimator
                    simPeer.inboundBandwidth =
                        AccurateBandwidthTracker(
                            peerConfig.bandwidth.inbound,
                            simPeer.simExecutor,
                            simPeer.currentTime,
                            name = "[$simPeer]-in"
                        )
                    simPeer.outboundBandwidth =
                        AccurateBandwidthTracker(
                            peerConfig.bandwidth.inbound,
                            simPeer.simExecutor,
                            simPeer.currentTime,
                            name = "[$simPeer]-in"
                        )
                    simPeerModifier(number, simPeer)
                }
        return simPeer
    }

    fun createAllPeers() {
        peers += (0 until cfg.totalPeers).map {
            it to createSimPeer(it)
        }
    }

    fun connectAllPeers() {
        cfg.topology.random = commonRnd
        network = cfg.topology.generateAndConnect(peers.values.toList())
        network.activeConnections.forEach {
            val connection = it as StreamSimConnection
            val latency = cfg.latency.getLatency(connection, commonRnd)
            it.connectionLatency = TimeDelayer(connection.listener.simExecutor) { latency.next() }
        }
    }
}
