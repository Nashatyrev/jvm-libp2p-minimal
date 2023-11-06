package io.libp2p.simulate.pubsub

import io.libp2p.core.pubsub.MessageApi
import io.libp2p.core.pubsub.Topic
import io.libp2p.core.pubsub.ValidationResult
import io.libp2p.pubsub.PubsubProtocol
import io.libp2p.simulate.*
import io.libp2p.simulate.delay.latency.LatencyDistribution
import kotlin.time.Duration

data class InOutBandwidth(
    val inbound: Bandwidth,
    val outbound: Bandwidth = inbound
)

data class MessageValidation(
    val validationDelay: Duration,
    val validationResult: ValidationResult
)

typealias MessageValidationGenerator = (MessageApi) -> MessageValidation

interface SimPubsubPeerConfig {
    // Gossip router config
    val pubsubProtocol: PubsubProtocol

    // Gossip simulation config
    val topics: List<Topic>
    val messageValidationGenerator: MessageValidationGenerator

    // Other
    val bandwidth: InOutBandwidth
}

interface SimPubsubConfig {
    val peerConfigs: List<SimPubsubPeerConfig>

    val pubsubMessageSizes: PubsubMessageSizes
    val latency: LatencyDistribution

    val topology: Topology
    val warmUpDelay: Duration
    val randomSeed: Long

    val totalPeers: Int get() = peerConfigs.size
}
