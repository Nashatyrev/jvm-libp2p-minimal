package io.libp2p.simulate.stats.collect.pubsub.gossip

import io.libp2p.simulate.pubsub.SimPubsubPeer
import io.libp2p.simulate.pubsub.gossip.GossipSimPeer
import io.libp2p.simulate.stats.collect.SimMessageId
import io.libp2p.simulate.stats.collect.pubsub.PubsubMessageResult

class GossipPubDeliveryResult(
    val deliveries: List<MessageDelivery>
) {

    data class MessagePublish(
        val simMsgId: SimMessageId,
        val fromPeer: SimPubsubPeer,
        val sentTime: Long,
    )

    data class MessageDelivery(
        val initialPublishMsg: MessagePublish,
        val origGossipMsg: PubsubMessageResult.PubMessageWrapper
    ) {
        val toPeer: GossipSimPeer get() = origGossipMsg.origMsg.receivingPeer as GossipSimPeer
        val fromPeer: GossipSimPeer get() = origGossipMsg.origMsg.sendingPeer as GossipSimPeer
        val receivedTime: Long get() = origGossipMsg.origMsg.receiveTime
        val deliveryDelay get() = receivedTime - initialPublishMsg.sentTime
    }

    val originalMessages: List<MessagePublish> by lazy {
        deliveries
            .map { it.initialPublishMsg }
            .distinct()
    }

    val publishTimes by lazy {
        originalMessages
            .map { it.sentTime }
            .distinct()
    }

    val deliveryDelays by lazy {
        deliveries.map { it.deliveryDelay }
    }

    fun filter(predicate: (MessageDelivery) -> Boolean): GossipPubDeliveryResult =
        GossipPubDeliveryResult(deliveries.filter { predicate(it) })

    fun <K> groupBy(keySelectror: (MessageDelivery) -> K): Map<K, GossipPubDeliveryResult> =
        deliveries
            .groupBy { keySelectror(it) }
            .mapValues { GossipPubDeliveryResult(it.value) }

    fun selectSlowestPeerDeliveries(): GossipPubDeliveryResult =
        deliveries
            .groupingBy { it.toPeer.peerId }
            .reduce { _, accumulator, element ->
                listOf(accumulator, element).maxByOrNull { it.receivedTime }!!
            }
            .values
            .sortedBy { it.receivedTime }
            .let { GossipPubDeliveryResult(it) }

    fun sliceByPublishTime(publishTime: Long) = filter { it.initialPublishMsg.sentTime == publishTime }

    fun aggregateSlowestBySimMessageId(messageGroups: Collection<Set<SimMessageId>>) =
        messageGroups
            .map { msgGroup ->
                this
                    .filter { it.initialPublishMsg.simMsgId in msgGroup }
                    .selectSlowestPeerDeliveries()
            }
            .merge()

    fun aggregateSlowestByPublishTime() =
        publishTimes
            .map { sliceByPublishTime(it).selectSlowestPeerDeliveries() }
            .merge()

    companion object {
        fun merge(stats: Collection<GossipPubDeliveryResult>): GossipPubDeliveryResult =
            stats
                .flatMap { it.deliveries }
                .sortedBy { it.receivedTime }
                .let { GossipPubDeliveryResult(it) }

        fun fromGossipMessageResult(gossipMessageResult: PubsubMessageResult): GossipPubDeliveryResult {
            val fastestReceives =
                gossipMessageResult.receivedPublishMessagesByPeerFastest().values.flatten()
            val orinatingMessages =
                gossipMessageResult.originatingPublishMessages.mapValues { (_, msg) ->
                    MessagePublish(
                        msg.simMsgId,
                        msg.origMsg.sendingPeer as SimPubsubPeer,
                        msg.origMsg.sendTime
                    )
                }

            return fastestReceives
                .map { receivedMsg ->
                    val simMsgId = receivedMsg.simMsgId
                    val origMessage = orinatingMessages[simMsgId]
                        ?: throw IllegalStateException("No originating message with id $simMsgId found")
                    MessageDelivery(
                        origMessage,
                        receivedMsg
                    )
                }
                .filter { it.toPeer != it.initialPublishMsg.fromPeer }
                .let { GossipPubDeliveryResult(it) }
        }

        private fun PubsubMessageResult.receivedPublishMessagesByPeerFastest() =
            this.peerReceivedMessages.mapValues { (_, msgs) ->
                msgs
                    .publishMessages
                    .groupBy { it.simMsgId }
                    .values
                    .map { idMsgs ->
                        idMsgs.minByOrNull { it.origMsg.receiveTime }
                    }
                    .filterNotNull()
            }


    }
}