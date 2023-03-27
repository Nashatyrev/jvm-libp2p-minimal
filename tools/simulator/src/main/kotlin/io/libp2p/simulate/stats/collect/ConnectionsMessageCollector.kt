package io.libp2p.simulate.stats.collect

import io.libp2p.pubsub.gossip.CurrentTimeSupplier
import io.libp2p.simulate.*
import java.util.*

open class ConnectionsMessageCollector<MessageT>(
    network: Network,
    private val timeSupplier: CurrentTimeSupplier
) {

    private val deliveredMessagesWrite = mutableListOf<CollectedMessage<MessageT>>()
    val deliveredMessages: List<CollectedMessage<MessageT>> = deliveredMessagesWrite

    private val pendingMessageMap = IdentityHashMap<MessageT, CollectedMessage<MessageT>>()
    val pendingMessages get() = pendingMessageMap
        .values

    init {
        network.activeConnections.forEach { conn ->
            handleConnection(conn)
        }
    }

    fun clear() {
        deliveredMessagesWrite.clear()
    }

    @Suppress("UNCHECKED_CAST")
    private fun handleConnection(connection: SimConnection) {
        connection.streams.forEach { stream ->
            stream.initiatorChannel.msgVisitors += object : SimChannelMessageVisitor {
                override fun onOutbound(message: Any) {
                    message as MessageT
                    pendingMessageMap[message] = CollectedMessage(
                        connection,
                        stream.streamInitiatorPeer,
                        timeSupplier(),
                        Long.MAX_VALUE,
                        EMPTY_DELAY_DATA,
                        message
                    )
                }
                override fun onInbound(message: Any, delayData: DelayData) {
                    val sentMessage = pendingMessageMap.remove(message as MessageT)
                        ?: throw IllegalStateException("Pending message not found for message $message at ${timeSupplier()}")
                    deliveredMessagesWrite += sentMessage.copy(receiveTime = timeSupplier(), delayData = delayData)
                }
            }

            stream.acceptorChannel.msgVisitors += object : SimChannelMessageVisitor {
                override fun onOutbound(message: Any) {
                    message as MessageT
                    pendingMessageMap[message] = CollectedMessage(
                        connection,
                        stream.streamAcceptorPeer,
                        timeSupplier(),
                        Long.MAX_VALUE,
                        EMPTY_DELAY_DATA,
                        message
                    )
                }
                override fun onInbound(message: Any, delayData: DelayData) {
                    val sentMessage = pendingMessageMap.remove(message as MessageT)
                        ?: throw IllegalStateException("Pending message not found for message $message at ${timeSupplier()}")
                    deliveredMessagesWrite += sentMessage.copy(receiveTime = timeSupplier(), delayData = delayData)
                }
            }
        }
    }

    companion object {
        private val EMPTY_DELAY_DATA = DelayData(0, 0, 0, 0)
    }
}

data class CollectedMessage<T>(
    val connection: SimConnection,
    val sendingPeer: SimPeer,
    val sendTime: Long,
    val receiveTime: Long,
    val delayData: DelayData,
    val message: T
) {
    val delay get() = receiveTime - sendTime
    val receivingPeer get() = if (connection.dialer === sendingPeer) connection.listener else connection.dialer

    fun <R> withMessage(msg: R): CollectedMessage<R> =
        CollectedMessage(connection, sendingPeer, sendTime, receiveTime, delayData, msg)

    fun delayDataToString() = "$delay=${delayData.wireDelay}+${delayData.latencyDelay}+max(${delayData.outboundBandwidthDelay}, ${delayData.inboundBandwidthDelay})"
    override fun toString(): String {
        return "CollectedMessage[$sendingPeer => $receivingPeer, $sendTime --(${delayDataToString()})-> $receiveTime]"
    }
}
