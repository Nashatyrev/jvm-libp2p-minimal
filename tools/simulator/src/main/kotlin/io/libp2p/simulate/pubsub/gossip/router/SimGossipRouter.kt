package io.libp2p.simulate.pubsub.gossip.router

import io.libp2p.core.pubsub.ValidationResult
import io.libp2p.pubsub.*
import io.libp2p.pubsub.gossip.*
import io.libp2p.pubsub.gossip.choke.ChokeStrategy
import io.netty.channel.ChannelHandler
import java.util.*
import java.util.concurrent.ScheduledExecutorService
import kotlin.time.Duration
import kotlin.time.toJavaDuration

class SimGossipRouter(
    params: GossipParams,
    scoreParams: GossipScoreParams,
    currentTimeSupplier: CurrentTimeSupplier,
    random: Random,
    name: String,
    mCache: MCache,
    score: GossipScore,
    chokeStrategy: ChokeStrategy,
    subscriptionTopicSubscriptionFilter: TopicSubscriptionFilter,
    protocol: PubsubProtocol,
    executor: ScheduledExecutorService,
    messageFactory: PubsubMessageFactory,
    seenMessages: SeenCache<Optional<ValidationResult>>,
    messageValidator: PubsubRouterMessageValidator,
    val serializeToBytes: Boolean,
    additionalHeartbeatDelay: Duration
) : GossipRouter(
    params,
    scoreParams,
    currentTimeSupplier,
    random,
    name,
    mCache,
    score,
    chokeStrategy,
    subscriptionTopicSubscriptionFilter,
    protocol,
    executor,
    messageFactory,
    seenMessages,
    messageValidator
) {

    override val heartbeatInitialDelay: java.time.Duration =
        params.heartbeatInterval + additionalHeartbeatDelay.toJavaDuration()

    override fun initChannelWithHandler(streamHandler: StreamHandler, handler: ChannelHandler?) {
        if (serializeToBytes) {
            super.initChannelWithHandler(streamHandler, handler)
        } else {
            // exchange Rpc.RPC messages directly (without serialization) for performance reasons
            with(streamHandler.stream) {
                handler?.also { pushHandler(it) }
                pushHandler(streamHandler)
            }
        }
    }
}