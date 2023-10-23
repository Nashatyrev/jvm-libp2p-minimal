package io.libp2p.pubsub.erasure

import io.libp2p.pubsub.DeterministicFuzzRouterFactory
import io.libp2p.pubsub.PubsubRouterDebug
import io.libp2p.pubsub.PubsubRouterTest
import io.libp2p.pubsub.erasure.router.MessageRouterFactory
import io.libp2p.pubsub.erasure.router.strategy.AckSendStrategy
import io.libp2p.pubsub.erasure.router.strategy.AckSendStrategy.Companion.ALWAYS_RESPOND_TO_INBOUND_SAMPLES
import io.libp2p.pubsub.erasure.router.strategy.SampleSendStrategy
import io.libp2p.pubsub.gossip.CurrentTimeSupplier
import java.util.concurrent.ScheduledExecutorService
import kotlin.random.Random

val random = Random(1)
val ackSendStrategy: () -> AckSendStrategy = { ALWAYS_RESPOND_TO_INBOUND_SAMPLES }
val sampleSendStrategy: () -> SampleSendStrategy = { SampleSendStrategy.sendAll() }

fun createErasureFuzzRouterFactory(): DeterministicFuzzRouterFactory =
    object : DeterministicFuzzRouterFactory {
        private var counter = 0
        override fun invoke(
            executor: ScheduledExecutorService,
            p2: CurrentTimeSupplier,
            random: java.util.Random
        ): PubsubRouterDebug {
            val erasureCoder: ErasureCoder = TestErasureCoder(4, 4)
            val messageRouterFactory: MessageRouterFactory = TestMessageRouterFactory(random, ackSendStrategy, sampleSendStrategy)

            val erasureRouter = ErasureRouter(executor, erasureCoder, messageRouterFactory)
            erasureRouter.name = "$counter"
            counter++
            return erasureRouter
        }

    }


class ErasurePubsubRouterTest(
) : PubsubRouterTest(createErasureFuzzRouterFactory()) {

}
