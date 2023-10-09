package io.libp2p.mux.yamux

import io.libp2p.core.Libp2pException
import io.libp2p.core.StreamHandler
import io.libp2p.core.multistream.MultistreamProtocolV1
import io.libp2p.etc.types.fromHex
import io.libp2p.etc.types.toHex
import io.libp2p.mux.MuxHandler
import io.libp2p.mux.MuxHandlerAbstractTest
import io.libp2p.mux.MuxHandlerAbstractTest.AbstractTestMuxFrame.Flag.*
import io.libp2p.tools.readAllBytesAndRelease
import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelHandlerContext
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import kotlin.random.Random

class YamuxHandlerTest : MuxHandlerAbstractTest() {

    override val maxFrameDataLength = 256
    private val maxBufferedConnectionWrites = 512
    private val initialWindowSize = 300
    override val localMuxIdGenerator = YamuxStreamIdGenerator(isLocalConnectionInitiator).toIterator()
    override val remoteMuxIdGenerator = YamuxStreamIdGenerator(!isLocalConnectionInitiator).toIterator()

    private val readFrameQueue = ArrayDeque<AbstractTestMuxFrame>()
    fun Long.toMuxId() = YamuxId(parentChannelId, this)

    override fun createMuxHandler(streamHandler: StreamHandler<*>): MuxHandler =
        object : YamuxHandler(
            MultistreamProtocolV1,
            maxFrameDataLength,
            null,
            streamHandler,
            true,
            maxBufferedConnectionWrites,
            initialWindowSize
        ) {
            // MuxHandler consumes the exception. Override this behaviour for testing
            @Deprecated("Deprecated in Java")
            override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
                ctx.fireExceptionCaught(cause)
            }
        }

    override fun writeFrame(frame: AbstractTestMuxFrame) {
        val muxId = frame.streamId.toMuxId()
        val yamuxFrame = when (frame.flag) {
            Open -> YamuxFrame(muxId, YamuxType.DATA, YamuxFlags.SYN, 0)
            Data -> {
                val data = frame.data.fromHex()
                YamuxFrame(
                    muxId,
                    YamuxType.DATA,
                    0,
                    data.size.toLong(),
                    data.toByteBuf(allocateBuf())
                )
            }

            Close -> YamuxFrame(muxId, YamuxType.DATA, YamuxFlags.FIN, 0)
            Reset -> YamuxFrame(muxId, YamuxType.DATA, YamuxFlags.RST, 0)
        }
        ech.writeInbound(yamuxFrame)
    }

    override fun readFrame(): AbstractTestMuxFrame? {
        val yamuxFrame = readYamuxFrame()
        if (yamuxFrame != null) {
            when (yamuxFrame.flags) {
                YamuxFlags.SYN -> readFrameQueue += AbstractTestMuxFrame(yamuxFrame.id.id, Open)
            }

            val data = yamuxFrame.data?.readAllBytesAndRelease()?.toHex() ?: ""
            when {
                yamuxFrame.type == YamuxType.DATA && data.isNotEmpty() ->
                    readFrameQueue += AbstractTestMuxFrame(yamuxFrame.id.id, Data, data)
            }

            when (yamuxFrame.flags) {
                YamuxFlags.FIN -> readFrameQueue += AbstractTestMuxFrame(yamuxFrame.id.id, Close)
                YamuxFlags.RST -> readFrameQueue += AbstractTestMuxFrame(yamuxFrame.id.id, Reset)
            }
        }

        return readFrameQueue.removeFirstOrNull()
    }

    private fun readYamuxFrame(): YamuxFrame? {
        return ech.readOutbound()
    }

    private fun readYamuxFrameOrThrow() = readYamuxFrame() ?: throw AssertionError("No outbound frames")

    @Test
    fun `test ack new stream`() {
        // signal opening of new stream
        openStreamRemote(12)

        writeStream(12, "23")

        val ackFrame = readYamuxFrameOrThrow()

        // receives ack stream
        assertThat(ackFrame.flags).isEqualTo(YamuxFlags.ACK)
        assertThat(ackFrame.type).isEqualTo(YamuxType.WINDOW_UPDATE)

        closeStream(12)
    }

    @Test
    fun `test window update is sent after more than half of the window is depleted`() {
        openStreamLocal()
        val streamId = readFrameOrThrow().streamId

        // > 1/2 window size
        val length = (initialWindowSize / 2) + 42
        ech.writeInbound(
            YamuxFrame(
                streamId.toMuxId(),
                YamuxType.DATA,
                0,
                length.toLong(),
                "42".repeat(length).fromHex().toByteBuf(allocateBuf())
            )
        )

        val windowUpdateFrame = readYamuxFrameOrThrow()

        // window frame is sent based on the new window
        assertThat(windowUpdateFrame.flags).isZero()
        assertThat(windowUpdateFrame.type).isEqualTo(YamuxType.WINDOW_UPDATE)
        assertThat(windowUpdateFrame.length).isEqualTo(length.toLong())
    }

    @Test
    fun `data should be buffered and sent after window increased from zero`() {
        val handler = openStreamLocal()
        val streamId = readFrameOrThrow().streamId

        ech.writeInbound(
            YamuxFrame(
                streamId.toMuxId(),
                YamuxType.WINDOW_UPDATE,
                YamuxFlags.ACK,
                -initialWindowSize.toLong()
            )
        )

        handler.ctx.writeAndFlush("1984".fromHex().toByteBuf(allocateBuf()))

        assertThat(readFrame()).isNull()

        ech.writeInbound(YamuxFrame(streamId.toMuxId(), YamuxType.WINDOW_UPDATE, YamuxFlags.ACK, 5000))
        val frame = readFrameOrThrow()
        assertThat(frame.data).isEqualTo("1984")
    }

    @Test
    fun `buffered data should not be sent if it does not fit within window`() {
        val handler = openStreamLocal()
        val streamId = readFrameOrThrow().streamId

        ech.writeInbound(
            YamuxFrame(
                streamId.toMuxId(),
                YamuxType.WINDOW_UPDATE,
                YamuxFlags.ACK,
                -initialWindowSize.toLong()
            )
        )

        val message = "1984".fromHex().toByteBuf(allocateBuf())
        // 2 bytes per message
        handler.ctx.writeAndFlush(message)
        handler.ctx.writeAndFlush(message.copy())

        assertThat(readFrame()).isNull()

        ech.writeInbound(
            YamuxFrame(
                streamId.toMuxId(),
                YamuxType.WINDOW_UPDATE,
                YamuxFlags.ACK,
                2
            )
        )

        var frame = readFrameOrThrow()
        // one message is received
        assertThat(frame.data).isEqualTo("1984")
        // need to wait for another window update to send more data
        assertThat(readFrame()).isNull()
        // sending window update
        ech.writeInbound(
            YamuxFrame(
                streamId.toMuxId(),
                YamuxType.WINDOW_UPDATE,
                YamuxFlags.ACK,
                1
            )
        )
        frame = readFrameOrThrow()
        assertThat(frame.data).isEqualTo("19")

        ech.writeInbound(
            YamuxFrame(
                streamId.toMuxId(),
                YamuxType.WINDOW_UPDATE,
                YamuxFlags.ACK,
                10000
            )
        )
        frame = readFrameOrThrow()
        assertThat(frame.data).isEqualTo("84")
    }

    @Test
    fun `overflowing buffer sends RST flag and throws an exception`() {
        val handler = openStreamLocal()
        val muxId = readFrameOrThrow().streamId.toMuxId()

        ech.writeInbound(
            YamuxFrame(
                muxId,
                YamuxType.WINDOW_UPDATE,
                YamuxFlags.ACK,
                -initialWindowSize.toLong()
            )
        )

        val createMessage: () -> ByteBuf =
            { "42".repeat(maxBufferedConnectionWrites / 5).fromHex().toByteBuf(allocateBuf()) }

        for (i in 1..5) {
            val writeResult = handler.ctx.writeAndFlush(createMessage())
            assertThat(writeResult.isSuccess).isTrue()
        }

        // next message will overflow the configured buffer
        val writeResult = handler.ctx.writeAndFlush(createMessage())
        assertThat(writeResult.isSuccess).isFalse()
        assertThat(writeResult.cause())
            .isInstanceOf(Libp2pException::class.java)
            .hasMessage("Overflowed send buffer (612/512). Last stream attempting to write: $muxId")

        val frame = readYamuxFrameOrThrow()
        assertThat(frame.flags).isEqualTo(YamuxFlags.RST)
    }

    @Test
    fun `frames are sent in order when send buffer is used`() {
        val handler = openStreamLocal()
        val streamId = readFrameOrThrow().streamId

        val createMessage: (String) -> ByteBuf =
            { it.toByteArray().toByteBuf(allocateBuf()) }

        val sendWindowUpdate: (Int) -> Unit = {
            ech.writeInbound(
                YamuxFrame(
                    streamId.toMuxId(),
                    YamuxType.WINDOW_UPDATE,
                    YamuxFlags.ACK,
                    it.toLong()
                )
            )
        }

        // approximately every 5 messages window size will be depleted
        val messagesToSend = 500
        val customWindowSize = 14
        sendWindowUpdate(-initialWindowSize + customWindowSize)

        val range = 1..messagesToSend

        // 100 window updates should be sent to ensure buffer is flushed and all messages are sent
        // so will send them at random times ensuring maxBufferedConnectionWrites can never be reached
        val windowUpdatesIndices = (range).chunked(100).flatMap {
            it.shuffled().take(20)
        }

        for (i in range) {
            if (i in windowUpdatesIndices) {
                sendWindowUpdate(customWindowSize)
            }
            handler.ctx.writeAndFlush(createMessage(i.toString()))
        }

        val receivedData = generateSequence {
            readYamuxFrame()
        }
            .map {
                assertThat(it.data).isNotNull()
                String(it.data!!.readAllBytesAndRelease())
            }
            .joinToString(separator = "")

        val expectedData = range.joinToString(separator = "")

        assertThat(receivedData).isEqualTo(expectedData)
    }

    @Test
    fun `test ping`() {
        val id: Long = YamuxId.SESSION_STREAM_ID
        ech.writeInbound(
            YamuxFrame(
                id.toMuxId(),
                YamuxType.PING,
                YamuxFlags.SYN,
                // opaque value, echoed back
                3
            )
        )

        val pingFrame = readYamuxFrameOrThrow()

        assertThat(pingFrame.flags).isEqualTo(YamuxFlags.ACK)
        assertThat(pingFrame.type).isEqualTo(YamuxType.PING)
        assertThat(pingFrame.length).isEqualTo(3)
    }

    @Test
    fun `test go away`() {
        val id: Long = YamuxId.SESSION_STREAM_ID
        ech.writeInbound(
            YamuxFrame(
                id.toMuxId(),
                YamuxType.GO_AWAY,
                0,
                // normal termination
                0x2
            )
        )

        val yamuxHandler = multistreamHandler as YamuxHandler
        assertThat(yamuxHandler.goAwayPromise).isCompletedWithValue(0x2)
    }

    @Test
    fun `test no go away on close`() {
        val yamuxHandler = multistreamHandler as YamuxHandler

        assertThat(yamuxHandler.goAwayPromise).isNotDone
        ech.close()
        assertThat(yamuxHandler.goAwayPromise).isCompletedExceptionally
    }

    @Test
    fun `opening a stream with wrong streamId parity should throw and close connection`() {
        val isRemoteConnectionInitiator = !isLocalConnectionInitiator
        val correctRemoteId = 10L + if (isRemoteConnectionInitiator) 1 else 0
        val incorrectId = correctRemoteId + 1
        Assertions.assertThrows(Libp2pException::class.java) {
            openStreamRemote(incorrectId)
        }
        assertThat(ech.isOpen).isFalse()
    }

    @Test
    fun `negative sendWindowSize should be correctly handled`() {
        val handler = openStreamLocal()
        val muxId = readFrameOrThrow().streamId.toMuxId()

        val msg = "42".repeat(initialWindowSize + 1).fromHex().toByteBuf(allocateBuf())
        // writing a message which is larger than sendWindowSize
        handler.ctx.writeAndFlush(msg)

        // sendWindowSize is 0 now

        // remote party wants to reduce the window by 10
        ech.writeInbound(
            YamuxFrame(
                muxId,
                YamuxType.WINDOW_UPDATE,
                YamuxFlags.ACK,
                -10
            )
        )

        // sendWindowSize is -10 now

        val msgPart1 = readYamuxFrameOrThrow()
        assertThat(msgPart1.length).isEqualTo(256L)
        assertThat(msgPart1.data!!.readableBytes()).isEqualTo(256)
        msgPart1.data!!.release()

        val msgPart2 = readYamuxFrameOrThrow()
        assertThat(msgPart2.length.toInt()).isEqualTo(initialWindowSize - 256)
        assertThat(msgPart2.data!!.readableBytes()).isEqualTo(initialWindowSize - 256)
        msgPart2.data!!.release()

        // ACKing message receive
        ech.writeInbound(
            YamuxFrame(
                muxId,
                YamuxType.WINDOW_UPDATE,
                YamuxFlags.ACK,
                initialWindowSize.toLong()
            )
        )

        val msgPart3 = readYamuxFrameOrThrow()
        assertThat(msgPart3.length).isEqualTo(1L)
        assertThat(msgPart3.data!!.readableBytes()).isEqualTo(1)
        msgPart3.data!!.release()
    }

    companion object {
        private fun YamuxStreamIdGenerator.toIterator() = iterator {
            while (true) {
                yield(this@toIterator.next())
            }
        }
    }
}
