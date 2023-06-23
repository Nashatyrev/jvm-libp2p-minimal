package io.libp2p.simulate.main.tcp

import io.libp2p.simulate.Bandwidth
import io.libp2p.simulate.mbitsPerSecond
import io.libp2p.tools.log
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

fun main() {
    val tcConfig = TcConfig("lo", justPrint = true)
    tcConfig.setLimits(8888, Bandwidth(10 * 1024 * 1024 / 8), 50.milliseconds)
}

class TcConfig(
    val ifc: String,
    val logger: (String) -> Unit = { log("[TcConfig] $it") },
    val justPrint: Boolean = false
) {

    val tcconfigExeDir = "/usr/local/bin"
    val tcset = "$tcconfigExeDir/tcset"
    val tcdel = "$tcconfigExeDir/tcdel"
    val tcshow = "$tcconfigExeDir/tcshow"

    fun setLimits(port: Int, bandwidth: Bandwidth, delay: Duration, inverseDirection: Boolean = false) {
        logger("Clearing config for $ifc")
        exec("$tcdel $ifc --all")
        logger("Setting limits for $ifc: bandwidth: $bandwidth, delay: $delay")

        listOf("outgoing", "incoming").forEach { direction ->

            val portOption =
                if (!inverseDirection) {
                    when (direction) {
                        "outgoing" -> "--src-port"
                        "incoming" -> "--dst-port"
                        else -> throw IllegalStateException()
                    }
                } else {
                    when (direction) {
                        "outgoing" -> "--dst-port"
                        "incoming" -> "--src-port"
                        else -> throw IllegalStateException()
                    }
                }

            val rateOption = when(bandwidth) {
                Bandwidth.UNLIM -> emptyList<String>()
                else -> listOf(
                    "--rate",
                    "${bandwidth.bytesPerSecond * 8}bps"
                )
            }

            exec(
                listOf(
                    tcset,
                    ifc,
                    "--delay",
                    delay.inWholeMilliseconds.toString(),
                    portOption,
                    "$port",
                    "--direction",
                    direction
                ) + rateOption
            )
        }

        exec("$tcshow $ifc")

        logger("Done.")
    }

    fun setTcpSlowStartAferIdle(flag: Boolean) {
        val value = if (flag) 1 else 0
        exec("sudo sysctl -w net.ipv4.tcp_slow_start_after_idle=$value")
    }

    fun setMTU(mtuSize: Int) {
        exec("/usr/sbin/ifconfig $ifc mtu $mtuSize")
    }

    fun setTcpCongestion(tcpCongestionControl: String, defaultQDisc: String) {
        exec("sudo sysctl -w net.core.default_qdisc=$defaultQDisc")
        exec("sudo sysctl -w net.ipv4.tcp_congestion_control=$tcpCongestionControl")
    }

    fun exec(args: String) = exec(args.split(" "))

    fun exec(args: List<String>, checkExsitValue: Boolean = true) {
        logger("> ${args.joinToString(" ")}")
        val rc = if (!justPrint) {
            val process = ProcessBuilder()
                .command(args)
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .redirectOutput(ProcessBuilder.Redirect.INHERIT)
                .start()

            if (!process.waitFor(5, TimeUnit.SECONDS)) {
                throw TimeoutException("Command timed out: $args")
            }

            process.exitValue()
        } else {
            0
        }

        if (checkExsitValue && rc != 0) {
            throw RuntimeException("Command failed with code $rc: $args ")
        }
    }
}