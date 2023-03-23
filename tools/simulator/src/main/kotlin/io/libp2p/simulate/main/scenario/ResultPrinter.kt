package io.libp2p.simulate.main.scenario

import io.libp2p.simulate.main.EpisubSimulation
import io.libp2p.simulate.stats.GroupByRangeAggregator
import io.libp2p.simulate.stats.StatsFactory
import io.libp2p.simulate.util.*
import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics

class ResultPrinter<TParams : Any, TResult : Any>(
    val paramsAndResults: List<Pair<TParams, TResult>>
) {

    constructor(paramsAndResults: Map<TParams, TResult>) : this(paramsAndResults.entries.map { it.key to it.value })

    val params: List<TParams> get() = paramsAndResults.map { it.first }
    val results: List<TResult> get() = paramsAndResults.map { it.second }

    inner class NumberStats<TNum : Number>(
        val namePrefix: String = "",
        val extractor: (TResult) -> List<TNum>
    ) {
        private val namePrefixDash = if (namePrefix.isEmpty()) "" else "$namePrefix-"

        fun <R : Any> addGeneric(name: String, calc: (List<TNum>) -> R) = also {
            addMetric("$namePrefixDash$name") { calc(extractor(it)) }
        }

        fun <R : Any> add(name: String, statExtractor: (DescriptiveStatistics) -> R) = also {
            addGeneric(name) {
                statExtractor(StatsFactory.DEFAULT.createStats(it).getDescriptiveStatistics())
            }
        }

        fun <R : Number> addLong(name: String, statExtractor: (DescriptiveStatistics) -> R) = also {
            add(name) {
                statExtractor(it).toLong()
            }
        }

        fun <R : Number> addDouble(name: String, decimals: Int = 2, statExtractor: (DescriptiveStatistics) -> R) =
            also {
                add(name) {
                    statExtractor(it).toDouble().toString(decimals)
                }
            }
    }

    inner class RangedNumberStats(
        val nums: NumberStats<Long>
    ) {
        var minValue: Long? = null
        var maxValue: Long? = null
        var rangeSize: Long? = null
        var paramsFilter: (TParams) -> Boolean = { true }
        var printRangeStartOnly = true

        val numbers by lazy {
            paramsAndResults
                .filter { paramsFilter(it.first) }
                .map { it.first to nums.extractor(it.second) }
                .toMap()
        }

        fun printTabSeparated(printHeader: Boolean = true): String {
            check(rangeSize != null)
            val rangeAggregator = GroupByRangeAggregator(
                numbers.mapKeys { (k, _) -> k.toString() }
            )

            val aggregate = rangeAggregator.aggregate(
                rangeSize!!,
                (minValue ?: rangeAggregator.minValue)..(maxValue ?: rangeAggregator.maxValue)
            )

            val dataS = aggregate.formatToString(printRangeStartOnly, printSeriesColumnHeaders = false)

            if (printHeader) {
                val headerS = varyingParams.transposed().print(printColumnHeaders = false)
                return headerS + "\n" + dataS
            } else {
                return dataS
            }

        }
    }

    inner class Metric(
        val name: String,
        val extractor: (TResult) -> Any
    )

    val metrics = mutableListOf<Metric>()

    val varyingParams: Table<Any> = run {
        val tab1 = Table.fromRows(params.map { it.propertiesAsMap() })
        val nonChangingParamIdxs = (0 until tab1.columnCount).filter { colIndex ->
            tab1.getColumnValues(colIndex).distinct().count() == 1
        }
        nonChangingParamIdxs
            .sortedDescending()
            .fold(tab1) { tab, removeIdx ->
                tab.removeColumn(removeIdx)
            }
    }

    val fixedParams =
        Table.fromRow(
            params.first().propertiesAsMap() -
                    varyingParams.columnNames.map { it as String }
        ).transposed()


    fun createRangedLongStats(extractor: (TResult) -> List<Long>) =
        RangedNumberStats(NumberStats("", extractor))

    fun <R : Any> addMetric(name: String, extractor: (TResult) -> R) {
        metrics += Metric(name, extractor)
    }

    fun <R : Number> addMetricDouble(name: String, decimals: Int = 2, extractor: (TResult) -> R) {
        addMetric(name) { extractor(it).toDouble().toString(decimals) }
    }

    fun <TNum : Number> addNumberStats(namePrefix: String = "", extractor: (TResult) -> List<TNum>): NumberStats<TNum> =
        NumberStats(namePrefix, extractor)


    fun createResultsTable() =
        Table.fromRows(
            results.map { result ->
                metrics
                    .map {
                        it.name to it.extractor(result)
                    }
                    .toMap()
            }
        )


    fun createTable() = varyingParams.appendColumns(createResultsTable())

    fun printPretty(): String =
        fixedParams.printPretty(printColHeader = false) + "\n\n" +
                createTable().printPretty(printRowHeader = false)

    fun printTabSeparated() =
        createTable().print("\t", false) + "\n\n"  +
                fixedParams.print(printColumnHeaders = false)

}