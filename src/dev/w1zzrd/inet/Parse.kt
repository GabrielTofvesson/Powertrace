package dev.w1zzrd.inet

private val traceHead = "traceroute to (.*?) \\(((?:(?:[0-9]{1,3}\\.){3}[0-9]{1,3})|(?:[0-9A-Fa-f]{4}:){4}(?:(?:(?:[0-9A-Fa-f]{4}:){3}[0-9A-Fa-f]{4})|:))\\), (.*?) hops max, (.*?) byte packets".toRegex()
//private val traceLine = " *([0-9]+) {2}(?:(?: ?(.*?) \\((.*?)\\) {2}(.*?) ms ?)|(\\*) ?)(?:(?:(?: ?(.*?) \\((.*?)\\))? {2}(.*?) ms ?)|(\\*) ?)?(?:(?:(?: ?(.*?) \\((.*?)\\))? {2}(.*?) ms)|(\\*))?".toRegex()
private val traceLine = " *([0-9]+) {2}(?:(?:(\\*) ?)|(?: ?(.*?) \\((.*?)\\) {2}(.*?) ms ?))(?:(?: ?([0-9]+\\.[0-9]+) ms)|(?:(\\*) ?)|(?:(?: ?(.*?) \\((.*?)\\))? {2}([0-9]+\\.[0-9]+) ms ?))?(?:(?: ?([0-9]+\\.[0-9]+) ms)|(\\*)|(?:(?: ?(.*?) \\((.*?)\\))? {2}(.*?) ms))?".toRegex()
private val ipv4 = "(?:[0-9]{1,3}\\.){3}[0-9]{1,3}".toRegex()
private val ipv6 = "(?:[0-9A-Fa-f]{4}:){4}(?:(?:(?:[0-9A-Fa-f]{4}:){3}[0-9A-Fa-f]{4})|:)".toRegex()
private val ipv6_2 = "(?:[0-9A-Fa-f]{4}:){4}:".toRegex()

private infix fun Int.byte(index: Int) = (this ushr (index shl 3)) and 0xFF
private infix fun Long._byte(index: Int) = (this ushr (index shl 3)) and 0xFF
private infix fun Long.byte(index: Int) = object {
    override fun toString() = "${if((this@byte _byte index) < 16) "0" else ""}${(this@byte _byte index).toString(16)}"
}

sealed class IP {
    companion object {
        fun parseIP(value: String): IP? {
            return when {
                ipv4.matches(value) -> IPv4(value.split('.').map { it.toInt() }.reduce { acc, v -> (acc shl 8) or v })
                ipv6_2.matches(value) -> IPv6(IPv6ID(value.split(':').subList(0, 4)), null)
                ipv6.matches(value) -> IPv6(IPv6ID(value.split(':').subList(0, 4)), IPv6ID(value.split(':').subList(4, 8)))
                else -> null
            }
        }
    }
}

data class IPv4(val rawIP: Int) : IP() {
    val first = rawIP byte 3
    val second = rawIP byte 2
    val third = rawIP byte 1
    val fourth = rawIP byte 0

    override fun toString() = "$first.$second.$third.$fourth"
}

data class IPv6ID(val rawIP: Long) {
    constructor(strings: Iterable<String>):
            this(strings.map { it.toLong(16) }.reduce { acc, l -> (acc shl 16) or l })

    val first = rawIP byte 7
    val second = rawIP byte 6
    val third = rawIP byte 5
    val fourth = rawIP byte 4
    val fifth = rawIP byte 3
    val sixth = rawIP byte 2
    val seventh = rawIP byte 1
    val eighth = rawIP byte 0

    override fun toString() = "$first$second:$third$fourth:$fifth$sixth:$seventh$eighth"
}

data class IPv6(val rawIP: IPv6ID, val ifID: IPv6ID?) : IP() {
    override fun toString() = "$rawIP:${ifID?.toString() ?: ":"}"
}

data class TraceLine(val hop: Int, val first: TraceEntry, val second: TraceEntry, val third: TraceEntry)

sealed class TraceEntry
data class SuccessEntry(val addr: String, val ip: IP, val delay: Float): TraceEntry()
object FailEntry: TraceEntry()


fun parseLine(line: String): TraceLine? {
    val match = traceLine.matchEntire(line)

    if (match == null) {
        println("Could not parse: $line")
        return null
    }

    data class MatchResult(val adr: String?, val ip: String?, val t: String?, val f: String?) {
        fun toTraceEntry(previousAdr: String?, previousIP: String?) =
            if(f != null || (adr == null && previousAdr == null) || (ip == null && previousIP == null))
                FailEntry
            else {
                adr ?: previousAdr ?: println("No adr")
                ip ?: previousIP ?: println("No ip")
                t ?: println("No t")
                SuccessEntry(adr ?: previousAdr!!, IP.parseIP(ip ?: previousIP!!)!!, t!!.toFloat())
            }
    }

    // Parse results in a semi-janky fashion
    val results = arrayOf(
        MatchResult(
            match.groups[3]?.value,
            match.groups[4]?.value,
            match.groups[5]?.value,
            match.groups[2]?.value
        ),
        MatchResult(
            match.groups[8]?.value,
            match.groups[9]?.value,
            match.groups[10]?.value ?: match.groups[6]?.value,
            match.groups[7]?.value
        ),
        MatchResult(
            match.groups[13]?.value,
            match.groups[14]?.value,
            match.groups[15]?.value ?: match.groups[11]?.value,
            match.groups[12]?.value
        )
    )

    try {
        val first = results[0].toTraceEntry(null, null)
        val second = results[1].toTraceEntry(results[0].adr, results[0].ip)
        val third = results[2].toTraceEntry(
            results[0].adr ?: results[1].adr,
            results[0].ip ?: results[1].ip
        )

        return TraceLine(match.groups[1]!!.value.toInt(), first, second, third)
    } catch (e: Throwable) {
        println(line)
        throw e
    }
}

data class TraceHead(val target: String, val ip: IP, val hops: Int, val maxHops: Int, val packets: Int)
data class TraceRoute(val head: TraceHead, val lines: Array<TraceLine>)

fun parseTrace(trace: String): TraceRoute? {
    // Bad domain name
    if (trace.contains("Temporary failure in name resolution")) return null

    val traceLines = trace.split('\n')
    val traces = traceLines.subList(1, traceLines.size).filterNot { it.isBlank() }.map { parseLine(it)!! }.toTypedArray()
    val head = traceHead.matchEntire(traceLines[0])

    if (head == null) {
        println("An error occurred when parsing trace. Please check your internet connection and try again")
        return null
    }

    return TraceRoute(
        TraceHead(
            head.groupValues[1],
            IP.parseIP(head.groupValues[2])!!,
            traces.last().hop,
            head.groupValues[3].toInt(),
            head.groupValues[4].toInt()
        ),
        traceLines.subList(1, traceLines.size).filterNot { it.isBlank() }.map { parseLine(it)!! }.toTypedArray()
    )
}