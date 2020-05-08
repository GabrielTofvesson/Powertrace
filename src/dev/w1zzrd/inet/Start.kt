package dev.w1zzrd.inet

import java.io.File
import java.io.FileOutputStream
import java.lang.StringBuilder
import java.util.*

fun <T> min(vararg values: T) where T: Comparable<T> = values.reduce { a, b -> if (a < b) a else b }
fun <T> max(vararg values: T) where T: Comparable<T> = values.reduce { a, b -> if (a > b) a else b }

fun makePad(len: Int): String {
    val array = CharArray(len)
    Arrays.fill(array, ' ')
    return String(array)
}

fun runTrace(host: String): String {
    val trace = Runtime.getRuntime().exec(arrayOf("traceroute", "-m", "128", "-T", host))
    val inStream = trace.inputStream

    val collect = StringBuilder(2048)
    val read = ByteArray(512)
    while (inStream.available() > 0 || trace.isAlive)
        if (inStream.available() > 0) {
            val readCount = inStream.read(read)
            collect.append(String(read, 0, readCount))
        }

    return collect.toString()
}

fun generateTraceData(host: String, pad: String) {
    println("($host)$pad Tracing...")

    val traceData = parseTrace(runTrace(host))
    if (traceData == null) {
        println("($host)$pad Could not run a trace")
        return
    }

    println("($host)$pad Analysing results...")
    val dest = traceData.lines.last()
    val successes = arrayOf(dest.first, dest.second, dest.third).filterIsInstance<SuccessEntry>().map { it.delay }.toTypedArray()

    val analysis = File(host)

    if(analysis.isFile && !analysis.delete()) {
        println("($host)$pad Could not overwrite existing entry")
        return
    }
    if(!analysis.createNewFile()) {
        println("($host)$pad Could not create entry")
        return
    }

    println("($host)$pad Consolidating...")

    // Write relevant data to file
    val output = FileOutputStream(analysis)

    if(successes.isEmpty()) { // Trace failed
        output.write("timeout,timeout,${traceData.head.hops}\n".toByteArray())
    } else { // Got full trace
        output.write("${min(*successes)},${max(*successes)},${traceData.head.hops}\n".toByteArray())
    }

    output.close()

    println("($host)$pad Complete!")
}

fun main(vararg args: String) {
    if(args.isEmpty()) {
        println("Please supply a list of domains to trace")
        return
    }

    val maxLen = max(*args.map { it.length }.toTypedArray())

    val tasks = args.map { val t = Thread{ generateTraceData(it, makePad(maxLen - it.length)) }; t.name = it; t }
    tasks.forEach(Thread::start)
    tasks.forEach(Thread::join)

    println("Done!")
}