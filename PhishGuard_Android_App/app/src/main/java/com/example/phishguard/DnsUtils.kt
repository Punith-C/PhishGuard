package com.example.phishguard

import java.io.OutputStream

object DnsUtils {

    fun isDnsPacket(packet: ByteArray): Boolean {
        return packet.size > 28 && (packet[9].toInt() and 0xFF) == 17
    }

    fun extractDomain(packet: ByteArray): String? {
        return try {
            val start = 28
            val sb = StringBuilder()
            var i = start
            while (packet[i].toInt() > 0) {
                val len = packet[i].toInt()
                i++
                sb.append(String(packet, i, len)).append(".")
                i += len
            }
            sb.dropLast(1).toString()
        } catch (e: Exception) {
            null
        }
    }

    fun sendFakeDnsResponse(output: OutputStream, query: ByteArray) {
        output.write(query)
    }
}
