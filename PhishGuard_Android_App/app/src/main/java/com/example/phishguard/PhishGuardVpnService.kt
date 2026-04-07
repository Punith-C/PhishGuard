package com.example.phishguard

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
class PhishGuardVpnService : VpnService() {

    companion object {
        private const val TAG                 = "PhishGuardVpnService"

        private const val NOTIF_CHANNEL_ID    = "phishguard_vpn"
        private const val ALERT_CHANNEL_ID    = "phishguard_alerts"
        private const val ALERT_CHANNEL_NAME  = "Phishing Alerts"
        private const val NOTIF_ID            = 1001

        private const val DNS_PORT            = 53
        private const val HTTPS_PORT          = 443
        private const val REAL_DNS_1          = "8.8.8.8"
        private const val REAL_DNS_2          = "8.8.4.4"
        private const val VPN_ADDRESS         = "10.0.0.2"
        private const val VPN_PREFIX_LEN      = 32
        private const val DNS_TIMEOUT_MS      = 3_000
        private const val PACKET_BUF_SIZE     = 32_767

        const val ACTION_STATUS_CHANGED       = "com.example.phishguard.VPN_STATUS_CHANGED"
        const val EXTRA_IS_RUNNING            = "is_running"
        const val ACTION_START                = "com.example.phishguard.START_VPN"
        const val ACTION_STOP                 = "com.example.phishguard.STOP_VPN"
        const val ACTION_DOMAIN_ALLOWED       = "com.example.phishguard.DOMAIN_ALLOWED"
        const val EXTRA_ALLOWED_DOMAIN        = "allowed_domain"
        private val DOH_SERVER_IPS = setOf(
            "8.8.8.8", "8.8.4.4",
            "1.1.1.1", "1.0.0.1",
            "9.9.9.9", "149.112.112.112",
            "208.67.222.222", "208.67.220.220",
            "185.228.168.9", "185.228.169.9",
            "45.90.28.0", "45.90.30.0",
            "94.140.14.14", "94.140.15.15",
            "8.26.56.26", "8.20.247.20"
        )
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val running      = AtomicBoolean(false)
    private val executor     = Executors.newCachedThreadPool()

    private val recentBlocks = ConcurrentHashMap<String, Long>()
    private val recentAllows = ConcurrentHashMap<String, Long>()
    private val CACHE_TTL_MS = 60_000L

    private val domainAllowedReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val domain = intent.getStringExtra(EXTRA_ALLOWED_DOMAIN) ?: return
            recentBlocks.remove(domain)
            recentAllows[domain] = System.currentTimeMillis()
            Log.i(TAG, "Cache cleared for allowed domain: $domain")
        }
    }

    override fun onCreate() {
        super.onCreate()
        PhishingDetector.init(applicationContext)
        createNotificationChannels()
        registerDomainAllowedReceiver()
        Log.i(TAG, "VPN service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }
        if (!running.get()) {
            startForeground(NOTIF_ID, buildForegroundNotification("PhishGuard active"))
            executor.execute { startVpn() }
        }
        return START_STICKY
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        executor.shutdownNow()
        try { unregisterReceiver(domainAllowedReceiver) } catch (_: Exception) {}
        super.onDestroy()
        Log.i(TAG, "VPN service destroyed")
    }
    private fun registerDomainAllowedReceiver() {
        val filter = IntentFilter(ACTION_DOMAIN_ALLOWED)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(domainAllowedReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(domainAllowedReceiver, filter)
        }
    }
    private fun startVpn() {
        try {
            val builder = Builder()
                .setSession("PhishGuard")
                .addAddress(VPN_ADDRESS, VPN_PREFIX_LEN)
                .addDnsServer(REAL_DNS_1)
                .addDnsServer(REAL_DNS_2)
                .setMtu(1500)
                .setBlocking(true)
            DOH_SERVER_IPS.forEach { ip ->
                try { builder.addRoute(ip, 32) }
                catch (e: Exception) { Log.w(TAG, "addRoute $ip failed: ${e.message}") }
            }

            try { builder.addDisallowedApplication(packageName) }
            catch (e: Exception) { Log.w(TAG, "Cannot exclude self: ${e.message}") }

            vpnInterface = builder.establish() ?: run {
                Log.e(TAG, "VPN establish() returned null — no permission?")
                return
            }

            running.set(true)
            broadcastStatus(true)
            Log.i(TAG, "VPN tunnel established")
            runTunLoop()

        } catch (e: Exception) {
            Log.e(TAG, "startVpn failed: ${e.message}", e)
            stopVpn()
        }
    }

    private fun stopVpn() {
        if (!running.compareAndSet(true, false)) return
        try {
            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN: ${e.message}")
        }
        stopForeground(true)
        stopSelf()
        broadcastStatus(false)
        Log.i(TAG, "VPN stopped")
    }
    private fun runTunLoop() {
        val vpnFd = vpnInterface?.fileDescriptor ?: return
        val input  = FileInputStream(vpnFd)
        val output = FileOutputStream(vpnFd)
        val packet = ByteArray(PACKET_BUF_SIZE)

        Log.i(TAG, "TUN loop started")

        while (running.get()) {
            try {
                val len = input.read(packet)
                if (len <= 0) continue

                val buf = ByteBuffer.wrap(packet, 0, len)
                buf.order(ByteOrder.BIG_ENDIAN)
                if (!isIpv4(buf)) continue
                if (isTcp(buf)) {
                    val destPort = getTcpDestPort(buf)
                    val destIp   = getDestIpString(buf)

                    if (destPort == HTTPS_PORT && destIp in DOH_SERVER_IPS) {
                        // Kill this DoH connection with a TCP RST so the browser
                        // falls back to standard UDP 53 which we intercept below.
                        val copy = packet.copyOf(len)
                        executor.execute { sendTcpRst(copy, len, output) }
                        Log.d(TAG, "DoH RST → $destIp:$destPort")
                    }
                    continue
                }
                if (!isUdp(buf)) continue

                val destPort = getUdpDestPort(buf)
                if (destPort != DNS_PORT) continue

                val copy = packet.copyOf(len)
                executor.execute { handleDnsPacket(len, output, copy) }

            } catch (e: Exception) {
                if (running.get()) Log.e(TAG, "TUN loop error: ${e.message}")
            }
        }

        Log.i(TAG, "TUN loop exited")
    }

    private fun handleDnsPacket(
        packetLen: Int,
        tunOut: FileOutputStream,
        rawPacket: ByteArray,
    ) {
        try {
            val ipHeaderLen = (rawPacket[0].toInt() and 0x0F) * 4
            val dnsOffset   = ipHeaderLen + 8
            if (dnsOffset >= packetLen) return

            val dnsPayload = rawPacket.copyOfRange(dnsOffset, packetLen)
            val hostname   = parseDnsQuery(dnsPayload) ?: return

            Log.d(TAG, "DNS query: $hostname")

            val now = System.currentTimeMillis()
            if (BlockedDomainsManager.isAllowed(hostname)) {
                recentBlocks.remove(hostname)
                recentAllows[hostname] = now
                forwardDnsToReal(rawPacket, packetLen, tunOut)
                return
            }
            recentAllows.remove(hostname)

            recentAllows[hostname]?.let { ts ->
                if (now - ts < CACHE_TTL_MS) {
                    forwardDnsToReal(rawPacket, packetLen, tunOut)
                    return
                }
            }
            recentBlocks[hostname]?.let { ts ->
                if (now - ts < CACHE_TTL_MS) {
                    val tid = getDnsTransactionId(dnsPayload)
                    sendDnsResponse(rawPacket, buildNxDomainResponse(dnsPayload, tid), tunOut)
                    return
                }
            }
            val isPhish = PhishingDetector.isPhishing(hostname)

            if (isPhish) {
                Log.w(TAG, "BLOCKED: $hostname")
                recentBlocks[hostname] = now
                cleanCache()

                val tid = getDnsTransactionId(dnsPayload)
                sendDnsResponse(rawPacket, buildNxDomainResponse(dnsPayload, tid), tunOut)

                postBlockedNotification(hostname)
                recordBlockedDomain(hostname)

            } else {
                recentAllows[hostname] = now
                forwardDnsToReal(rawPacket, packetLen, tunOut)
            }

        } catch (e: Exception) {
            Log.e(TAG, "handleDnsPacket error: ${e.message}")
            try { forwardDnsToReal(rawPacket, packetLen, tunOut) } catch (_: Exception) {}
        }
    }
    private fun forwardDnsToReal(rawPacket: ByteArray, len: Int, tunOut: FileOutputStream) {
        executor.execute {
            try {
                val ipHeaderLen = (rawPacket[0].toInt() and 0x0F) * 4
                val dnsPayload  = rawPacket.copyOfRange(ipHeaderLen + 8, len)

                val sock = DatagramSocket()

                protect(sock)

                sock.soTimeout = DNS_TIMEOUT_MS
                sock.use {
                    val dnsServer = InetAddress.getByName(REAL_DNS_1)
                    sock.send(DatagramPacket(dnsPayload, dnsPayload.size, dnsServer, DNS_PORT))

                    val respBuf = ByteArray(PACKET_BUF_SIZE)
                    val respPkt = DatagramPacket(respBuf, respBuf.size)
                    sock.receive(respPkt)

                    sendDnsResponse(rawPacket, respPkt.data.copyOf(respPkt.length), tunOut)
                }
            } catch (e: Exception) {
                Log.w(TAG, "DNS forward failed: ${e.message}")
            }
        }
    }
    private fun sendDnsResponse(
        originalIpPacket: ByteArray,
        dnsPayload: ByteArray,
        tunOut: FileOutputStream,
    ) {
        try {
            val ipHeaderLen = (originalIpPacket[0].toInt() and 0x0F) * 4

            val origSrcIp   = originalIpPacket.copyOfRange(12, 16)
            val origDstIp   = originalIpPacket.copyOfRange(16, 20)
            val origSrcPort = ((originalIpPacket[ipHeaderLen].toInt()     and 0xFF) shl 8) or
                    (originalIpPacket[ipHeaderLen + 1].toInt() and 0xFF)
            val origDstPort = ((originalIpPacket[ipHeaderLen + 2].toInt() and 0xFF) shl 8) or
                    (originalIpPacket[ipHeaderLen + 3].toInt() and 0xFF)

            val udpLen   = 8 + dnsPayload.size
            val totalLen = 20 + udpLen

            val response = ByteArray(totalLen)
            val bb = ByteBuffer.wrap(response).order(ByteOrder.BIG_ENDIAN)

            // IP header
            bb.put(0x45.toByte())
            bb.put(0x00.toByte())
            bb.putShort(totalLen.toShort())
            bb.putShort(0x0000.toShort())
            bb.putShort(0x4000.toShort())
            bb.put(0x40.toByte())
            bb.put(0x11.toByte())
            bb.putShort(0x0000.toShort())
            bb.put(origDstIp)
            bb.put(origSrcIp)

            val checksum = ipChecksum(response, 0, 20)
            response[10] = (checksum shr 8).toByte()
            response[11] = (checksum and 0xFF).toByte()

            // UDP header
            bb.putShort(origDstPort.toShort())
            bb.putShort(origSrcPort.toShort())
            bb.putShort(udpLen.toShort())
            bb.putShort(0x0000.toShort())
            bb.put(dnsPayload)

            synchronized(tunOut) { tunOut.write(response) }

        } catch (e: Exception) {
            Log.e(TAG, "sendDnsResponse error: ${e.message}")
        }
    }
    private fun sendTcpRst(rawPacket: ByteArray, packetLen: Int, tunOut: FileOutputStream) {
        try {
            val ipHeaderLen = (rawPacket[0].toInt() and 0x0F) * 4
            if (packetLen < ipHeaderLen + 20) return

            val origSrcIp   = rawPacket.copyOfRange(12, 16)
            val origDstIp   = rawPacket.copyOfRange(16, 20)
            val origSrcPort = ((rawPacket[ipHeaderLen].toInt()     and 0xFF) shl 8) or
                    (rawPacket[ipHeaderLen + 1].toInt() and 0xFF)
            val origDstPort = ((rawPacket[ipHeaderLen + 2].toInt() and 0xFF) shl 8) or
                    (rawPacket[ipHeaderLen + 3].toInt() and 0xFF)

            val origSeq = ((rawPacket[ipHeaderLen + 4].toInt() and 0xFF).toLong() shl 24) or
                    ((rawPacket[ipHeaderLen + 5].toInt() and 0xFF).toLong() shl 16) or
                    ((rawPacket[ipHeaderLen + 6].toInt() and 0xFF).toLong() shl 8)  or
                    (rawPacket[ipHeaderLen + 7].toInt() and 0xFF).toLong()
            val ackNum = (origSeq + 1L) and 0xFFFFFFFFL

            val rstPacket = ByteArray(40)
            val bb = ByteBuffer.wrap(rstPacket).order(ByteOrder.BIG_ENDIAN)

            bb.put(0x45.toByte())
            bb.put(0x00.toByte())
            bb.putShort(40.toShort())
            bb.putShort(0x0000.toShort())
            bb.putShort(0x4000.toShort())
            bb.put(0x40.toByte())
            bb.put(0x06.toByte())
            bb.putShort(0x0000.toShort())
            bb.put(origDstIp)
            bb.put(origSrcIp)

            val ipCheck = ipChecksum(rstPacket, 0, 20)
            rstPacket[10] = (ipCheck shr 8).toByte()
            rstPacket[11] = (ipCheck and 0xFF).toByte()

            // ── TCP header ────────────────────────────────────────
            bb.putShort(origDstPort.toShort())
            bb.putShort(origSrcPort.toShort())
            bb.putInt(0)
            bb.putInt(ackNum.toInt())
            bb.put(0x50.toByte())
            bb.put(0x14.toByte())
            bb.putShort(0x0000.toShort())
            bb.putShort(0x0000.toShort())
            bb.putShort(0x0000.toShort())

            // TCP checksum over pseudo-header
            val tcpSegment = rstPacket.copyOfRange(20, 40)
            val tcpCheck   = tcpChecksum(origDstIp, origSrcIp, tcpSegment)
            rstPacket[36] = (tcpCheck shr 8).toByte()
            rstPacket[37] = (tcpCheck and 0xFF).toByte()

            synchronized(tunOut) { tunOut.write(rstPacket) }
            Log.d(TAG, "TCP RST sent: port $origSrcPort ← $origDstPort")

        } catch (e: Exception) {
            Log.e(TAG, "sendTcpRst error: ${e.message}")
        }
    }
    private fun parseDnsQuery(dns: ByteArray): String? {
        return try {
            if (dns.size < 12) return null
            val flags = ((dns[2].toInt() and 0xFF) shl 8) or (dns[3].toInt() and 0xFF)
            if (flags and 0x8000 != 0) return null   // response, not query

            val qdcount = ((dns[4].toInt() and 0xFF) shl 8) or (dns[5].toInt() and 0xFF)
            if (qdcount == 0) return null

            val sb = StringBuilder()
            var i = 12

            while (i < dns.size) {
                val len = dns[i].toInt() and 0xFF
                if (len == 0) break
                if (len and 0xC0 == 0xC0) break
                if (i + len + 1 > dns.size) return null
                if (sb.isNotEmpty()) sb.append('.')
                sb.append(String(dns, i + 1, len, Charsets.UTF_8))
                i += len + 1
            }

            val hostname = sb.toString().lowercase()
            if (hostname.isEmpty()) null else hostname
        } catch (e: Exception) { null }
    }

    private fun getDnsTransactionId(dns: ByteArray): Short {
        if (dns.size < 2) return 0
        return (((dns[0].toInt() and 0xFF) shl 8) or (dns[1].toInt() and 0xFF)).toShort()
    }

    private fun buildNxDomainResponse(queryDns: ByteArray, transactionId: Short): ByteArray {
        val response = queryDns.copyOf()
        response[0] = (transactionId.toInt() shr 8).toByte()
        response[1] = (transactionId.toInt() and 0xFF).toByte()
        response[2] = 0x81.toByte()
        response[3] = 0x83.toByte()
        if (response.size >= 8)  { response[6]  = 0; response[7]  = 0 }   // ANCOUNT=0
        if (response.size >= 10) { response[8]  = 0; response[9]  = 0 }   // NSCOUNT=0
        if (response.size >= 12) { response[10] = 0; response[11] = 0 }   // ARCOUNT=0
        return response
    }
    private fun isIpv4(buf: ByteBuffer) = (buf.get(0).toInt() and 0xF0) shr 4 == 4

    private fun isUdp(buf: ByteBuffer): Boolean {
        val ipHeaderLen = (buf.get(0).toInt() and 0x0F) * 4
        if (buf.limit() < ipHeaderLen + 1) return false
        return buf.get(9).toInt() and 0xFF == 17
    }
    private fun isTcp(buf: ByteBuffer): Boolean {
        val ipHeaderLen = (buf.get(0).toInt() and 0x0F) * 4
        if (buf.limit() < ipHeaderLen + 1) return false
        return buf.get(9).toInt() and 0xFF == 6
    }
    private fun getUdpDestPort(buf: ByteBuffer): Int {
        val ipHeaderLen = (buf.get(0).toInt() and 0x0F) * 4
        if (buf.limit() < ipHeaderLen + 4) return -1
        return ((buf.get(ipHeaderLen + 2).toInt() and 0xFF) shl 8) or
                (buf.get(ipHeaderLen + 3).toInt() and 0xFF)
    }
    private fun getTcpDestPort(buf: ByteBuffer): Int {
        val ipHeaderLen = (buf.get(0).toInt() and 0x0F) * 4
        if (buf.limit() < ipHeaderLen + 4) return -1
        return ((buf.get(ipHeaderLen + 2).toInt() and 0xFF) shl 8) or
                (buf.get(ipHeaderLen + 3).toInt() and 0xFF)
    }
    private fun getDestIpString(buf: ByteBuffer): String {
        if (buf.limit() < 20) return ""
        return "${buf.get(16).toInt() and 0xFF}.${buf.get(17).toInt() and 0xFF}" +
                ".${buf.get(18).toInt() and 0xFF}.${buf.get(19).toInt() and 0xFF}"
    }
    private fun ipChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        while (i < offset + length - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (length % 2 != 0) sum += (data[offset + length - 1].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv() and 0xFFFF
    }
    private fun tcpChecksum(srcIp: ByteArray, dstIp: ByteArray, tcpSegment: ByteArray): Int {
        val pseudo = ByteArray(12 + tcpSegment.size)
        System.arraycopy(srcIp,      0, pseudo, 0,  4)
        System.arraycopy(dstIp,      0, pseudo, 4,  4)
        pseudo[8]  = 0
        pseudo[9]  = 6
        pseudo[10] = (tcpSegment.size shr 8).toByte()
        pseudo[11] = (tcpSegment.size and 0xFF).toByte()
        System.arraycopy(tcpSegment, 0, pseudo, 12, tcpSegment.size)
        return ipChecksum(pseudo, 0, pseudo.size)
    }
    private fun cleanCache() {
        val now = System.currentTimeMillis()
        recentBlocks.entries.removeAll { now - it.value > CACHE_TTL_MS }
        recentAllows.entries.removeAll { now - it.value > CACHE_TTL_MS }
    }
    private fun recordBlockedDomain(hostname: String) {
        try { BlockedDomainsManager.recordBlocked(hostname) }
        catch (e: Exception) { Log.e(TAG, "recordBlockedDomain error: ${e.message}") }
    }

    private fun broadcastStatus(isRunning: Boolean) {
        sendBroadcast(Intent(ACTION_STATUS_CHANGED).apply {
            putExtra(EXTRA_IS_RUNNING, isRunning)
        })
    }
    private fun postBlockedNotification(hostname: String) {
        val intent = Intent(this, WarningActivity::class.java).apply {
            putExtra("blocked_hostname", hostname)
            putExtra("phishing_score", PhishingDetector.getThreshold())
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            hostname.hashCode(),
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = NotificationCompat.Builder(this, ALERT_CHANNEL_ID)
            .setContentTitle("⚠️ Phishing Site Blocked")
            .setContentText("Blocked: $hostname")
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText("PhishGuard blocked access to '$hostname' because it looks like a phishing site. Tap to review.")
            )
            .setSmallIcon(R.drawable.ic_shield_active)
            .setContentIntent(pendingIntent)
            .setFullScreenIntent(pendingIntent, true)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .build()

        getSystemService(NotificationManager::class.java)
            ?.notify(hostname.hashCode(), notification)
    }
    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java) ?: return

            val serviceChannel = NotificationChannel(
                NOTIF_CHANNEL_ID,
                "PhishGuard VPN",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "PhishGuard auto-protection status"
                setShowBadge(false)
            }

            val alertChannel = NotificationChannel(
                ALERT_CHANNEL_ID,
                ALERT_CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH,
            ).apply {
                description = "Alerts when a phishing site is blocked"
                enableVibration(true)
                setShowBadge(true)
            }

            nm.createNotificationChannel(serviceChannel)
            nm.createNotificationChannel(alertChannel)
        }
    }

    private fun buildForegroundNotification(message: String): Notification {
        val stopIntent = PendingIntent.getService(
            this, 0,
            Intent(this, PhishGuardVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val openIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, NOTIF_CHANNEL_ID)
            .setContentTitle("PhishGuard")
            .setContentText(message)
            .setSmallIcon(R.drawable.ic_shield_active)
            .setContentIntent(openIntent)
            .addAction(R.drawable.ic_stop, "Stop", stopIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
}