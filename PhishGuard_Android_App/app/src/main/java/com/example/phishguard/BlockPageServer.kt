package com.example.phishguard

import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.ServerSocket
import java.net.Socket
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.concurrent.Executors
import java.util.regex.Pattern

object BlockPageServer {

    private const val TAG = "BlockPageServer"
    private const val PORT = 8080

    private var running = false
    private var serverSocket: ServerSocket? = null

    private val executor = Executors.newCachedThreadPool()

    fun start() {
        if (running) return

        try {
            serverSocket = ServerSocket(PORT)
            running = true

            Log.i(TAG, "Block page server started on port $PORT")

            executor.execute {

                while (running) {
                    try {
                        val socket = serverSocket?.accept() ?: break
                        executor.execute { handleClient(socket) }
                    } catch (e: Exception) {
                        if (running) {
                            Log.e(TAG, "Accept error: ${e.message}")
                        }
                    }
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Server start failed: ${e.message}")
        }
    }

    fun stop() {
        running = false
        try {
            serverSocket?.close()
        } catch (_: Exception) {}

        serverSocket = null
        executor.shutdownNow()

        Log.i(TAG, "Block page server stopped")
    }

    private fun handleClient(socket: Socket) {

        try {
            val reader = BufferedReader(InputStreamReader(socket.getInputStream()))
            val requestLine = reader.readLine() ?: return

            val domain = extractDomain(requestLine)

            if (domain == null) {
                socket.close()
                return
            }

            if (requestLine.contains("/proceed")) {

                val decoded = URLDecoder.decode(domain, "UTF-8")
                BlockedDomainsManager.allowTemporarily(decoded)

                val redirect = """
                    HTTP/1.1 302 Found
                    Location: http://$decoded/
                    Connection: close
                    
                """.trimIndent()

                socket.getOutputStream().write(redirect.toByteArray())

            } else {

                val html = buildBlockPage(domain)

                val response = """
                    HTTP/1.1 200 OK
                    Content-Type: text/html
                    Content-Length: ${html.toByteArray().size}
                    Connection: close
                    
                    $html
                """.trimIndent()

                socket.getOutputStream().write(response.toByteArray())
            }

        } catch (e: Exception) {
            Log.e(TAG, "Client error: ${e.message}")
        } finally {
            try {
                socket.close()
            } catch (_: Exception) {}
        }
    }

    private fun extractDomain(requestLine: String): String? {

        return try {

            val parts = requestLine.split(" ")

            if (parts.size < 2) return null

            val path = parts[1]

            val pattern = Pattern.compile("domain=([^&]+)")
            val matcher = pattern.matcher(path)

            if (matcher.find()) {
                matcher.group(1)
            } else {
                null
            }

        } catch (e: Exception) {
            null
        }
    }

    private fun buildBlockPage(domain: String): String {

        val encoded = URLEncoder.encode(domain, "UTF-8")

        return """
        <!DOCTYPE html>
        <html>
        <head>
        <meta charset="utf-8"/>
        <title>Phishing Risk Detected</title>
        <style>
        body{
            background:#111827;
            color:white;
            font-family:sans-serif;
            text-align:center;
            padding-top:15%;
        }
        .card{
            max-width:500px;
            margin:auto;
            background:#1f2937;
            padding:40px;
            border-radius:12px;
        }
        h1{
            color:#ef4444;
        }
        .btn{
            display:inline-block;
            padding:12px 24px;
            margin:10px;
            border-radius:6px;
            text-decoration:none;
            color:white;
        }
        .danger{background:#ef4444;}
        .safe{background:#10b981;}
        </style>
        </head>

        <body>

        <div class="card">

        <h1>⚠ Phishing Risk Detected</h1>

        <p>
        The website <b>$domain</b> appears to be a phishing attempt.
        Entering passwords or payment details could be dangerous.
        </p>

        <br>

        <a class="btn danger" href="/proceed?domain=$encoded">
        Continue Anyway
        </a>

        <a class="btn safe" href="https://google.com">
        Go to Safety
        </a>

        </div>

        </body>
        </html>
        """.trimIndent()
    }
}