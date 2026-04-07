package com.example.phishguard.analysis

import android.content.Context
import android.util.Log
import org.tensorflow.lite.Interpreter
import java.io.BufferedReader
import java.io.FileInputStream
import java.io.InputStreamReader
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel
import java.util.Locale

object MlEngine {

    private const val TAG = "MlEngine"

    private const val MODEL_FILE = "phishing_model.tflite"
    private const val CENTER_FILE = "scaler_center.txt"
    private const val SCALE_FILE = "scaler_scale.txt"
    private const val CENTER_NPY = "scaler_center.npy"
    private const val SCALE_NPY = "scaler_scale.npy"
    private const val THRESHOLD_FILE = "threshold.txt"
    private const val ROOTS_FILE = "trusted_roots.txt"
    private const val COUNT_FILE = "feature_count.txt"

    private var interpreter: Interpreter? = null
    private var scalerMean = FloatArray(FeatureExtractor.N_FEATURES)
    private var scalerScale = FloatArray(FeatureExtractor.N_FEATURES) { 1f }
    private var threshold = 0.5f
    private val trustedRoots = HashSet<String>(512)
    private val trustedSorted = ArrayList<String>(512)
    @Volatile private var ready = false

    fun init(context: Context) {
        if (ready) return
        try {
            val n = loadFeatureCount(context)
            Log.i(TAG, "Feature count from assets: $n")

            interpreter = Interpreter(loadModelFile(context))
            loadTrustedRoots(context)
            threshold = loadThreshold(context)

            val center = loadScalerTxt(context, CENTER_FILE)
            val scale = loadScalerTxt(context, SCALE_FILE)

            if (center != null && scale != null &&
                center.size == FeatureExtractor.N_FEATURES &&
                scale.size == FeatureExtractor.N_FEATURES) {
                scalerMean = center
                scalerScale = scale
                Log.i(TAG, "Scaler loaded from .txt files")
            } else {
                val centerNpy = loadNpy(context, CENTER_NPY)
                val scaleNpy = loadNpy(context, SCALE_NPY)
                if (centerNpy != null) scalerMean = centerNpy
                if (scaleNpy != null) scalerScale = scaleNpy
                Log.i(TAG, "Scaler loaded from .npy files")
            }

            for (i in scalerScale.indices) {
                if (scalerScale[i] == 0f || scalerScale[i].isNaN()) {
                    scalerScale[i] = 1f
                }
            }

            ready = true
            Log.i(TAG, "MlEngine ready — features=${FeatureExtractor.N_FEATURES} threshold=$threshold trusted=${trustedRoots.size}")
        } catch (e: Exception) {
            Log.e(TAG, "MlEngine init failed: ${e.message}", e)
        }
    }

    fun isReady() = ready

    fun score(rawHostname: String): Float {
        if (!ready) return 0f

        val h = rawHostname.trim().lowercase(Locale.ROOT).removePrefix("www.")
        if (h.length < 3) return 0f

        if (isTrusted(h)) {
            Log.d(TAG, "ALLOW (whitelist): $h")
            return 0f
        }

        return try {
            val raw = FeatureExtractor.extract(h)

            val scaled = FloatArray(raw.size) { i ->
                val m = if (i < scalerMean.size) scalerMean[i] else 0f
                val s = if (i < scalerScale.size) scalerScale[i] else 1f
                (raw[i] - m) / s
            }

            val inputBuf = ByteBuffer
                .allocateDirect(raw.size * 4)
                .order(ByteOrder.nativeOrder())

            scaled.forEach { inputBuf.putFloat(it) }
            inputBuf.rewind()

            val output = Array(1) { FloatArray(1) }
            interpreter!!.run(inputBuf, output)
            output[0][0].coerceIn(0f, 1f)

        } catch (e: Exception) {
            Log.e(TAG, "Inference error for '$h': ${e.message}")
            0f
        }
    }

    fun isPhishing(hostname: String): Boolean = score(hostname) >= threshold

    fun getThreshold(): Float = threshold

    fun isTrusted(hostname: String): Boolean {
        val h = hostname.lowercase(Locale.ROOT).removePrefix("www.")
        if (h in trustedRoots) return true
        for (root in trustedSorted) {
            if (h == root || h.endsWith(".$root")) return true
        }
        return false
    }

    fun isTrustedRoot(domain: String): Boolean =
        domain.lowercase(Locale.ROOT) in trustedRoots

    private fun loadModelFile(context: Context): MappedByteBuffer {
        val afd = context.assets.openFd(MODEL_FILE)
        return FileInputStream(afd.fileDescriptor).channel
            .map(FileChannel.MapMode.READ_ONLY, afd.startOffset, afd.declaredLength)
    }

    private fun loadScalerTxt(context: Context, filename: String): FloatArray? {
        return try {
            val values = ArrayList<Float>()
            BufferedReader(InputStreamReader(context.assets.open(filename))).use { r ->
                r.lineSequence()
                    .map { it.trim() }
                    .filter { it.isNotBlank() && !it.startsWith("#") }
                    .forEach { line ->
                        val tokens = line.split(Regex("\\s+"))
                        val v = tokens.lastOrNull()?.toFloatOrNull()
                        if (v != null) values.add(v)
                    }
            }
            if (values.isEmpty()) null else values.toFloatArray()
        } catch (e: Exception) {
            Log.w(TAG, "$filename not found, trying .npy")
            null
        }
    }

    private fun loadNpy(context: Context, filename: String): FloatArray? {
        return try {
            val bytes = context.assets.open(filename).readBytes()
            val headerLen = (bytes[8].toInt() and 0xFF) or ((bytes[9].toInt() and 0xFF) shl 8)
            val dataStart = 10 + headerLen
            val header = String(bytes, 10, headerLen, Charsets.US_ASCII)
            val isF64 = "float64" in header || "<f8" in header || "f8" in header

            val buf = ByteBuffer.wrap(bytes, dataStart, bytes.size - dataStart)
                .order(ByteOrder.LITTLE_ENDIAN)

            val size = if (isF64) (bytes.size - dataStart) / 8
            else (bytes.size - dataStart) / 4

            FloatArray(size) { if (isF64) buf.double.toFloat() else buf.float }

        } catch (e: Exception) {
            Log.w(TAG, "Cannot load $filename: ${e.message}")
            null
        }
    }

    private fun loadThreshold(context: Context): Float {
        return try {
            context.assets.open(THRESHOLD_FILE).bufferedReader()
                .lineSequence()
                .firstOrNull { it.isNotBlank() && !it.startsWith("#") }
                ?.trim()?.toFloatOrNull() ?: 0.5f
        } catch (e: Exception) {
            Log.w(TAG, "threshold.txt not found, using 0.5")
            0.5f
        }
    }

    private fun loadFeatureCount(context: Context): Int {
        return try {
            context.assets.open(COUNT_FILE).bufferedReader()
                .readLine()?.trim()?.toIntOrNull() ?: FeatureExtractor.N_FEATURES
        } catch (e: Exception) {
            FeatureExtractor.N_FEATURES
        }
    }

    private fun loadTrustedRoots(context: Context) {
        try {
            BufferedReader(InputStreamReader(context.assets.open(ROOTS_FILE))).use { r ->
                r.lineSequence()
                    .map { it.trim().lowercase(Locale.ROOT) }
                    .filter { it.isNotBlank() && !it.startsWith("#") }
                    .forEach { trustedRoots.add(it) }
            }
            trustedSorted.addAll(trustedRoots.sortedByDescending { it.length })
            Log.i(TAG, "Loaded ${trustedRoots.size} trusted roots")
        } catch (e: Exception) {
            Log.w(TAG, "trusted_roots.txt not found — using fallback whitelist")
            loadFallbackRoots()
        }
    }

    private fun loadFallbackRoots() {
        val fallback = listOf(
            "google.com","youtube.com","googleapis.com","gstatic.com",
            "gmail.com","googleusercontent.com",
            "microsoft.com","outlook.com","office.com","microsoftonline.com",
            "azure.com","onedrive.com","windows.com",
            "apple.com","icloud.com",
            "amazon.com","amazon.in","amazonaws.com","cloudfront.net",
            "facebook.com","instagram.com","whatsapp.com","fbcdn.net",
            "twitter.com","x.com","t.co",
            "linkedin.com","licdn.com",
            "github.com","gitlab.com","stackoverflow.com",
            "paypal.com","stripe.com","razorpay.com","paytm.com",
            "sbi.co.in","hdfcbank.com","icicibank.com","axisbank.com",
            "gov.in","nic.in","irctc.co.in",
            "netflix.com","spotify.com","youtube.com",
            "cloudflare.com","akamai.com","fastly.com",
        )
        trustedRoots.addAll(fallback)
        trustedSorted.addAll(fallback.sortedByDescending { it.length })
    }

    fun getDiagnostics(hostname: String): String {
        val h = hostname.trim().lowercase(Locale.ROOT).removePrefix("www.")
        val sc = score(hostname)
        val feats = FeatureExtractor.extract(h)

        return buildString {
            appendLine("=== MlEngine Diagnostics ===")
            appendLine("Hostname   : $h")
            appendLine("Score      : ${"%.4f".format(sc)}")
            appendLine("Threshold  : $threshold")
            appendLine("Phishing   : ${sc >= threshold}")
            appendLine("Trusted    : ${isTrusted(h)}")
            appendLine("RegDomain  : ${FeatureExtractor.getRegistrableDomain(h)}")
            appendLine("--- Top features ---")
            appendLine("  host_len       = ${feats[0].toInt()}")
            appendLine("  sub_count      = ${feats[4].toInt()}")
            appendLine("  sus_tld        = ${feats[25].toInt()}")
            appendLine("  keyword_count  = ${feats[44].toInt()}")
            appendLine("  brand_count    = ${feats[45].toInt()}")
            appendLine("  trusted_host   = ${feats[70].toInt()}")
            appendLine("  trusted_reg    = ${feats[71].toInt()}")
        }
    }
}