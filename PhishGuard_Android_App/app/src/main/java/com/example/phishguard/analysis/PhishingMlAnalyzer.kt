package com.example.phishguard.analysis

import android.content.Context
import android.util.Log

class PhishingMlAnalyzer(private val context: Context) {

    companion object {
        private const val TAG = "PhishingMlAnalyzer"
    }

    init {
        MlEngine.init(context)
    }

    data class AnalysisResult(
        val hostname: String,
        val score: Float,
        val isPhishing: Boolean,
        val isTrusted: Boolean,
        val verdict: Verdict,
        val reason: String,
        val analysisTimeMs: Long,
    ) {
        enum class Verdict {
            SAFE,
            SUSPICIOUS,
            PHISHING,
        }

        val riskLevel: String
            get() = when (verdict) {
                Verdict.SAFE -> "Safe"
                Verdict.SUSPICIOUS -> "Suspicious"
                Verdict.PHISHING -> "Phishing"
            }

        val shouldBlock: Boolean
            get() = isPhishing
    }

    fun analyzeHostname(rawHostname: String): AnalysisResult {
        val start = System.currentTimeMillis()
        val h = rawHostname.trim().lowercase().removePrefix("www.")

        if (h.length < 3) {
            return AnalysisResult(
                hostname = h,
                score = 0f,
                isPhishing = false,
                isTrusted = false,
                verdict = AnalysisResult.Verdict.SAFE,
                reason = "Too short to analyse",
                analysisTimeMs = 0L,
            )
        }

        if (!MlEngine.isReady()) {
            Log.w(TAG, "MlEngine not ready — allowing $h")
            return AnalysisResult(
                hostname = h,
                score = 0f,
                isPhishing = false,
                isTrusted = false,
                verdict = AnalysisResult.Verdict.SAFE,
                reason = "Model not loaded",
                analysisTimeMs = System.currentTimeMillis() - start,
            )
        }

        if (MlEngine.isTrusted(h)) {
            return AnalysisResult(
                hostname = h,
                score = 0f,
                isPhishing = false,
                isTrusted = true,
                verdict = AnalysisResult.Verdict.SAFE,
                reason = "Trusted domain whitelist",
                analysisTimeMs = System.currentTimeMillis() - start,
            )
        }

        val score = MlEngine.score(h)
        val threshold = MlEngine.getThreshold()
        val isPhish = score >= threshold
        val isSus = score >= 0.4f && !isPhish

        val (verdict, reason) = when {
            isPhish -> Pair(
                AnalysisResult.Verdict.PHISHING,
                buildReason(h, score)
            )
            isSus -> Pair(
                AnalysisResult.Verdict.SUSPICIOUS,
                "Suspicious pattern detected (score: ${"%.2f".format(score)})"
            )
            else -> Pair(
                AnalysisResult.Verdict.SAFE,
                "Low risk score (${"%.2f".format(score)})"
            )
        }

        Log.d(TAG, "${if (isPhish) "BLOCK" else "ALLOW"} $h  score=${"%.3f".format(score)}")

        return AnalysisResult(
            hostname = h,
            score = score,
            isPhishing = isPhish,
            isTrusted = false,
            verdict = verdict,
            reason = reason,
            analysisTimeMs = System.currentTimeMillis() - start,
        )
    }

    fun analyzeUrl(rawUrl: String): AnalysisResult {
        val hostname = extractHostname(rawUrl)
        return analyzeHostname(hostname)
    }

    fun isPhishing(hostname: String): Boolean =
        MlEngine.isPhishing(hostname)

    private fun extractHostname(url: String): String {
        return try {
            val withScheme = if ("://" in url) url else "http://$url"
            val host = java.net.URL(withScheme).host ?: url
            host.lowercase().removePrefix("www.")
        } catch (e: Exception) {
            url.split("/").firstOrNull()?.lowercase()?.removePrefix("www.") ?: url
        }
    }

    private fun buildReason(hostname: String, score: Float): String {
        val parts = ArrayList<String>()
        val h = hostname.lowercase()

        val tld = h.substringAfterLast(".")
        if (tld in setOf("xyz", "tk", "ml", "cf", "gq", "pw", "top", "click", "site", "online", "live", "icu", "vip", "cc")) {
            parts.add("suspicious TLD (.$tld)")
        }

        val phishWords = listOf(
            "login", "secure", "verify", "account", "update", "signin",
            "banking", "wallet", "credential", "billing", "alert", "prize", "winner"
        )
        val foundWords = phishWords.filter { it in h }
        if (foundWords.isNotEmpty()) {
            parts.add("phishing keywords: ${foundWords.joinToString(", ")}")
        }

        val brands = listOf(
            "paypal", "google", "facebook", "microsoft", "apple", "amazon",
            "netflix", "hdfc", "sbi", "icici", "paytm", "razorpay"
        )
        val foundBrands = brands.filter { it in h }
        if (foundBrands.isNotEmpty()) {
            parts.add("brand impersonation: ${foundBrands.joinToString(", ")}")
        }

        if (h.count { it == '-' } >= 2) parts.add("multiple hyphens")
        if (h.length > 40) parts.add("unusually long hostname")

        val baseReason =
            if (parts.isEmpty()) "ML model detected phishing pattern"
            else parts.joinToString("; ")

        return "$baseReason (score: ${"%.2f".format(score)})"
    }
}