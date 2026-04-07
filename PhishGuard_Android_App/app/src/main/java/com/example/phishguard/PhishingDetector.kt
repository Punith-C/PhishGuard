package com.example.phishguard

import android.content.Context
import android.util.Log
import com.example.phishguard.analysis.MlEngine
import com.example.phishguard.analysis.PhishingMlAnalyzer

object PhishingDetector {

    private const val TAG = "PhishingDetector"
    private var analyzer: PhishingMlAnalyzer? = null

    fun init(context: Context) {
        if (analyzer != null) return
        analyzer = PhishingMlAnalyzer(context.applicationContext)
        Log.i(TAG, "PhishingDetector ready")
    }

    fun isPhishing(hostname: String): Boolean {
        val a = analyzer ?: run {
            Log.w(TAG, "Not initialised — allowing $hostname")
            return false
        }
        return try {
            a.isPhishing(hostname)
        } catch (e: Exception) {
            Log.e(TAG, "Error checking $hostname: ${e.message}")
            false
        }
    }

    fun analyze(input: String): PhishingMlAnalyzer.AnalysisResult {
        val a = analyzer ?: throw IllegalStateException("PhishingDetector not initialised")
        return a.analyzeUrl(input)
    }

    fun analyzeHostname(hostname: String): PhishingMlAnalyzer.AnalysisResult {
        val a = analyzer ?: throw IllegalStateException("PhishingDetector not initialised")
        return a.analyzeHostname(hostname)
    }

    fun isTrusted(hostname: String): Boolean = MlEngine.isTrusted(hostname)

    fun getThreshold(): Float = MlEngine.getThreshold()

    fun isReady(): Boolean = MlEngine.isReady()
}