package com.example.phishguard

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.example.phishguard.analysis.PhishingMlAnalyzer
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.progressindicator.LinearProgressIndicator
import com.google.firebase.auth.FirebaseAuth

class ManualScanActivity : AppCompatActivity() {

    private var analyzer: PhishingMlAnalyzer? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_manual_scan)

        setupHeader()

        val etUrl         = findViewById<EditText>(R.id.etUrl)
        val btnScan       = findViewById<MaterialButton>(R.id.btnScan)
        val progress      = findViewById<LinearProgressIndicator>(R.id.progressIndicator)

        val cardResultIcon  = findViewById<MaterialCardView>(R.id.cardResultIcon)
        val imgResult       = findViewById<ImageView>(R.id.imgResult)
        val tvResultTitle   = findViewById<TextView>(R.id.tvResultTitle)
        val tvResultSubtitle = findViewById<TextView>(R.id.tvResultSubtitle)
        val layoutDetails   = findViewById<LinearLayout>(R.id.layoutDetails)

        val tvDomain   = findViewById<TextView>(R.id.tvDomain)
        val tvScore    = findViewById<TextView>(R.id.tvScore)
        val progressScore = findViewById<LinearProgressIndicator>(R.id.progressScore)
        val tvTime     = findViewById<TextView>(R.id.tvTime)
        val tvReason   = findViewById<TextView>(R.id.tvReason)

        btnScan.setOnClickListener {
            val input = etUrl.text.toString().trim()

            if (input.isEmpty()) {
                tvResultTitle.text = "No URL Entered"
                tvResultSubtitle.text = "Please type or paste a URL in the field above before scanning."
                layoutDetails.visibility = View.GONE
                return@setOnClickListener
            }

            try {
                progress.visibility = View.VISIBLE
                btnScan.isEnabled = false
                layoutDetails.visibility = View.GONE
                tvResultTitle.text = "Scanning…"
                tvResultSubtitle.text = "Analyzing the URL for phishing signals…"

                if (analyzer == null) {
                    analyzer = PhishingMlAnalyzer(this)
                }

                val result = analyzer!!.analyzeUrl(input)

                progress.visibility = View.GONE
                btnScan.isEnabled = true
                val (iconRes, iconBgColor, accentColor, titleText, subtitleText) =
                    when (result.verdict) {

                        PhishingMlAnalyzer.AnalysisResult.Verdict.SAFE -> VerdictStyle(
                            iconRes     = R.drawable.ic_check_circle,
                            iconBgColor = R.color.verdict_safe_bg,
                            accentColor = R.color.verdict_safe,
                            title       = "✓  Safe",
                            subtitle    = "This website passed all phishing checks and appears safe to visit."
                        )

                        PhishingMlAnalyzer.AnalysisResult.Verdict.SUSPICIOUS -> VerdictStyle(
                            iconRes     = R.drawable.ic_warning,
                            iconBgColor = R.color.verdict_suspicious_bg,
                            accentColor = R.color.verdict_suspicious,
                            title       = "⚠  Suspicious",
                            subtitle    = "This website has some warning signs. Proceed with caution."
                        )

                        PhishingMlAnalyzer.AnalysisResult.Verdict.PHISHING -> VerdictStyle(
                            iconRes     = R.drawable.ic_dangerous,
                            iconBgColor = R.color.verdict_phishing_bg,
                            accentColor = R.color.verdict_phishing,
                            title       = "✕  Phishing Detected",
                            subtitle    = "This website is likely a phishing site. Do NOT enter any personal information."
                        )
                    }

                imgResult.setImageResource(iconRes)
                cardResultIcon.setCardBackgroundColor(ContextCompat.getColor(this, iconBgColor))
                tvResultTitle.setTextColor(ContextCompat.getColor(this, accentColor))
                tvResultTitle.text = titleText
                tvResultSubtitle.text = subtitleText

                tvDomain.text = result.hostname.ifBlank { "Unknown" }

                val scorePercent = (result.score * 100).toInt().coerceIn(0, 100)
                tvScore.text = "$scorePercent / 100"
                progressScore.progress = scorePercent
                progressScore.setIndicatorColor(ContextCompat.getColor(this, accentColor))

                tvTime.text = "${result.analysisTimeMs} ms"

                tvReason.text = result.reason
                    .split("\n")
                    .filter { it.isNotBlank() }
                    .joinToString("\n") { "• ${it.trim()}" }
                    .ifBlank { "No additional details available." }

                layoutDetails.visibility = View.VISIBLE

            } catch (e: Exception) {
                progress.visibility = View.GONE
                btnScan.isEnabled = true
                tvResultTitle.text = "Scan Failed"
                tvResultSubtitle.text = "An error occurred while analyzing the URL. Please try again."
                layoutDetails.visibility = View.GONE

                Toast.makeText(this, "Error: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }
    private data class VerdictStyle(
        val iconRes: Int,
        val iconBgColor: Int,
        val accentColor: Int,
        val title: String,
        val subtitle: String
    )

    private fun setupHeader() {
        val emailText = findViewById<TextView>(R.id.headerUserEmail)
        val logoutBtn = findViewById<MaterialButton>(R.id.headerLogout)

        emailText.text = FirebaseAuth.getInstance().currentUser?.email ?: "Guest"

        logoutBtn.setOnClickListener {
            FirebaseAuth.getInstance().signOut()
            startActivity(Intent(this, LoginActivity::class.java))
            finish()
        }
    }
}