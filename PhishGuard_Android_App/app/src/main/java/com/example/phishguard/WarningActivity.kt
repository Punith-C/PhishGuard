package com.example.phishguard

import android.os.Build
import android.os.Bundle
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton

class WarningActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        } else {
            @Suppress("DEPRECATION")
            window.addFlags(
                android.view.WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                        android.view.WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON
            )
        }

        setContentView(R.layout.activity_warning)

        val domain = intent.getStringExtra("domain") ?: "Unknown domain"

        findViewById<TextView>(R.id.tvWarningDomain).text = domain

        findViewById<MaterialButton>(R.id.btnGoBack).setOnClickListener {
            finish()
        }

        findViewById<MaterialButton>(R.id.btnAllow5Min).setOnClickListener {
            BlockedDomainsManager.allowTemporarily(domain)
            Toast.makeText(
                this,
                "$domain allowed for 5 minutes. Reload the page.",
                Toast.LENGTH_LONG
            ).show()
            finish()
        }

        findViewById<MaterialButton>(R.id.btnAllowAlways).setOnClickListener {
            BlockedDomainsManager.allowPermanently(this, domain)
            Toast.makeText(
                this,
                "$domain permanently whitelisted.",
                Toast.LENGTH_LONG
            ).show()
            finish()
        }
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        setIntent(intent)

        val domain = intent.getStringExtra("domain") ?: return
        findViewById<TextView>(R.id.tvWarningDomain)?.text = domain
    }
}