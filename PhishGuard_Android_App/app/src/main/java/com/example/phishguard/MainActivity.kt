package com.example.phishguard

import android.content.Intent
import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.firebase.auth.FirebaseAuth

class MainActivity : AppCompatActivity() {

    private lateinit var btnAuto: MaterialButton
    private lateinit var btnManual: MaterialButton

    private lateinit var cardAuto: MaterialCardView
    private lateinit var cardManual: MaterialCardView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContentView(R.layout.activity_main)

        btnAuto = findViewById(R.id.btnAuto)
        btnManual = findViewById(R.id.btnManual)

        cardAuto = findViewById(R.id.cardAuto)
        cardManual = findViewById(R.id.cardManual)

        // Auto protection click
        btnAuto.setOnClickListener { handleAutoClick() }
        cardAuto.setOnClickListener { handleAutoClick() }

        // Manual scan click
        btnManual.setOnClickListener { openManualScan() }
        cardManual.setOnClickListener { openManualScan() }

        setupHeader()
    }

    private fun handleAutoClick() {

        if (VpnStatusChecker.isVpnRunning(this)) {

            startActivity(Intent(this, ProtectionDashboardActivity::class.java))

        } else {

            startActivity(Intent(this, AutoProtectionActivity::class.java))
        }
    }

    private fun openManualScan() {
        startActivity(Intent(this, ManualScanActivity::class.java))
    }

    private fun setupHeader() {

        val emailText = findViewById<TextView>(R.id.headerUserEmail)
        val logoutBtn = findViewById<MaterialButton>(R.id.headerLogout)

        val user = FirebaseAuth.getInstance().currentUser
        emailText.text = user?.email ?: "Guest"

        logoutBtn.setOnClickListener {

            FirebaseAuth.getInstance().signOut()

            startActivity(Intent(this, LoginActivity::class.java))
            finish()
        }
    }

    override fun onResume() {
        super.onResume()
        updateAutoProtectionUI()
    }

    private fun updateAutoProtectionUI() {

        if (VpnStatusChecker.isVpnRunning(this)) {

            btnAuto.text = "Open Dashboard"

        } else {

            btnAuto.text = "Enable Auto Protection"
        }
    }
}