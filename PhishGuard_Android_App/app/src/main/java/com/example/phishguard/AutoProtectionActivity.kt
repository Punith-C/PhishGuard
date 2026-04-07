package com.example.phishguard

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.button.MaterialButton
import com.google.android.material.progressindicator.CircularProgressIndicator
import com.google.firebase.auth.FirebaseAuth

class AutoProtectionActivity : AppCompatActivity() {

    private lateinit var btnEnable: MaterialButton
    private lateinit var tvStatusText: TextView
    private lateinit var tvStatusDetail: TextView
    private lateinit var ivStatusIcon: ImageView
    private lateinit var progressIndicator: CircularProgressIndicator

    companion object {
        private const val VPN_REQUEST_CODE = 100
    }

    private val notificationPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) {
            requestVpnPermission()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContentView(R.layout.activity_auto_protection)

        setupHeader()

        initViews()
        setupClickListeners()
        updateUiState()
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

    private fun initViews() {
        btnEnable = findViewById(R.id.btnEnableProtection)
        tvStatusText = findViewById(R.id.tvStatusText)
        tvStatusDetail = findViewById(R.id.tvStatusDetail)
        ivStatusIcon = findViewById(R.id.ivStatusIcon)
        progressIndicator = findViewById(R.id.progressIndicator)
    }

    private fun setupClickListeners() {
        btnEnable.setOnClickListener {
            checkNotificationPermission()
        }
    }

    override fun onResume() {
        super.onResume()
        updateUiState()
    }

    private fun updateUiState() {
        if (VpnStatusChecker.isVpnRunning(this)) {

            ivStatusIcon.setImageResource(R.drawable.ic_shield_check)
            tvStatusText.text = "Protection Active"
            tvStatusDetail.text = "Real-time phishing monitoring enabled"
            btnEnable.text = "Protection Enabled"
            btnEnable.isEnabled = false

        } else {

            ivStatusIcon.setImageResource(R.drawable.ic_shield_check)
            tvStatusText.text = "Protection Disabled"
            tvStatusDetail.text = "Enable to monitor network traffic"
            btnEnable.text = "Enable Auto Protection"
            btnEnable.isEnabled = true
        }
    }

    private fun checkNotificationPermission() {

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {

            if (ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.POST_NOTIFICATIONS
                ) == PackageManager.PERMISSION_GRANTED
            ) {

                requestVpnPermission()

            } else {

                notificationPermissionLauncher.launch(
                    Manifest.permission.POST_NOTIFICATIONS
                )
            }

        } else {
            requestVpnPermission()
        }
    }

    private fun requestVpnPermission() {

        val intent = VpnService.prepare(this)

        if (intent != null) {
            startActivityForResult(intent, VPN_REQUEST_CODE)
        } else {
            startVpnService()
        }
    }

    override fun onActivityResult(
        requestCode: Int,
        resultCode: Int,
        data: Intent?
    ) {

        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            startVpnService()
        }
    }

    private fun startVpnService() {

        showLoadingState()

        val intent = Intent(this, PhishGuardVpnService::class.java).apply {
            action = PhishGuardVpnService.ACTION_START
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }

        window.decorView.postDelayed({

            hideLoadingState()

            startActivity(
                Intent(this, ProtectionDashboardActivity::class.java)
            )

            finish()

        }, 800)
    }

    private fun showLoadingState() {
        progressIndicator.visibility = android.view.View.VISIBLE
        btnEnable.isEnabled = false
        btnEnable.text = "Starting..."
    }

    private fun hideLoadingState() {
        progressIndicator.visibility = android.view.View.GONE
    }
}