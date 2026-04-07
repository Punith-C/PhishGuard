package com.example.phishguard

import android.annotation.SuppressLint
import android.content.*
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.firebase.auth.FirebaseAuth

class ProtectionDashboardActivity : AppCompatActivity() {

    private lateinit var tvShieldStatus   : TextView
    private lateinit var tvStatusSub      : TextView
    private lateinit var tvBlockedCount   : TextView
    private lateinit var layoutEmptyState : LinearLayout
    private lateinit var rvBlockedDomains : RecyclerView
    private lateinit var btnStopProtection: MaterialButton
    private lateinit var btnClearAll      : MaterialButton
    private lateinit var cardStatus       : MaterialCardView
    private lateinit var dotStatus        : View
    private lateinit var adapter          : BlockedDomainAdapter

    private val refreshHandler = Handler(Looper.getMainLooper())

    private val autoRefreshRunnable = object : Runnable {
        override fun run() {
            refreshList()
            refreshHandler.postDelayed(this, 3000)
        }
    }

    private val domainAllowedReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            refreshList()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_protection_dashboard)

        setupToolbar()

        tvShieldStatus    = findViewById(R.id.tvShieldStatus)
        tvStatusSub       = findViewById(R.id.tvStatusSub)
        tvBlockedCount    = findViewById(R.id.tvBlockedCount)
        layoutEmptyState  = findViewById(R.id.layoutEmptyState)
        rvBlockedDomains  = findViewById(R.id.rvBlockedDomains)
        btnStopProtection = findViewById(R.id.btnStopProtection)
        btnClearAll       = findViewById(R.id.btnClearAll)
        cardStatus        = findViewById(R.id.cardStatus)
        dotStatus         = findViewById(R.id.dotStatus)

        setupRecyclerView()
        setupButtons()
        setupBackPress()
        refreshList()
    }

    private fun setupToolbar() {
        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        toolbar.setOnMenuItemClickListener {
            if (it.itemId == R.id.action_logout) {
                if (VpnStatusChecker.isVpnRunning(this)) {
                    Toast.makeText(this, "Stop protection before logging out.", Toast.LENGTH_LONG).show()
                    return@setOnMenuItemClickListener true
                }
                FirebaseAuth.getInstance().signOut()
                startActivity(Intent(this, LoginActivity::class.java))
                finish()
                return@setOnMenuItemClickListener true
            }
            false
        }
    }

    @SuppressLint("UnspecifiedRegisterReceiverFlag")
    override fun onResume() {
        super.onResume()
        val filter = IntentFilter(PhishGuardVpnService.ACTION_DOMAIN_ALLOWED)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(domainAllowedReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(domainAllowedReceiver, filter)
        }
        refreshHandler.post(autoRefreshRunnable)
        refreshList()
    }

    override fun onPause() {
        super.onPause()
        try { unregisterReceiver(domainAllowedReceiver) } catch (_: Exception) {}
        refreshHandler.removeCallbacks(autoRefreshRunnable)
    }

    private fun setupBackPress() {
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (VpnStatusChecker.isVpnRunning(this@ProtectionDashboardActivity)) {
                    Toast.makeText(
                        this@ProtectionDashboardActivity,
                        "Stop protection before leaving.",
                        Toast.LENGTH_SHORT
                    ).show()
                } else {
                    isEnabled = false
                    onBackPressedDispatcher.onBackPressed()
                }
            }
        })
    }

    private fun setupRecyclerView() {
        adapter = BlockedDomainAdapter(
            onAllowClicked = { entry ->
                BlockedDomainsManager.allowTemporarily(entry.domain)
                refreshList()
            },
            onBlockClicked = { entry ->
                BlockedDomainsManager.revokePermanent(entry.domain)
                refreshList()
            }
        )
        rvBlockedDomains.layoutManager = LinearLayoutManager(this)
        rvBlockedDomains.adapter = adapter
    }

    private fun setupButtons() {
        btnStopProtection.setOnClickListener {
            startService(
                Intent(this, PhishGuardVpnService::class.java).apply {
                    action = PhishGuardVpnService.ACTION_STOP
                }
            )
            Toast.makeText(this, "Protection stopped", Toast.LENGTH_SHORT).show()
            refreshList()
        }

        btnClearAll.setOnClickListener {
            BlockedDomainsManager.clearSession()
            refreshList()
            Toast.makeText(this, "Blocked history cleared", Toast.LENGTH_SHORT).show()
        }
    }

    private fun refreshList() {
        val domains = BlockedDomainsManager.blockedSession.map {
            BlockedDomainEntry(
                domain         = it.key,
                firstBlockedAt = it.value,
                lastBlockedAt  = it.value,
                count          = 1,
                allowed        = BlockedDomainsManager.isAllowed(it.key)
            )
        }

        adapter.submitList(domains)
        tvBlockedCount.text = domains.size.toString()

        layoutEmptyState.visibility  = if (domains.isEmpty()) View.VISIBLE else View.GONE
        rvBlockedDomains.visibility  = if (domains.isEmpty()) View.GONE   else View.VISIBLE

        updateStatusHeader()
    }

    private fun updateStatusHeader() {
        val isProtected = VpnStatusChecker.isVpnRunning(this)

        if (isProtected) {

            cardStatus.setCardBackgroundColor(
                ContextCompat.getColor(this, R.color.verdict_safe)   // solid green
            )
            tvShieldStatus.text      = "🛡 Protected"
            tvShieldStatus.setTextColor(0xFFFFFFFF.toInt())
            tvStatusSub.text         = "PhishGuard monitoring DNS"
            tvStatusSub.setTextColor(0xDDFFFFFF.toInt())
            dotStatus.setBackgroundResource(R.drawable.bg_dot_active)   // green dot

        } else {

            cardStatus.setCardBackgroundColor(
                ContextCompat.getColor(this, R.color.verdict_phishing) // solid red
            )
            tvShieldStatus.text      = "⚠ Inactive"
            tvShieldStatus.setTextColor(0xFFFFFFFF.toInt())
            tvStatusSub.text         = "Protection is off — tap Start to enable"
            tvStatusSub.setTextColor(0xDDFFFFFF.toInt())
            dotStatus.setBackgroundResource(R.drawable.bg_dot_inactive) // red dot
        }
    }
}