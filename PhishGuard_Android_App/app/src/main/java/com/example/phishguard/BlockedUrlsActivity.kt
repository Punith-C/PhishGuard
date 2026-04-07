package com.example.phishguard

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.button.MaterialButton
import com.google.android.material.tabs.TabLayout

class BlockedUrlsActivity : AppCompatActivity() {

    private lateinit var tabLayout   : TabLayout
    private lateinit var recyclerView: RecyclerView
    private lateinit var tvEmpty     : TextView
    private lateinit var btnStopVpn  : MaterialButton
    private lateinit var adapter     : BlockedUrlsAdapter

    private val handler  = Handler(Looper.getMainLooper())
    private val refresher = object : Runnable {
        override fun run() {
            refreshList()
            handler.postDelayed(this, 4000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_blocked_urls)

        tabLayout    = findViewById(R.id.tabLayout)
        recyclerView = findViewById(R.id.recyclerView)
        tvEmpty      = findViewById(R.id.tvEmpty)
        btnStopVpn   = findViewById(R.id.btnStopVpn)

        recyclerView.layoutManager = LinearLayoutManager(this)

        adapter = BlockedUrlsAdapter(
            onAllowTemp = { domain ->
                BlockedDomainsManager.allowTemporarily(domain)
                Toast.makeText(this, "$domain allowed for 5 minutes", Toast.LENGTH_SHORT).show()
                refreshList()
            },
            onAllowPermanent = { domain ->
                BlockedDomainsManager.allowPermanently(this, domain)
                Toast.makeText(this, "$domain permanently whitelisted", Toast.LENGTH_SHORT).show()
                refreshList()
            },
            onRevoke = { domain ->
                BlockedDomainsManager.revokePermanent(domain)
                Toast.makeText(this, "$domain removed from whitelist", Toast.LENGTH_SHORT).show()
                refreshList()
            }
        )
        recyclerView.adapter = adapter

        tabLayout.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab) { refreshList() }
            override fun onTabUnselected(tab: TabLayout.Tab) {}
            override fun onTabReselected(tab: TabLayout.Tab) { refreshList() }
        })

        btnStopVpn.setOnClickListener {
            stopService(Intent(this, PhishGuardVpnService::class.java))
            BlockedDomainsManager.clearSession()
            getSharedPreferences("phishguard_prefs", MODE_PRIVATE)
                .edit().putBoolean("vpn_enabled", false).apply()
            Toast.makeText(this, "VPN Protection Stopped", Toast.LENGTH_SHORT).show()
            finish()
        }
    }

    override fun onResume() {
        super.onResume()
        handler.post(refresher)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(refresher)
    }

    private fun refreshList() {
        when (tabLayout.selectedTabPosition) {
            0 -> {
                val items = BlockedDomainsManager.blockedSession.keys.sorted()
                    .map { BlockedUrlItem(it, BlockedUrlItem.TYPE_BLOCKED, "") }
                updateList(items, "No domains blocked this session")
            }
            1 -> {
                val items = BlockedDomainsManager.getPermanentWhitelist().sorted()
                    .map { BlockedUrlItem(it, BlockedUrlItem.TYPE_PERMANENT, "") }
                updateList(items, "No permanently whitelisted domains")
            }
        }
    }

    private fun updateList(items: List<BlockedUrlItem>, emptyText: String) {
        if (items.isEmpty()) {
            recyclerView.visibility = View.GONE
            tvEmpty.visibility      = View.VISIBLE
            tvEmpty.text            = emptyText
        } else {
            recyclerView.visibility = View.VISIBLE
            tvEmpty.visibility      = View.GONE
            adapter.submitList(items)
        }
    }
}