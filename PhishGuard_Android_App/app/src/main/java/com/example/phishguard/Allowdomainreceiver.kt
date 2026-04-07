package com.example.phishguard

import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.widget.Toast

class AllowDomainReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != "com.example.phishguard.ALLOW_DOMAIN") return

        val domain = intent.getStringExtra("domain") ?: return

        BlockedDomainsManager.allowTemporarily(domain)

        context.getSystemService(NotificationManager::class.java)
            ?.cancel(domain.hashCode())

        Handler(Looper.getMainLooper()).post {
            Toast.makeText(
                context.applicationContext,
                "✓ $domain allowed for 5 minutes. Reload the page.",
                Toast.LENGTH_LONG
            ).show()
        }

        context.sendBroadcast(
            Intent("com.example.phishguard.DOMAIN_ALLOWED").apply {
                putExtra("domain", domain)
                setPackage(context.packageName)
            }
        )
    }
}