package com.example.phishguard

import android.Manifest
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import android.util.Patterns
import androidx.annotation.RequiresPermission
import com.example.phishguard.analysis.MlEngine
import java.net.URI

class EmailNotificationListener : NotificationListenerService() {

    @RequiresPermission(Manifest.permission.POST_NOTIFICATIONS)
    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val extras = sbn.notification.extras ?: return

        val title = extras.getCharSequence("android.title")?.toString() ?: ""
        val text = extras.getCharSequence("android.text")?.toString() ?: ""
        val bigText = extras.getCharSequence("android.bigText")?.toString() ?: ""

        val fullText = "$title $text $bigText"
        val matcher = Patterns.WEB_URL.matcher(fullText)

        while (matcher.find()) {
            val url = matcher.group() ?: continue

            if (UrlCache.isAlreadyScanned(url)) continue

            Log.d("PhishGuard", "Notification URL detected: $url")

            val hostname = extractHostname(url) ?: continue
            val score = MlEngine.score(hostname)

            if (score >= 0.7f) {
                AlertUtils.showPhishingAlert(
                    context = this,
                    url = url,
                    risk = score
                )
            }
        }
    }

    private fun extractHostname(url: String): String? {
        return try {
            val uri = if (url.startsWith("http")) URI(url) else URI("http://$url")
            uri.host
        } catch (e: Exception) {
            null
        }
    }
}