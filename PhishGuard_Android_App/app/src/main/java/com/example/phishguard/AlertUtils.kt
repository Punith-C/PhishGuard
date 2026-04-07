package com.example.phishguard

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.annotation.RequiresPermission
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

object AlertUtils {

    private const val CHANNEL_ID = "phishguard_alerts"

    @RequiresPermission(Manifest.permission.POST_NOTIFICATIONS)
    fun showPhishingAlert(context: Context, url: String, risk: Float) {

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "PhishGuard Alerts",
                NotificationManager.IMPORTANCE_HIGH
            )
            channel.description = "Phishing detection alerts"
            val manager = context.getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }

        val intent = Intent(context, MainActivity::class.java)
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_info_outline)
            .setContentTitle("⚠ Phishing Link Detected")
            .setContentText(url)
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText("Suspicious link detected:\n$url\n\nRisk score: ${"%.2f".format(risk)}")
            )
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()

        NotificationManagerCompat.from(context)
            .notify(System.currentTimeMillis().toInt(), notification)
    }
}
