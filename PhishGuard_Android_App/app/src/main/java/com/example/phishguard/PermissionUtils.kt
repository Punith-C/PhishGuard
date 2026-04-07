package com.example.phishguard

import android.content.Context
import android.provider.Settings

object PermissionUtils {

    fun isNotificationAccessEnabled(context: Context): Boolean {
        val enabled =
            Settings.Secure.getString(
                context.contentResolver,
                "enabled_notification_listeners"
            )
        return enabled?.contains(context.packageName) == true
    }
}
