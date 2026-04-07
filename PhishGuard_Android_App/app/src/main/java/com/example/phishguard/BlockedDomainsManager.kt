package com.example.phishguard

import android.content.Context

object BlockedDomainsManager {

    private const val PREF_NAME = "phishguard_prefs"
    private const val KEY_WHITELIST = "permanent_whitelist"
    private const val ALLOW_DURATION = 5 * 60 * 1000L

    val blockedSession = mutableMapOf<String, Long>()
    private val allowedTemp = mutableMapOf<String, Long>()
    private val permanentWhitelist = mutableSetOf<String>()

    fun init(context: Context) {
        val prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
        permanentWhitelist.clear()
        permanentWhitelist.addAll(
            prefs.getStringSet(KEY_WHITELIST, emptySet()) ?: emptySet()
        )
    }

    private fun saveWhitelist(context: Context) {
        val prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
        prefs.edit()
            .putStringSet(KEY_WHITELIST, permanentWhitelist)
            .apply()
    }

    fun recordBlocked(domain: String) {
        blockedSession[domain] = System.currentTimeMillis()
    }

    fun allowTemporarily(domain: String) {
        allowedTemp[domain] = System.currentTimeMillis() + ALLOW_DURATION
    }

    fun allowPermanently(context: Context, domain: String) {
        permanentWhitelist.add(domain)
        allowedTemp.remove(domain)
        saveWhitelist(context)
    }

    fun revokePermanent(domain: String) {
        permanentWhitelist.remove(domain)
        allowedTemp.remove(domain)
    }

    fun getPermanentWhitelist(): Set<String> =
        permanentWhitelist.toSet()

    fun isAllowed(domain: String): Boolean {
        if (permanentWhitelist.contains(domain)) return true

        val expiry = allowedTemp[domain] ?: return false

        if (System.currentTimeMillis() > expiry) {
            allowedTemp.remove(domain)
            return false
        }

        return true
    }

    fun clearSession() {
        blockedSession.clear()
        allowedTemp.clear()
    }
}