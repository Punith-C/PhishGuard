package com.example.phishguard

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities

object VpnStatusChecker {

    fun isVpnRunning(context: Context): Boolean {

        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE)
                as ConnectivityManager

        val networks = cm.allNetworks

        for (network in networks) {

            val caps = cm.getNetworkCapabilities(network)

            if (caps != null &&
                caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                return true
            }
        }

        return false
    }
}