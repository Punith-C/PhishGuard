package com.example.phishguard

import android.app.Application
import com.example.phishguard.analysis.MlEngine

class PhishGuardApp : Application() {
    override fun onCreate() {
        super.onCreate()
        MlEngine.init(this)
    }
}