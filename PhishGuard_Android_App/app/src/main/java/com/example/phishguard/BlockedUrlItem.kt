package com.example.phishguard

// Single declaration — delete any other BlockedUrlItem files
data class BlockedUrlItem(
    val domain   : String,
    val itemType : Int,
    val extraInfo: String
) {
    companion object {
        const val TYPE_BLOCKED   = 0   // red   — blocked this session
        const val TYPE_TEMP      = 1   // cyan  — temporarily allowed
        const val TYPE_PERMANENT = 2   // green — always allowed
    }
}