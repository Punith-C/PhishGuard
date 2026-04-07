package com.example.phishguard

data class BlockedDomainEntry(
    val domain: String,
    val firstBlockedAt: Long,
    val lastBlockedAt: Long,
    val count: Int,
    val allowed: Boolean
)