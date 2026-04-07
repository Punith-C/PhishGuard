package com.example.phishguard

object UrlCache {

    private val seenUrls = HashSet<String>()

    fun isAlreadyScanned(url: String): Boolean {
        if (seenUrls.contains(url)) return true
        seenUrls.add(url)
        if (seenUrls.size > 200) {
            seenUrls.clear()
        }
        return false
    }
}
