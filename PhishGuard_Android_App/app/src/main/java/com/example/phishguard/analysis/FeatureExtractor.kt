package com.example.phishguard.analysis

import java.util.Locale
import kotlin.math.log2

object FeatureExtractor {

    const val N_FEATURES = 72

    const val IDX_HOST_LEN = 0
    const val IDX_TLD_LEN = 1
    const val IDX_SLD_LEN = 2
    const val IDX_SUB_LEN = 3
    const val IDX_SUB_COUNT = 4
    const val IDX_LABEL_COUNT = 5
    const val IDX_MAX_LABEL_LEN = 6
    const val IDX_AVG_LABEL_LEN = 7

    const val IDX_TRUSTED_HOSTNAME = 70
    const val IDX_TRUSTED_REG = 71

    private val SUSPICIOUS_TLDS = setOf(
        "xyz","tk","ml","ga","cf","gq","pw","top","click","win",
        "download","loan","work","bid","racing","date","stream",
        "faith","review","accountant","trade","party","science",
        "cricket","ninja","club","site","online","tech","space",
        "live","uno","icu","cam","rest","monster","buzz","guru",
        "link","email","promo","biz","info","cc","men","name",
        "kim","country","gdn","ren","accountants","phd","vip",
    )

    private val COMMON_TLDS = setOf(
        "com","org","net","edu","gov","io","co","app","dev","in"
    )

    private val COUNTRY_TLDS = setOf(
        "in","uk","au","de","fr","jp","cn","br","ca","ru","it",
        "es","nl","se","no","fi","dk","pl","pt","gr","ch","at",
        "nz","sg","hk","my","th","id","ph","pk","bd","lk","np",
    )

    private val PHISHING_KEYWORDS = listOf(
        "login","secure","account","update","verify","banking","confirm",
        "signin","webscr","wallet","recover","suspend","unlock","validate",
        "credential","billing","alert","claim","auth","reset","reactivate",
        "blocked","restricted","unusual","support","service","password",
        "security","notification","activation","authorize","refund",
        "prize","winner","free","gift","lucky","reward","bonus",
        "urgent","immediate","action","required","limited",
    )

    private val KEYWORD_FLAGS = listOf(
        "login","secure","verify","update","account","confirm",
        "signin","suspend","banking","wallet","recover","alert",
        "credential","billing","auth","password","prize","winner",
    )

    private val BRANDS = listOf(
        "paypal","google","facebook","microsoft","apple","amazon",
        "netflix","instagram","twitter","linkedin","whatsapp","ebay",
        "chase","citibank","wellsfargo","hsbc","barclays","dhl",
        "fedex","usps","ups","irs","spotify","dropbox","adobe",
        "zoom","coinbase","sbi","hdfc","icici","flipkart","paytm",
        "razorpay","discord","telegram","steam","roblox","xbox",
        "playstation","hotstar","zerodha","groww","phonepe","gpay",
    )

    private val REAL_BRAND_EXTS = listOf(
        "com","org","net","co.in","in","io","co.uk","com.au"
    )

    private val IP_REGEX = Regex("""(\d{1,3}\.){3}\d{1,3}""")
    private val DIG_SUB_REGEX = Regex("""[a-z]\d[a-z]|\d[a-z]\d""")
    private val REPEAT_CHAR_REGEX = Regex("""(.)\1{2,}""")
    private val HEX_REGEX = Regex("""%[0-9a-fA-F]{2}""")
    private val TOKEN_SPLIT = Regex("""[.\-_]""")

    fun extract(rawHostname: String): FloatArray {
        val h = rawHostname.trim().lowercase(Locale.ROOT).removePrefix("www.")
        if (h.length < 2) return FloatArray(N_FEATURES)

        val parts = h.split(".")
        val tld = parts.lastOrNull() ?: ""
        val sld = if (parts.size >= 2) parts[parts.size - 2] else ""
        val subs = if (parts.size > 2) parts.dropLast(2) else emptyList()
        val subStr = subs.joinToString(".")
        val regDom = getRegistrableDomain(h)

        val a1 = h.length.f()
        val a2 = tld.length.f()
        val a3 = sld.length.f()
        val a4 = subStr.length.f()
        val a5 = subs.size.f()
        val a6 = parts.size.f()
        val a7 = (parts.maxOfOrNull { it.length } ?: 0).f()
        val a8 = if (parts.isEmpty()) 0f else parts.sumOf { it.length }.f() / parts.size.f()

        val b1 = h.count { it == '.' }.f()
        val b2 = h.count { it == '-' }.f()
        val b3 = h.count { it.isDigit() }.f()
        val b4 = h.count { it.isLetter() }.f()
        val b5 = h.count { !it.isLetterOrDigit() && it !in ".-" }.f()
        val b6 = sld.count { it == '-' }.f()
        val b7 = sld.count { it.isDigit() }.f()
        val b8 = subStr.count { it == '.' }.f()
        val b9 = subStr.count { it == '-' }.f()

        val hl = h.length.coerceAtLeast(1).f()
        val c1 = b3 / hl
        val c2 = b2 / hl
        val c3 = b4 / hl
        val c4 = consonantRatio(sld)
        val c5 = consonantRatio(h)
        val c6 = vowelRatio(sld)
        val c7 = vowelRatio(h)

        val d1 = if (IP_REGEX.matches(h)) 1f else 0f
        val d2 = if (tld in SUSPICIOUS_TLDS) 1f else 0f
        val d3 = if (tld in COMMON_TLDS) 1f else 0f
        val d4 = if (tld in COUNTRY_TLDS) 1f else 0f
        val d5 = if (subs.size >= 2) 1f else 0f
        val d6 = if (subs.size >= 3) 1f else 0f
        val d7 = if (h.length > 40) 1f else 0f
        val d8 = if (sld.length > 20) 1f else 0f
        val d9 = if ("xn--" in h) 1f else 0f
        val d10 = if (sld.count { it == '-' } >= 2) 1f else 0f
        val d11 = if (sld.isNotEmpty() && sld.all { it.isDigit() }) 1f else 0f
        val d12 = if (DIG_SUB_REGEX.containsMatchIn(sld)) 1f else 0f
        val d13 = if (REPEAT_CHAR_REGEX.containsMatchIn(h)) 1f else 0f
        val d14 = if (HEX_REGEX.containsMatchIn(h)) 1f else 0f
        val d15 = h.split("www").size.minus(1).coerceIn(0, 3).f()

        val tokens = h.split(TOKEN_SPLIT).filter { it.isNotEmpty() }
        val e1 = (tokens.maxOfOrNull { it.length } ?: 0).f()
        val e2 = if (tokens.isEmpty()) 0f else tokens.sumOf { it.length }.f() / tokens.size.f()
        val e3 = tokens.size.f()
        val e4 = tokens.count { it.length > 8 }.f()
        val e5 = longestDigitRun(h).f()

        val f1 = shannonEntropy(h)
        val f2 = shannonEntropy(sld)
        val f3 = shannonEntropy(subStr)
        val f4 = shannonEntropy(tld)

        val g1 = PHISHING_KEYWORDS.count { it in h }.f()
        val g2 = BRANDS.count { it in h }.f()
        val gFlags = KEYWORD_FLAGS.map { if (it in h) 1f else 0f }

        var h1 = 0f
        if (!MlEngine.isTrusted(regDom)) {
            for (brand in BRANDS) {
                if (brand in subStr) { h1 = 1f; break }
            }
        }

        var h2 = 0f
        for (brand in BRANDS) {
            if (brand in h) {
                val isReal = REAL_BRAND_EXTS.any { ext ->
                    h == "$brand.$ext" || h.endsWith(".$brand.$ext")
                }
                if (!isReal) { h2 = 1f; break }
            }
        }

        val i1 = if (MlEngine.isTrusted(h)) 1f else 0f
        val i2 = if (MlEngine.isTrustedRoot(regDom)) 1f else 0f

        return floatArrayOf(
            a1, a2, a3, a4, a5, a6, a7, a8,
            b1, b2, b3, b4, b5, b6, b7, b8, b9,
            c1, c2, c3, c4, c5, c6, c7,
            d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15,
            e1, e2, e3, e4, e5,
            f1, f2, f3, f4,
            g1, g2, *gFlags.toFloatArray(),
            h1, h2,
            i1, i2,
        )
    }

    private fun Int.f() = this.toFloat()

    fun getRegistrableDomain(hostname: String): String {
        val h = hostname.lowercase(Locale.ROOT).removePrefix("www.")
        val p = h.split(".")
        return when {
            p.size >= 3 &&
                    p[p.size - 2] in setOf("co","ac","gov","edu","org","net","com") &&
                    p.last().length == 2 ->
                p.takeLast(3).joinToString(".")
            p.size >= 2 -> p.takeLast(2).joinToString(".")
            else -> h
        }
    }

    private fun shannonEntropy(s: String): Float {
        if (s.isEmpty()) return 0f
        val freq = HashMap<Char, Int>()
        s.forEach { freq[it] = (freq[it] ?: 0) + 1 }
        val n = s.length.toFloat()
        return -freq.values.sumOf { cnt ->
            val p = cnt / n
            (p * log2(p.toDouble())).takeIf { !it.isNaN() && !it.isInfinite() } ?: 0.0
        }.toFloat()
    }

    private fun consonantRatio(s: String): Float {
        val consonants = s.count { it.lowercaseChar() in "bcdfghjklmnpqrstvwxyz" }
        val letters = s.count { it.isLetter() }
        return consonants.toFloat() / letters.coerceAtLeast(1).toFloat()
    }

    private fun vowelRatio(s: String): Float {
        val vowels = s.count { it.lowercaseChar() in "aeiou" }
        val letters = s.count { it.isLetter() }
        return vowels.toFloat() / letters.coerceAtLeast(1).toFloat()
    }

    private fun longestDigitRun(s: String): Int {
        var best = 0
        var cur = 0
        for (c in s) {
            if (c.isDigit()) {
                cur++
                if (cur > best) best = cur
            } else cur = 0
        }
        return best
    }
}