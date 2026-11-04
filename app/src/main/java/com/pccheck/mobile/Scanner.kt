package com.pccheck.mobile

import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import java.io.File
import java.io.RandomAccessFile
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class Row(val result: String, val cheat: String, val evidence: String, val time: String, val path: String)
data class Sig(val name: String, val key: String, val weak: Boolean = false)
data class Hit(val sig: Sig, val level: String)

fun fmt(ms: Long): String =
    if (ms <= 0) "-" else SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(ms))

object Sigs {
    // "weak" = common English word, only flagged with a hint word or when the name starts with it
    val list = listOf(
        Sig("Delta", "delta", true), Sig("Solara", "solara"), Sig("Xeno", "xeno", true),
        Sig("Swift", "swift", true), Sig("Wave", "wave", true), Sig("Electron", "electron", true),
        Sig("Synapse", "synapse"), Sig("KRNL", "krnl"), Sig("Fluxus", "fluxus"),
        Sig("JJSploit", "jjsploit"), Sig("Celery", "celery", true), Sig("Arceus X", "arceus"),
        Sig("Velocity", "velocity", true), Sig("Macrothird", "macrothird"), Sig("real.exe", "real.exe"),
        Sig("Codex", "codex", true), Sig("Hydrogen", "hydrogen", true), Sig("Vega X", "vegax"),
        Sig("Evon", "evon", true), Sig("Cryptic", "cryptic", true)
    )
    private val hints = listOf("executor", "exploit", "roblox", "inject", "script", "hack", "cheat")

    val scriptSigs = listOf(
        "loadstring(", "getgenv", "game:httpget", "hookfunction", "firesignal", "fireclickdetector",
        "identifyexecutor", "getexecutorname", "getrawmetatable", "setclipboard", "drawing.new", "syn.request"
    )

    fun matchName(text: String, installable: Boolean): Hit? {
        val t = text.lowercase().replace(" ", "").replace("_", "")
        val hint = hints.any { t.contains(it) }
        for (s in list) {
            val i = t.indexOf(s.key)
            if (i < 0) continue
            if (!s.weak) return Hit(s, "DETECTED")
            if (hint) return Hit(s, "DETECTED")
            if (installable && i == 0) {
                val n = t.getOrNull(s.key.length)
                if (n == null || !n.isLetter()) return Hit(s, "POSSIBLE")
            }
        }
        return null
    }
}

object Scanner {
    private val apkExt = setOf("apk", "xapk", "apks", "apkm")
    private val instExt = apkExt + setOf("exe", "zip", "rar", "7z", "lua", "luau", "dll", "jar")
    private val textExt = setOf("lua", "luau", "txt", "json", "js", "cfg", "ini", "log", "md", "html", "xml")
    private val skipMagic = setOf("mp4", "mp3", "jpg", "jpeg", "png", "webp", "gif")

    fun scanApps(ctx: Context, listAll: Boolean): List<Row> {
        val pm = ctx.packageManager
        val out = ArrayList<Row>()
        for (ai in pm.getInstalledApplications(0)) {
            val pkg = ai.packageName
            if (pkg == ctx.packageName) continue
            val label = ai.loadLabel(pm).toString()
            val sys = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            val time = try { fmt(pm.getPackageInfo(pkg, 0).firstInstallTime) } catch (e: Exception) { "-" }
            val hit = Sigs.matchName("$label $pkg", true)
            val fake = pkg.contains("roblox") && pkg != "com.roblox.client"
            when {
                hit != null -> out.add(Row(hit.level, hit.sig.name, "Installed app: $label", time, pkg))
                fake -> out.add(Row("SUSPICIOUS", "Modded Roblox?", "Roblox package with unofficial name: $label", time, pkg))
                listAll && !sys -> out.add(Row("OK", "-", "Installed app: $label", time, pkg))
            }
        }
        return out
    }

    /** Apps opened in the last [days] days, including apps that were already uninstalled. */
    fun recentActivity(ctx: Context, days: Int): List<Row> {
        val pm = ctx.packageManager
        val usm = ctx.getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
        val now = System.currentTimeMillis()
        val ev = usm.queryEvents(now - days * 86_400_000L, now)
        val last = HashMap<String, Long>()
        val count = HashMap<String, Int>()
        val e = UsageEvents.Event()
        while (ev.hasNextEvent()) {
            ev.getNextEvent(e)
            if (e.eventType == UsageEvents.Event.MOVE_TO_FOREGROUND) {
                val p = e.packageName
                last[p] = maxOf(last[p] ?: 0L, e.timeStamp)
                count[p] = (count[p] ?: 0) + 1
            }
        }
        val out = ArrayList<Row>()
        for ((pkg, ts) in last.entries.sortedByDescending { it.value }) {
            var label = pkg
            var installed = true
            var sys = false
            try {
                val ai = pm.getApplicationInfo(pkg, 0)
                label = ai.loadLabel(pm).toString()
                sys = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            } catch (ex: Exception) { installed = false }
            if (sys && Sigs.matchName("$label $pkg", true) == null) continue
            val hit = Sigs.matchName("$label $pkg", true)
            val ev2 = "Opened ${count[pkg]}x in last $days days: $label" + if (!installed) " (UNINSTALLED)" else ""
            val res = when {
                hit != null -> hit.level
                !installed -> "UNINSTALLED"
                else -> "OK"
            }
            out.add(Row(res, hit?.sig?.name ?: "-", ev2, fmt(ts), pkg))
        }
        return out
    }

    private fun isZip(f: File): Boolean = try {
        RandomAccessFile(f, "r").use {
            val b = ByteArray(4)
            it.read(b) == 4 && b[0] == 0x50.toByte() && b[1] == 0x4B.toByte() && b[2] == 3.toByte() && b[3] == 4.toByte()
        }
    } catch (e: Throwable) { false }

    fun scanFiles(
        ctx: Context, roots: List<File>, deep: Boolean,
        cancelled: () -> Boolean, progress: (String) -> Unit, onRow: (Row) -> Unit
    ) {
        val pm = ctx.packageManager
        val stack = kotlin.collections.ArrayDeque<File>()
        roots.forEach { stack.add(it) }
        var n = 0
        while (stack.isNotEmpty() && !cancelled()) {
            val f = stack.removeLast()
            if (f.isDirectory) { f.listFiles()?.let { stack.addAll(it) }; continue }
            n++
            if (n % 300 == 0) progress("Scanned $n files...")
            val ext = f.extension.lowercase()
            val size = f.length()
            val t = fmt(f.lastModified())
            val p = f.absolutePath
            var reported = false

            Sigs.matchName(f.name, ext in instExt)?.let {
                onRow(Row(it.level, it.sig.name, "Filename match (.$ext)", t, p)); reported = true
            }
            if (!deep) continue

            val looksZip = ext !in apkExt && ext !in skipMagic && size in 300_000..600_000_000 && isZip(f)
            if (ext in apkExt || looksZip) {
                val pi = try { pm.getPackageArchiveInfo(p, 0) } catch (e: Throwable) { null }
                val ai = pi?.applicationInfo
                if (pi != null && ai != null) {
                    ai.sourceDir = p; ai.publicSourceDir = p
                    val label = try { ai.loadLabel(pm).toString() } catch (e: Throwable) { "" }
                    val hit = Sigs.matchName("$label ${pi.packageName}", true)
                    val fake = pi.packageName.contains("roblox") && pi.packageName != "com.roblox.client"
                    val renamed = if (ext !in apkExt) " (RENAMED - real type is APK)" else ""
                    if (hit != null && !reported) {
                        onRow(Row(hit.level, hit.sig.name, "APK content$renamed: $label / ${pi.packageName}", t, p))
                    } else if (fake) {
                        onRow(Row("SUSPICIOUS", "Modded Roblox?", "APK$renamed: $label / ${pi.packageName}", t, p))
                    }
                }
            } else if (ext in textExt && size in 1..2_000_000) {
                val s = try { String(f.readBytes(), Charsets.ISO_8859_1).lowercase() } catch (e: Throwable) { continue }
                val hits = Sigs.scriptSigs.filter { s.contains(it) }
                if (hits.size >= 2 || "getgenv" in hits || "identifyexecutor" in hits) {
                    onRow(Row("SCRIPT", "Lua exploit script", "Found: ${hits.take(5).joinToString(", ")}", t, p))
                } else if (!reported) {
                    Sigs.list.firstOrNull { !it.weak && s.contains(it.key) }?.let {
                        onRow(Row("POSSIBLE", it.name, "Executor name found inside file", t, p))
                    }
                }
            }
        }
    }
}
