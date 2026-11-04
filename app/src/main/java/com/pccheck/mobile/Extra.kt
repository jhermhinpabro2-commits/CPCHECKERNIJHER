package com.pccheck.mobile

import android.content.Context
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Build
import android.os.storage.StorageManager
import java.io.File
import java.util.PriorityQueue

object Extra {
    private val textExt = setOf("lua", "luau", "txt", "json", "js", "cfg", "ini", "log", "md", "html", "xml", "dat", "tmp", "bak", "")
    private val weirdExt = setOf("", "dat", "tmp", "bak")

    /** USB OTG drives and SD cards are mounted under /storage/<id> */
    fun removableRoots(): List<File> =
        File("/storage").listFiles()?.filter { it.isDirectory && it.name != "emulated" && it.name != "self" } ?: emptyList()

    private fun walk(roots: List<File>, cancelled: () -> Boolean, visit: (File) -> Unit) {
        val stack = kotlin.collections.ArrayDeque<File>()
        roots.forEach { stack.add(it) }
        while (stack.isNotEmpty() && !cancelled()) {
            val f = stack.removeLast()
            if (f.isDirectory) f.listFiles()?.let { stack.addAll(it) } else visit(f)
        }
    }

    fun scanScripts(roots: List<File>, cancelled: () -> Boolean, progress: (String) -> Unit, onRow: (Row) -> Unit) {
        var n = 0
        walk(roots, cancelled) { f ->
            n++
            if (n % 300 == 0) progress("Scanned $n files...")
            val ext = f.extension.lowercase()
            val size = f.length()
            val limit = if (ext in weirdExt) 300_000L else 2_000_000L
            if (ext !in textExt || size <= 0 || size > limit) return@walk
            val s = try { String(f.readBytes(), Charsets.ISO_8859_1).lowercase() } catch (e: Throwable) { return@walk }
            val hits = Sigs.scriptSigs.filter { s.contains(it) }
            if (hits.size >= 2 || "getgenv" in hits || "identifyexecutor" in hits) {
                val renamed = if (ext !in setOf("lua", "luau")) " (not a .lua file - possibly renamed)" else ""
                onRow(Row("SCRIPT", "Exploit script", "Found: ${hits.take(5).joinToString(", ")}$renamed", fmt(f.lastModified()), f.absolutePath))
            } else if (ext == "lua" || ext == "luau") {
                onRow(Row("INFO", "Lua file", "No exploit strings found", fmt(f.lastModified()), f.absolutePath))
            }
        }
    }

    /** Filename hits + hidden files + the newest [cap] files. */
    fun listFiles(roots: List<File>, cap: Int, cancelled: () -> Boolean, progress: (String) -> Unit): List<Row> {
        val heap = PriorityQueue<Pair<Long, File>>(compareBy<Pair<Long, File>> { it.first })
        val out = ArrayList<Row>()
        var hiddenCount = 0
        var n = 0
        walk(roots, cancelled) { f ->
            n++
            if (n % 300 == 0) progress("Scanned $n files...")
            val p = f.absolutePath
            val hit = Sigs.matchName(f.name, true)
            if (hit != null) {
                out.add(Row(hit.level, hit.sig.name, "Filename match (${f.length() / 1024} KB)", fmt(f.lastModified()), p))
            } else if (p.contains("/.")) {
                if (hiddenCount++ < 1000)
                    out.add(Row("HIDDEN", "-", "Hidden file/folder (${f.length() / 1024} KB)", fmt(f.lastModified()), p))
            } else {
                heap.add(f.lastModified() to f)
                if (heap.size > cap) heap.poll()
            }
        }
        heap.sortedByDescending { it.first }.forEach { (m, f) ->
            out.add(Row("OK", "-", "${f.length() / 1024} KB", fmt(m), f.absolutePath))
        }
        return out
    }

    private fun className(c: Int) = when (c) {
        1 -> "Audio"; 3 -> "HID (keyboard/mouse/controller)"; 8 -> "Mass Storage"; 9 -> "Hub"
        14 -> "Video"; 224 -> "Wireless"; 255 -> "Vendor specific"; else -> "Class $c"
    }

    fun describe(d: UsbDevice): String {
        val classes = HashSet<Int>()
        classes.add(d.deviceClass)
        for (i in 0 until d.interfaceCount) classes.add(d.getInterface(i).interfaceClass)
        classes.remove(0)
        val name = try { listOfNotNull(d.manufacturerName, d.productName).joinToString(" ") } catch (e: Throwable) { "" }
        return "${name.ifBlank { "Unknown device" }} | VID:%04X PID:%04X | %s".format(d.vendorId, d.productId, classes.joinToString(", ") { className(it) })
    }

    fun usbDevices(ctx: Context): List<Row> {
        val out = ArrayList<Row>()
        val um = ctx.getSystemService(Context.USB_SERVICE) as UsbManager
        val now = fmt(System.currentTimeMillis())
        for (d in um.deviceList.values) out.add(Row("CONNECTED", "USB device", describe(d), now, d.deviceName))
        val sm = ctx.getSystemService(Context.STORAGE_SERVICE) as StorageManager
        for (v in sm.storageVolumes.filter { it.isRemovable }) {
            val dir = if (Build.VERSION.SDK_INT >= 30) v.directory?.path ?: "-" else "-"
            out.add(Row("VOLUME", "Removable storage", "${v.getDescription(ctx)} (${v.state})", now, dir))
        }
        return out
    }
}
