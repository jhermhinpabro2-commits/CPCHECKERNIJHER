package com.pccheck.mobile

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.app.AppOpsManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.Color
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import android.widget.Toast
import java.io.File

class MainActivity : Activity() {
    @Volatile private var cancel = false
    @Volatile private var running = false
    private val pages = ArrayList<Page>()
    private val tabBtns = ArrayList<Button>()
    private lateinit var content: FrameLayout
    private var usbReceiver: BroadcastReceiver? = null
    private val blue = 0xFF1B4DFF.toInt()
    private val dim = 0xFF0F1A5C.toInt()

    // ---------- one page per tool, each with its own search bar ----------
    inner class Page(val title: String) {
        val all = ArrayList<Row>()
        val shown = ArrayList<Row>()
        val root = LinearLayout(this@MainActivity).apply { orientation = LinearLayout.VERTICAL; visibility = View.GONE }
        val status = TextView(this@MainActivity).apply { text = "Ready."; setTextColor(0xFFB8C4FF.toInt()); setPadding(0, 8, 0, 8) }
        val search = EditText(this@MainActivity).apply {
            hint = "Search"; setHintTextColor(Color.GRAY); setTextColor(Color.WHITE); setSingleLine()
            addTextChangedListener(object : TextWatcher {
                override fun afterTextChanged(s: Editable?) { refresh() }
                override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
                override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            })
        }
        val adapter = object : BaseAdapter() {
            override fun getCount() = shown.size
            override fun getItem(i: Int) = shown[i]
            override fun getItemId(i: Int) = i.toLong()
            override fun getView(i: Int, v: View?, p: ViewGroup?): View {
                val r = shown[i]
                val tv = (v as? TextView) ?: TextView(this@MainActivity).apply { setPadding(8, 14, 8, 14); textSize = 12f }
                tv.setTextColor(when (r.result) {
                    "DETECTED" -> 0xFFFF5555.toInt()
                    "POSSIBLE", "SUSPICIOUS", "SCRIPT", "HIDDEN", "ATTACHED" -> 0xFFFFB347.toInt()
                    "UNINSTALLED", "DETACHED" -> 0xFFFF8AD8.toInt()
                    "CONNECTED", "VOLUME", "INFO" -> 0xFF7FE3FF.toInt()
                    else -> Color.WHITE
                })
                tv.text = "[${r.result}] ${r.cheat}\n${r.evidence}\n${r.time}\n${r.path}"
                return tv
            }
        }
        val list = ListView(this@MainActivity).apply {
            adapter = this@Page.adapter
            setBackgroundColor(0xFF0A1240.toInt())
            setOnItemClickListener { _, _, i, _ -> showDetail(shown[i]) }
        }

        fun refresh() {
            val q = search.text.toString().lowercase()
            val rank = mapOf("DETECTED" to 0, "SUSPICIOUS" to 1, "POSSIBLE" to 1, "SCRIPT" to 1, "HIDDEN" to 1, "ATTACHED" to 1, "UNINSTALLED" to 2)
            shown.clear()
            shown.addAll(all.filter { q.isEmpty() || "${it.result} ${it.cheat} ${it.evidence} ${it.path}".lowercase().contains(q) }
                .sortedBy { rank[it.result] ?: 3 })
            adapter.notifyDataSetChanged()
        }
        fun add(r: List<Row>) = runOnUiThread { all.addAll(r); refresh() }
        fun clear() { all.clear(); refresh() }
    }

    private fun btn(t: String, f: () -> Unit) = Button(this).apply {
        text = t; isAllCaps = false; setTextColor(Color.WHITE); setBackgroundColor(blue)
        layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { setMargins(4, 4, 4, 4) }
        setOnClickListener { f() }
    }

    private fun row(vararg v: View) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL; v.forEach { addView(it) }
    }

    private fun page(title: String, desc: String, extra: List<View>, actions: List<Pair<String, (Page) -> Unit>>): Page {
        val p = Page(title)
        p.root.addView(TextView(this).apply { text = desc; textSize = 12f; setTextColor(0xFFB8C4FF.toInt()); setPadding(0, 8, 0, 8) })
        extra.forEach { p.root.addView(it) }
        p.root.addView(row(*actions.map { (t, f) -> btn(t) { f(p) } }.toTypedArray()))
        p.root.addView(row(btn("Stop") { cancel = true }, btn("Export CSV") { export(p) }, btn("Clear") { p.clear() }))
        p.root.addView(p.search)
        p.root.addView(p.status)
        p.root.addView(p.list, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        pages.add(p)
        content.addView(p.root, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        return p
    }

        override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        showLogin()
    }

    private fun showLogin() {
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = android.view.Gravity.CENTER
            setBackgroundColor(0xFF050B2E.toInt())
            setPadding(48, 48, 48, 48)
        }
        box.addView(TextView(this).apply {
            text = "PC CHECKER"; textSize = 28f; setTextColor(Color.WHITE)
            gravity = android.view.Gravity.CENTER
        })
        box.addView(TextView(this).apply {
            text = "Enter password to continue"; textSize = 14f; setTextColor(0xFFB8C4FF.toInt())
            gravity = android.view.Gravity.CENTER; setPadding(0, 8, 0, 24)
        })
        val pw = EditText(this).apply {
            hint = "Password"; setHintTextColor(Color.GRAY); setTextColor(Color.WHITE)
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        box.addView(pw)
        val err = TextView(this).apply { setTextColor(0xFFFF5555.toInt()); setPadding(0, 8, 0, 8) }
        box.addView(err)
        box.addView(Button(this).apply {
            text = "Enter"; isAllCaps = false; setTextColor(Color.WHITE); setBackgroundColor(blue)
            setOnClickListener {
                if (pw.text.toString() == "JherScanner") buildMain()
                else { err.text = "Wrong password"; pw.setText("") }
            }
        })
        setContentView(box)
    }

    private fun buildMain() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setBackgroundColor(0xFF050B2E.toInt()); setPadding(16, 56, 16, 16)
        }
        root.addView(TextView(this).apply { text = "PC CHECKER"; textSize = 22f; setTextColor(Color.WHITE) })
        root.addView(TextView(this).apply { text = "TOOLS - Mobile"; textSize = 16f; setTextColor(0xFF6C8CFF.toInt()); setPadding(0, 0, 0, 8) })
        val tabs = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        root.addView(HorizontalScrollView(this).apply { addView(tabs) })
        content = FrameLayout(this)
        root.addView(content, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        setContentView(root)

        val deep = CheckBox(this).apply { text = "Deep content scan (catches renamed files)"; setTextColor(Color.WHITE); isChecked = true }
        val sdBox = CheckBox(this).apply { text = "Scan SD card / USB too"; setTextColor(Color.WHITE) }

        page("Detect Roblox Cheats", "Finds executors by filename, APK contents and script traces - even if renamed or hidden.",
            listOf(deep, sdBox), listOf("Detect Roblox Cheats" to { p: Page -> detect(p, deep.isChecked, sdBox.isChecked) }))
        page("Last Activity View", "Every app opened in the last 7 days, including apps that were already uninstalled.",
            emptyList(), listOf("Load Activity" to { p: Page -> activity(p) }))
        page("Script View", "Finds Lua / exploit scripts, even with a changed extension. Tap a result to read its content.",
            emptyList(), listOf("Scan Scripts" to { p: Page -> scripts(p) }))
        val usb = page("USB Device View", "USB devices connected now (VID/PID, type) plus a live log of plug / unplug while this app is open.",
            emptyList(), listOf("Refresh" to { p: Page -> usbRefresh(p) }))
        page("USB Files", "Scans every file on a plugged-in USB drive or SD card. Flags cheats and hidden files.",
            emptyList(), listOf("Scan USB / SD Files" to { p: Page -> usbFiles(p) }))
        page("Files Scanner", "Lists cheat files, hidden files and the newest files on the phone. Tap a file to view it.",
            emptyList(), listOf("Scan All Files" to { p: Page -> filesScan(p) }))
        page("Installed Apps", "All installed apps with cheat detection.",
            emptyList(), listOf("List Apps" to { p: Page -> apps(p) }))

        pages.forEachIndexed { i, p ->
            val b = Button(this).apply {
                text = p.title; isAllCaps = false; setTextColor(Color.WHITE); setOnClickListener { select(i) }
            }
            tabBtns.add(b); tabs.addView(b)
        }
        select(0)

        usbReceiver = object : BroadcastReceiver() {
            @Suppress("DEPRECATION")
            override fun onReceive(c: Context, i: Intent) {
                val d = i.getParcelableExtra<UsbDevice>(UsbManager.EXTRA_DEVICE) ?: return
                val ev = if (i.action == UsbManager.ACTION_USB_DEVICE_ATTACHED) "ATTACHED" else "DETACHED"
                usb.add(listOf(Row(ev, "USB device", Extra.describe(d), fmt(System.currentTimeMillis()), d.deviceName)))
            }
        }
        registerReceiver(usbReceiver, IntentFilter().apply {
            addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED); addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
        })
    }

    override fun onDestroy() {
        usbReceiver?.let { unregisterReceiver(it) }
        super.onDestroy()
    }

    private fun select(i: Int) {
        pages.forEachIndexed { k, p -> p.root.visibility = if (k == i) View.VISIBLE else View.GONE }
        tabBtns.forEachIndexed { k, b -> b.setBackgroundColor(if (k == i) blue else dim) }
    }

    // ---------- permissions ----------
    private fun hasStorage() =
        if (Build.VERSION.SDK_INT >= 30) Environment.isExternalStorageManager()
        else checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED

    private fun askStorage() {
        if (Build.VERSION.SDK_INT >= 30)
            startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:$packageName")))
        else requestPermissions(arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE), 1)
    }

    /** Returns true if files can be read; otherwise opens the permission screen. */
    private fun storageOk(): Boolean {
        if (hasStorage()) return true
        askStorage(); toast("Allow 'All files access', then tap the button again")
        return false
    }

    @Suppress("DEPRECATION")
    private fun hasUsage(): Boolean {
        val ops = getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        return ops.checkOpNoThrow("android:get_usage_stats", android.os.Process.myUid(), packageName) == AppOpsManager.MODE_ALLOWED
    }

    // ---------- tools ----------
    private fun roots(includeSd: Boolean): List<File> {
        val l = arrayListOf(Environment.getExternalStorageDirectory())
        if (includeSd) Extra.removableRoots().forEach { if (it !in l) l.add(it) }
        return l
    }

    private fun prog(p: Page) = { s: String -> runOnUiThread { p.status.text = s } }

    private fun fullScan(p: Page, roots: List<File>, cap: Int) {
        val seen = HashSet<String>()
        Scanner.scanFiles(this, roots, true, { cancel }, prog(p)) { r -> seen.add(r.path); p.add(listOf(r)) }
        if (!cancel) p.add(Extra.listFiles(roots, cap, { cancel }, prog(p)).filter { seen.add(it.path) })
    }

    private fun detect(p: Page, d: Boolean, sd: Boolean) {
        if (running) return toast("A scan is already running")
        p.clear()
        val roots = roots(sd)
        val ok = storageOk()
        runTask(p, "Scanning") {
            p.add(Scanner.scanApps(this, false))
            if (ok) Scanner.scanFiles(this, roots, d, { cancel }, prog(p)) { r -> p.add(listOf(r)) }
        }
    }

    private fun activity(p: Page) {
        if (running) return toast("A scan is already running")
        if (!hasUsage()) {
            toast("Turn ON usage access for PC Checker Mobile, then come back")
            startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)); return
        }
        p.clear()
        runTask(p, "Reading activity") { p.add(Scanner.recentActivity(this, 7)) }
    }

    private fun scripts(p: Page) {
        if (running) return toast("A scan is already running")
        if (!storageOk()) return
        p.clear()
        val roots = roots(true)
        runTask(p, "Scanning scripts") { Extra.scanScripts(roots, { cancel }, prog(p)) { r -> p.add(listOf(r)) } }
    }

    private fun usbRefresh(p: Page) {
        p.add(Extra.usbDevices(this))
        p.status.text = "Refreshed. Past USB history is not stored by Android - only live events are logged."
    }

    private fun usbFiles(p: Page) {
        if (running) return toast("A scan is already running")
        val roots = Extra.removableRoots()
        if (roots.isEmpty()) { p.status.text = "No USB / SD storage found. Plug in the drive (OTG) first."; return }
        if (!storageOk()) return
        p.clear()
        runTask(p, "Scanning USB / SD") { fullScan(p, roots, 5000) }
    }

    private fun filesScan(p: Page) {
        if (running) return toast("A scan is already running")
        if (!storageOk()) return
        p.clear()
        val roots = roots(true)
        runTask(p, "Scanning files") { fullScan(p, roots, 3000) }
    }

    private fun apps(p: Page) {
        if (running) return toast("A scan is already running")
        p.clear()
        runTask(p, "Listing apps") { p.add(Scanner.scanApps(this, true)) }
    }

    private fun runTask(p: Page, name: String, task: () -> Unit) {
        running = true; cancel = false; p.status.text = "$name..."
        Thread {
            try { task() } catch (e: Throwable) { runOnUiThread { toast("Error: ${e.message}") } }
            running = false
            runOnUiThread {
                val det = p.all.count { it.result == "DETECTED" }
                p.status.text = (if (cancel) "Stopped. " else "Done. ") + "${p.all.size} results, $det detected"
            }
        }.start()
    }

    private fun showDetail(r: Row) {
        val sb = StringBuilder("Result: ${r.result}\nCheat: ${r.cheat}\nEvidence: ${r.evidence}\nTime: ${r.time}\nPath: ${r.path}")
        val f = File(r.path)
        val binary = setOf("apk", "exe", "zip", "rar", "7z", "jar", "dll", "png", "jpg", "jpeg", "webp", "mp4", "mp3")
        if (f.isFile && f.length() in 1..1_000_000 && f.extension.lowercase() !in binary) {
            try { sb.append("\n\n--- Content ---\n").append(f.readText().take(20000)) } catch (e: Throwable) {}
        }
        AlertDialog.Builder(this).setTitle(r.cheat).setMessage(sb.toString()).setPositiveButton("Close", null).show()
    }

    private fun export(p: Page) {
        if (p.all.isEmpty()) return toast("Nothing to export")
        fun q(s: String) = "\"" + s.replace("\"", "\"\"") + "\""
        val csv = StringBuilder("Result,Cheat,Evidence,Time,Path\n")
        p.all.forEach { csv.append(listOf(it.result, it.cheat, it.evidence, it.time, it.path).joinToString(",") { s -> q(s) }).append('\n') }
        startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"; putExtra(Intent.EXTRA_SUBJECT, "${p.title}.csv"); putExtra(Intent.EXTRA_TEXT, csv.toString())
        }, "Export CSV"))
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_LONG).show()
}
