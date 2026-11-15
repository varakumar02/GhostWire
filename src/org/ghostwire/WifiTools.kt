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
 * The aircrack-ng suite, bundled as prebuilt aarch64 binaries and run as root.
 *
 * Binaries ship in assets/wifi/bin and their shared libraries in assets/wifi/lib
 * (see assets/wifi/SOURCE for provenance — these are the stock GPLv2 upstream
 * programs, invoked unmodified). They are copied to the app's files dir and made
 * executable on first use, the way the DIAG helper ships, then exec'd with
 * LD_LIBRARY_PATH pointing at the extracted libs. Missing binaries degrade
 * gracefully: [installed] is false and the UI says what to drop in.
 *
 * Attack command strings mirror wifite2's (GPLv2) — the flags are facts about the
 * tools, reimplemented here, not ported code.
 */
class WifiTools(context: Context) {

    private val base = File(context.filesDir, "wifi")
    private val binDir = File(base, "bin")
    private val libDir = File(base, "lib")
    private val assets = context.assets

    /** airodump writes its capture set here; readable by root for CSV polling. */
    val workDir: String = File(base, "work").apply { mkdirs() }.absolutePath

    /** LD_LIBRARY_PATH prefix for exec'ing a bundled binary as root. */
    val env: String get() = "LD_LIBRARY_PATH=${libDir.absolutePath}:\$LD_LIBRARY_PATH"

    fun bin(name: String): String = File(binDir, name).absolutePath

    /** The core set must be present for monitor scanning + handshake capture. */
    private val core = listOf("airodump-ng", "aireplay-ng", "aircrack-ng")

    var installed: Boolean = false
        private set

    /** Copy any bundled binaries/libs out and chmod them. Idempotent, cheap to rerun. */
    fun ensure(): Boolean {
        binDir.mkdirs(); libDir.mkdirs()
        copyTree("wifi/bin", binDir)
        copyTree("wifi/lib", libDir)
        // chmod as root so exec works from the app-private dir on every ROM.
        Root.run("chmod 755 ${binDir.absolutePath}/* 2>/dev/null; chmod 644 ${libDir.absolutePath}/* 2>/dev/null")
        installed = core.all { File(binDir, it).exists() }
        return installed
    }

    /** List which core/optional tools are present, for a status readout. */
    fun report(): String {
        val all = core + listOf("tshark", "hcxdumptool", "hcxpcapngtool", "reaver", "bully", "pixiewps")
        return all.joinToString("\n") { "  ${if (File(binDir, it).exists()) "✓" else "·"} $it" }
    }

    private fun copyTree(assetDir: String, dest: File) {
        val names = runCatching { assets.list(assetDir) }.getOrNull() ?: return
        for (n in names) {
            val out = File(dest, n)
            runCatching {
                assets.open("$assetDir/$n").use { input ->
                    out.outputStream().use { input.copyTo(it) }
                }
            }
        }
    }

    // ---- attack commands (mirroring wifite2's flags) --------------------------

    /** Targeted deauth: n bursts at an AP, optionally a single client. */
    fun deauth(iface: String, bssid: String, client: String?, bursts: Int = 5): String {
        if (!WifiIface.valid(iface) || !bssid.matches(MAC)) return "invalid target"
        val c = client?.takeIf { it.matches(MAC) }?.let { "-c $it" } ?: ""
        return Root.run(
            "$env ${bin("aireplay-ng")} -0 $bursts --ignore-negative-one -a $bssid -D $c $iface 2>&1"
        ).out
    }

    /**
     * Is there a usable WPA handshake in [cap] for [bssid]? Prefers tshark's EAPOL
     * message check, falls back to hcxpcapngtool producing a WPA*02/03/04 line.
     * Returns null when neither tool is bundled (so we never claim a false positive).
     */
    fun hasHandshake(cap: String, bssid: String): Boolean? {
        if (cap.isBlank()) return false
        if (File(binDir, "tshark").exists()) {
            val eapol = Root.run(
                "$env ${bin("tshark")} -r '$cap' -n -Y eapol -T fields -e wlan.ta -e wlan.da 2>/dev/null | wc -l"
            ).out.trim().toIntOrNull() ?: 0
            if (eapol >= 2) return true
        }
        if (File(binDir, "hcxpcapngtool").exists()) {
            val out = "$workDir/hs.22000"
            Root.run("$env ${bin("hcxpcapngtool")} -o '$out' '$cap' 2>/dev/null")
            val hit = Root.run("grep -ci '^WPA\\*0[234]\\*' '$out' 2>/dev/null").out.trim().toIntOrNull() ?: 0
            if (hit > 0) return true
        }
        return if (File(binDir, "tshark").exists() || File(binDir, "hcxpcapngtool").exists()) false else null
    }

    companion object {
        private val MAC = Regex("^[0-9A-Fa-f:]{17}$")
    }
}
