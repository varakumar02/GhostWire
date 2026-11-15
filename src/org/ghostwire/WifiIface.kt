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

/**
 * Wi-Fi interface enumeration + monitor-mode control, as root.
 *
 * The enable/disable mechanics follow the logic the NetHunter app uses in its
 * EvilTwin screen (GPLv2 — reimplemented clean here, not copied): classify an
 * interface as internal vs USB from sysfs, switch an internal qcacld radio with
 * the `con_mode` sysfs knob and anything else with `iw ... set type monitor`,
 * then verify. The one knob that matters on this phone is `con_mode` (QCA6490 /
 * qcacld-3.0); an OTG USB adapter takes the `iw` path and is the safer route,
 * since monitor mode on the internal chip has panicked this device once in the
 * CFR path (see .claude/research/wifi-sensing.md).
 *
 * Interface names are validated before they ever reach a root command line.
 */
object WifiIface {

    /** One wireless netdev. [internal] = on-SoC (not USB-OTG). */
    data class Iface(
        val name: String,
        val dualBand: Boolean,
        val internal: Boolean,
        val mode: String,     // managed / monitor / ...
    ) {
        fun label(): String {
            val bus = if (internal) "internal" else "USB"
            val band = if (dualBand) "dual-band" else "2.4GHz"
            val mon = if (mode == "monitor") " • MONITOR" else ""
            return "$name ($bus, $band)$mon"
        }
    }

    // Linux netdev names are <=15 chars; keep it to a safe shell-word charset.
    private val VALID = Regex("^[A-Za-z0-9._-]{1,15}$")
    fun valid(name: String): Boolean = VALID.matches(name)

    /**
     * List wireless interfaces (wlan0, wlxXXXX USB adapters, …) with band, bus and
     * current mode, in one root shell. Unlike NetHunter's `grep '^wlan'`, this uses
     * `^wl` so USB adapters named wlxNNN are not dropped.
     */
    fun list(): List<Iface> {
        val sh = """
            for d in ${'$'}(iw dev 2>/dev/null | awk '/Interface/{print ${'$'}2}' | grep '^wl' | sort -u); do
              phy=${'$'}(iw dev ${'$'}d info 2>/dev/null | awk '/wiphy/{print ${'$'}2}')
              band=0; iw phy${'$'}phy info 2>/dev/null | grep -q 'Band 2:' && band=1
              dp=${'$'}(readlink -f /sys/class/net/${'$'}d/device 2>/dev/null)
              intr=1; echo "${'$'}dp" | grep -q '/usb' && intr=0
              mode=${'$'}(iw dev ${'$'}d info 2>/dev/null | awk '/type/{print ${'$'}2}')
              echo "${'$'}d|${'$'}band|${'$'}intr|${'$'}mode"
            done
        """.trimIndent()
        return Root.run(sh).out.lineSequence()
            .mapNotNull { line ->
                val p = line.trim().split("|")
                if (p.size < 4 || !valid(p[0])) null
                else Iface(p[0], p[1] == "1", p[2] == "1", p[3].ifBlank { "?" })
            }.toList()
    }

    /** `type` of an interface right now, or "" if it can't be read. */
    fun mode(iface: String): String {
        if (!valid(iface)) return ""
        return Root.run("iw dev $iface info 2>/dev/null | awk '/type/{print \$2}'").out.trim()
    }

    /** Global con_mode sysfs path (qcacld), or "" if the driver doesn't expose one. */
    private fun conMode(): String =
        Root.run("find /sys/module -name con_mode 2>/dev/null | head -n 1").out.trim()

    /**
     * Put [iface] into monitor mode. Internal qcacld radios go through con_mode=4;
     * everything else (USB adapters) through `iw set type monitor`. Returns the
     * verified mode text ("monitor" on success) and the command log.
     */
    fun enableMonitor(iface: String, internal: Boolean): Result {
        if (!valid(iface)) return Result(false, "", "invalid interface name")
        val cm = if (internal) conMode() else ""
        val sh = if (cm.isNotEmpty())
            "ip link set $iface down 2>&1; echo 4 > $cm 2>&1; ip link set $iface up 2>&1"
        else
            "ip link set $iface down 2>&1; iw dev $iface set type monitor 2>&1; ip link set $iface up 2>&1"
        val log = Root.run(sh).out
        val now = mode(iface)
        return Result(now == "monitor", now,
            (if (cm.isNotEmpty()) "via con_mode ($cm)\n" else "via iw set type monitor\n") + log)
    }

    /**
     * Restore [iface] to managed and bring normal Wi-Fi back. con_mode=0 first (if
     * present), then drop any *mon VIF / reset to managed, then `svc wifi enable`.
     */
    fun disableMonitor(iface: String): Result {
        if (!valid(iface)) return Result(false, "", "invalid interface name")
        val cm = conMode()
        val sh = buildString {
            if (cm.isNotEmpty()) append("echo 0 > $cm 2>&1; ")
            append("ip link set $iface down 2>&1; ")
            append("iw dev $iface set type managed 2>&1; ")
            append("ip link set $iface up 2>&1; ")
            append("svc wifi enable 2>&1")
        }
        val log = Root.run(sh).out
        val now = mode(iface)
        return Result(now != "monitor", now, log)
    }

    data class Result(val ok: Boolean, val mode: String, val log: String)
}
