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
 * Wi-Fi interface enumeration + monitor-mode control, as root, self-contained.
 *
 * Enumeration and mode switching use the app's own bundled `iw` (via [WifiTools]);
 * con_mode and `ip link` are Android-side. The monitor logic follows what the
 * NetHunter app does in its EvilTwin screen (GPLv2 — reimplemented clean, not
 * copied): classify an interface as internal vs USB from sysfs, switch an internal
 * qcacld radio with the `con_mode` sysfs knob and a USB adapter with `iw set type
 * monitor`, then verify. On this phone (QCA6490) monitor mode on the internal chip
 * has crashed once in the CFR path, so an OTG USB adapter is the safer route.
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

    private val VALID = Regex("^[A-Za-z0-9._-]{1,15}$")
    fun valid(name: String): Boolean = VALID.matches(name)

    /**
     * List wireless interfaces (wlan0, wlxXXXX USB adapters, …) with band, bus and
     * current mode. Parses the bundled `iw dev` output in Kotlin; falls back to
     * /sys/class/net names (unknown band/mode) if iw produced nothing.
     */
    fun list(tools: WifiTools): List<Iface> {
        val dev = tools.exec("iw dev 2>/dev/null")
        val out = ArrayList<Iface>()
        var name: String? = null
        var phy = -1
        var mode = "?"
        fun flush() {
            val n = name ?: return
            if (n.startsWith("wl") && valid(n)) {
                val internal = !Root.run("readlink -f /sys/class/net/$n/device 2>/dev/null").out.contains("/usb")
                val dual = phy >= 0 &&
                    tools.exec("iw phy$phy info 2>/dev/null").contains("Band 2:")
                out.add(Iface(n, dual, internal, mode))
            }
            name = null; phy = -1; mode = "?"
        }
        for (raw in dev.lineSequence()) {
            val l = raw.trim()
            when {
                l.startsWith("phy#") -> phy = l.removePrefix("phy#").toIntOrNull() ?: -1
                l.startsWith("Interface ") -> { flush(); name = l.removePrefix("Interface ").trim() }
                l.startsWith("type ") -> mode = l.removePrefix("type ").trim()
                l.startsWith("wiphy ") -> l.removePrefix("wiphy ").trim().toIntOrNull()?.let { phy = it }
            }
        }
        flush()
        if (out.isNotEmpty()) return out
        // Fallback: iw gave nothing (missing/old). List wl* from sysfs.
        return Root.run("ls /sys/class/net 2>/dev/null").out.lineSequence()
            .map { it.trim() }.filter { it.startsWith("wl") && valid(it) }
            .map { n ->
                val internal = !Root.run("readlink -f /sys/class/net/$n/device 2>/dev/null").out.contains("/usb")
                Iface(n, false, internal, "?")
            }.toList()
    }

    /** `type` of an interface right now, or "" if it can't be read. */
    fun mode(tools: WifiTools, iface: String): String {
        if (!valid(iface)) return ""
        return tools.exec("iw dev $iface info 2>/dev/null").lineSequence()
            .map { it.trim() }.firstOrNull { it.startsWith("type ") }
            ?.removePrefix("type ")?.trim().orEmpty()
    }

    /** Poll [mode] until it reports [want] or the tries run out — the interface
     *  takes a moment to report its new type after `ip link up`. */
    private fun waitMode(tools: WifiTools, iface: String, want: String, tries: Int = 8): String {
        var m = ""
        repeat(tries) {
            m = mode(tools, iface)
            if (m == want) return m
            try { Thread.sleep(400) } catch (_: InterruptedException) {}
        }
        return m
    }

    /** Global con_mode sysfs path (qcacld), or "" if the driver doesn't expose one. */
    private fun conMode(): String =
        Root.run("find /sys/module -name con_mode 2>/dev/null | head -n 1").out.trim()

    /** The wl* interface currently in monitor mode (one cheap `iw dev` scan), or null. */
    private fun monitorIfaceNow(tools: WifiTools): String? {
        var name: String? = null
        for (raw in tools.exec("iw dev 2>/dev/null").lineSequence()) {
            val l = raw.trim()
            when {
                l.startsWith("Interface ") -> name = l.removePrefix("Interface ").trim()
                l == "type monitor" -> name?.takeIf { it.startsWith("wl") }?.let { return it }
            }
        }
        return null
    }

    private fun waitMonitorIface(tools: WifiTools, tries: Int = 8): String? {
        repeat(tries) {
            monitorIfaceNow(tools)?.let { return it }
            try { Thread.sleep(400) } catch (_: InterruptedException) {}
        }
        return null
    }

    /**
     * Enable monitor mode for [iface]. Internal qcacld radios go through con_mode=4,
     * which lands monitor on whichever vif the driver exposes (usually wlan0), not
     * necessarily the selected one — so the actual monitor interface is detected and
     * returned in [Result.monIface]. A USB adapter uses `iw set type monitor` on the
     * selected interface directly.
     */
    fun enableMonitor(tools: WifiTools, iface: String, internal: Boolean): Result {
        if (!valid(iface)) return Result(false, "", iface, "invalid interface name")
        val cm = if (internal) conMode() else ""
        if (cm.isNotEmpty()) {
            // Take the framework out of the way first, or it keeps the STA interface up and
            // fights the con_mode switch. svc wifi disable → down → con_mode=4 → up.
            // Redirect svc's stdin/stdout/stderr or the detached Wi-Fi service inherits the
            // pipe and Root.run blocks forever waiting for EOF (it hung the UI on "Enabling…").
            Root.run("svc wifi disable >/dev/null 2>&1 </dev/null")
            Root.run("ip link set $iface down 2>&1; echo 4 > $cm 2>&1; ip link set $iface up 2>&1")
            val mon = waitMonitorIface(tools)
            return Result(mon != null, if (mon != null) "monitor" else "",
                mon ?: iface, "via con_mode ($cm) → ${mon ?: "none"}")
        }
        Root.run("ip link set $iface down 2>&1")
        tools.exec("iw dev $iface set type monitor 2>&1")
        Root.run("ip link set $iface up 2>&1")
        val now = waitMode(tools, iface, "monitor")
        return Result(now == "monitor", now, iface, "via iw set type monitor")
    }

    /**
     * Restore [iface] to managed and bring normal Wi-Fi back. con_mode=0 first (if
     * present), then reset to managed, then `svc wifi enable`.
     */
    fun disableMonitor(tools: WifiTools, iface: String): Result {
        if (!valid(iface)) return Result(false, "", iface, "invalid interface name")
        val cm = conMode()
        // Mirror of the enable path. The chip went monitor via con_mode while the Wi-Fi
        // framework still thought the STA interface was up — so just resetting con_mode and
        // calling `svc wifi enable` leaves the framework convinced nothing changed and the
        // station interface is never rebuilt (this is why disable "did nothing" before).
        // Toggle the framework OFF, reset con_mode with the interface down, then back ON so
        // the framework re-initialises wlan0 in station mode from scratch.
        Root.run("svc wifi disable >/dev/null 2>&1 </dev/null")
        Root.run("ip link set $iface down 2>&1")
        if (cm.isNotEmpty()) Root.run("echo 0 > $cm 2>&1")
        tools.exec("iw dev $iface set type managed 2>&1")
        Root.run("svc wifi enable >/dev/null 2>&1 </dev/null")
        val now = waitMode(tools, iface, "managed")
        return Result(now != "monitor", now, iface, "svc wifi cycle + con_mode=0")
    }

    data class Result(val ok: Boolean, val mode: String, val monIface: String, val log: String)
}
