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
 * Shared Wi-Fi model + render helpers used by both the passive WifiManager scan
 * and the airodump-driven monitor scan. Fields mirror what airodump's CSV carries
 * (BSSID, channel, encryption, power, beacons, IVs, ESSID, and per-AP stations);
 * the airodump power quirk (AP values are stored by wifite as dBm+100) is dropped
 * here — [power] is always raw dBm so passive and monitor rows read the same.
 */

/** One access point, merged across successive reads (CSV polls or scan callbacks). */
class Ap(val bssid: String) {
    var channel: Int = -1
    var enc: String = ""        // WPA3 / WPA2 / WPA / WEP / OWE / OPEN
    var auth: String = ""       // SAE / PSK / MGT / OWE / ""
    var pmf: Int = 0            // 0 none, 1 optional, 2 required
    var power: Int = 0          // raw dBm (0 = unknown)
    var beacons: Long = 0
    var ivs: Long = 0
    var essid: String? = null   // null = hidden
    var wps: Boolean = false
    var protocols: String = ""  // full flag set: "WPA2/WPA3 PSK WPS PMF~"
    var lastSeen: Long = 0
    val clients = LinkedHashMap<String, Station>()

    /** Short encryption label with wifite-style suffixes. */
    fun encLabel(): String {
        val a = when (auth) { "PSK" -> "-P"; "MGT" -> "-E"; else -> "" }
        val p = when (pmf) { 2 -> "+"; 1 -> "~"; else -> "" }
        return (enc.ifBlank { "?" }) + a + p
    }

    /** Full protocol flags for the row — the complete set, not just the primary enc. */
    fun protoLabel(): String = protocols.ifBlank { encLabel() }

    fun name(): String = essid ?: "($bssid)"
}

/** One station/client seen in the air. */
class Station(val mac: String) {
    var power: Int = 0          // raw dBm
    var packets: Long = 0
    var bssid: String = ""      // associated AP, or "" / not-associated
    var lastSeen: Long = 0
}

object Wifi {

    /** 2.4 / 5 / 6 GHz band label from a centre frequency in MHz. */
    fun band(freqMhz: Int): String = when {
        freqMhz in 2400..2500 -> "2.4"
        freqMhz in 4900..5900 -> "5"
        freqMhz >= 5925 -> "6"
        else -> "?"
    }

    /** IEEE channel number from a centre frequency in MHz. */
    fun channel(freqMhz: Int): Int = when {
        freqMhz == 2484 -> 14
        freqMhz in 2412..2472 -> (freqMhz - 2407) / 5
        freqMhz in 5160..5885 -> (freqMhz - 5000) / 5
        freqMhz in 5955..7115 -> (freqMhz - 5950) / 5       // 6 GHz
        else -> -1
    }

    /**
     * Parse a WifiManager ScanResult.capabilities string into (enc, auth, pmf, wps).
     * e.g. "[WPA2-PSK-CCMP][RSN-SAE-CCMP][ESS][WPS]".
     */
    fun security(caps: String): Quad {
        val c = caps.uppercase()
        val enc = when {
            "WPA3" in c || "SAE" in c -> "WPA3"
            "RSN" in c || "WPA2" in c -> "WPA2"
            "WPA" in c -> "WPA"
            "WEP" in c -> "WEP"
            "OWE" in c -> "OWE"
            else -> "OPEN"
        }
        val auth = when {
            "SAE" in c -> "SAE"
            "EAP" in c || "MGT" in c -> "MGT"
            "PSK" in c -> "PSK"
            "OWE" in c -> "OWE"
            else -> ""
        }
        val pmf = when {
            "MFPR" in c -> 2
            "MFPC" in c -> 1
            else -> 0
        }
        return Quad(enc, auth, pmf, "WPS" in c)
    }

    data class Quad(val enc: String, val auth: String, val pmf: Int, val wps: Boolean)

    /**
     * Full protocol flag set from a WifiManager capabilities string, e.g.
     * "[WPA2-PSK-CCMP][RSN-SAE-CCMP][ESS][WPS][MFPC]" -> "WPA2/WPA3 PSK/SAE WPS PMF~".
     * Unlike [security], this keeps every key-mgmt family the AP advertises (a mixed
     * WPA+WPA2 or WPA2+WPA3 AP shows both).
     */
    fun protocols(caps: String): String {
        val c = caps.uppercase()
        val families = ArrayList<String>()
        if ("WPA3" in c || "SAE" in c) families += "WPA3"
        if ("RSN" in c || "WPA2" in c) families += "WPA2"
        if ("[WPA-" in c) families += "WPA"            // WPA1 tag, distinct from WPA2
        if ("WEP" in c) families += "WEP"
        if ("OWE" in c && families.isEmpty()) families += "OWE"
        if (families.isEmpty()) families += "OPEN"
        val auth = ArrayList<String>()
        if ("SAE" in c) auth += "SAE"
        if ("EAP" in c || "-MGT" in c) auth += "EAP"
        if ("PSK" in c) auth += "PSK"
        if ("OWE" in c) auth += "OWE"
        val out = ArrayList<String>()
        out += families.joinToString("/")
        if (auth.isNotEmpty()) out += auth.joinToString("/")
        if ("WPS" in c) out += "WPS"
        when { "MFPR" in c -> out += "PMF+"; "MFPC" in c -> out += "PMF~" }
        return out.joinToString(" ")
    }

    /** Full protocol flags from the airodump CSV privacy + auth columns (monitor path). */
    fun protocolsFromCsv(privacy: String, auth: String, wps: Boolean): String {
        val p = privacy.uppercase()
        val families = ArrayList<String>()
        if ("WPA3" in p) families += "WPA3"
        if ("WPA2" in p) families += "WPA2"
        if (Regex("(^|\\s)WPA($|\\s)").containsMatchIn(p)) families += "WPA"
        if ("WEP" in p) families += "WEP"
        if ("OWE" in p) families += "OWE"
        if (families.isEmpty()) families += if (p.isBlank() || "OPN" in p) "OPEN" else p.trim()
        val out = ArrayList<String>()
        out += families.joinToString("/")
        when (auth.uppercase()) {
            "SAE" -> out += "SAE"; "PSK" -> out += "PSK"; "MGT" -> out += "EAP"; "OWE" -> out += "OWE"
        }
        if (wps) out += "WPS"
        return out.joinToString(" ")
    }

    /** Three-cell signal bar + value, from raw dBm, mirroring wifite's PWR column. */
    fun powerBar(dbm: Int): String {
        if (dbm == 0) return "       "
        val q = dbm + 100          // -100..-20 dBm -> 0..80, matching airodump's quality
        val bars = when {
            q > 50 -> "▂▄▆"
            q > 35 -> "▂▄ "
            q > 20 -> "▂  "
            else -> "▁  "
        }
        return "%s %4d".format(bars, dbm)
    }
}
