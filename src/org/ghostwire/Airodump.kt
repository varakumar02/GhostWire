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
 * Drive airodump-ng on a monitor interface and read back its CSV, the way wifite2
 * does (GPLv2 — the invocation and CSV layout are facts about airodump, not ported
 * code): airodump rewrites the CSV every second (`--write-interval 1`), and we poll
 * the file rather than scrape stdout. One session writes a `<prefix>-NN.{csv,cap}`
 * set in the tool's capture dir ([WifiTools.workDir]); the `.cap` feeds a handshake
 * check.
 *
 *   airodump-ng <iface> --background 1 -a -w <prefix> --write-interval 1
 *       [-c <ch> | --band abg] [--wps] [--bssid <b>] --output-format pcap,csv
 */
class Airodump(
    private val tools: WifiTools,
    private val iface: String,
    private val channel: Int? = null,
    private val bssid: String? = null,
    private val prefix: String = "gw",
) {
    /** Launch airodump detached; the process keeps rewriting the CSV. */
    fun start(): Boolean {
        if (!WifiIface.valid(iface)) return false
        tools.exec("rm -f ${prefix}-*.csv ${prefix}-*.cap ${prefix}-*.kismet* 2>/dev/null")
        val chan = if (channel != null && channel > 0) "-c $channel" else "--band abg"
        val target = bssid?.takeIf { it.matches(MAC) }?.let { "--bssid $it" } ?: ""
        tools.exec(
            "airodump-ng $iface --background 1 -a -w $prefix --write-interval 1 " +
                "$chan $target --wps --output-format pcap,csv",
            bg = true
        )
        return true
    }

    /** Stop every airodump this session started (matched by interface + prefix). */
    fun stop() {
        Root.run("pkill -f 'airodump-ng $iface .*-w $prefix' 2>/dev/null; " +
            "pkill -INT -f 'airodump-ng $iface' 2>/dev/null")
    }

    /** Android path of the capture file beside the CSV, for handshake checks. */
    fun capPath(): String = tools.newest("${prefix}-*.cap")

    /** Read the current CSV and parse it. Null until airodump writes one. */
    fun poll(): Parsed? {
        val csv = Root.run("cat \"$(ls -1t ${tools.workDir}/${prefix}-*.csv 2>/dev/null | head -n 1)\" 2>/dev/null").out
        if (csv.isBlank()) return null
        return parse(csv)
    }

    data class Parsed(val aps: List<Ap>, val stations: List<Station>)

    companion object {
        private val MAC = Regex("^[0-9A-Fa-f:]{17}$")

        /**
         * Parse an airodump CSV. Two sections: an AP block from the `BSSID` header
         * and a station block from `Station MAC`. Field indices match airodump: AP
         * 0 BSSID, 3 channel, 5 privacy, 7 auth, 8 power, 9 beacons, 10 #IV, 13
         * ESSID; station 0 MAC, 3 power, 4 packets, 5 associated BSSID.
         */
        fun parse(csv: String): Parsed {
            val aps = ArrayList<Ap>()
            val stations = ArrayList<Station>()
            var inStations = false
            for (raw in csv.lineSequence()) {
                val line = raw.replace("\u0000", "").trim()
                if (line.isEmpty()) continue
                val f = line.split(",").map { it.trim() }
                when {
                    f[0] == "BSSID" -> { inStations = false; continue }
                    f[0] == "Station MAC" -> { inStations = true; continue }
                }
                if (!inStations) {
                    if (f.size < 14 || !f[0].matches(MAC)) continue
                    aps.add(Ap(f[0].uppercase()).apply {
                        channel = f[3].toIntOrNull() ?: -1
                        val privacy = f[5]
                        enc = when {
                            "WPA3" in privacy -> "WPA3"
                            "WPA2" in privacy -> "WPA2"
                            "WPA" in privacy -> "WPA"
                            "WEP" in privacy -> "WEP"
                            "OWE" in privacy -> "OWE"
                            privacy.isBlank() || privacy == "OPN" -> "OPEN"
                            else -> privacy.split(" ").firstOrNull { it.isNotBlank() } ?: "?"
                        }
                        auth = when (val a = f[7]) { "SAE", "PSK", "MGT", "OWE" -> a; else -> "" }
                        protocols = Wifi.protocolsFromCsv(privacy, auth, wps)
                        power = f[8].toIntOrNull()?.takeIf { it != -1 } ?: 0
                        beacons = f[9].toLongOrNull() ?: 0
                        ivs = f.getOrNull(10)?.toLongOrNull() ?: 0
                        val name = f.getOrNull(13).orEmpty()
                        essid = name.takeIf { it.isNotBlank() && it.any { c -> c != '\u0000' } }
                    })
                } else {
                    if (f.size < 6 || !f[0].matches(MAC)) continue
                    if ("not associated" in f[5].lowercase()) continue
                    stations.add(Station(f[0].uppercase()).apply {
                        power = f[3].toIntOrNull()?.takeIf { it != -1 } ?: 0
                        packets = f[4].toLongOrNull() ?: 0
                        bssid = f[5].uppercase()
                    })
                }
            }
            return Parsed(aps, stations)
        }
    }
}
