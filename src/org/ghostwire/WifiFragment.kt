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

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.wifi.WifiManager
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.LinearLayout
import android.widget.Spinner
import android.widget.TextView
import androidx.fragment.app.Fragment
import com.google.android.material.dialog.MaterialAlertDialogBuilder

/**
 * Wi-Fi tab. Two scan paths over one table:
 *  - managed: a passive WifiManager scan (no root, no binaries) — always available;
 *  - monitor: airodump-ng on the chosen interface, polling its CSV like wifite2.
 *
 * Monitor mode is toggled with the NetHunter-style logic in [WifiIface] on the
 * interface picked in the spinner (internal qcacld via con_mode, USB via iw). The
 * aircrack-ng binaries are bundled (see [WifiTools]); without them the monitor and
 * attack actions explain what to install and the passive scan still works.
 *
 * Active actions (deauth, handshake capture) sit behind a confirm dialog — they are
 * for interfaces you are authorised to test.
 */
class WifiFragment : Fragment() {

    private lateinit var ifaceSpinner: Spinner
    private lateinit var monBtn: Button
    private lateinit var scanBtn: Button
    private lateinit var status: TextView
    private lateinit var list: LinearLayout
    private lateinit var tools: WifiTools

    private var ifaces: List<WifiIface.Iface> = emptyList()
    private val aps = LinkedHashMap<String, Ap>()
    private val expanded = HashSet<String>()

    private var scanning = false
    private var monitorIface: String? = null
    private var airodump: Airodump? = null
    private var poller: Thread? = null

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, s: Bundle?): View =
        inflater.inflate(R.layout.fragment_wifi, container, false)

    override fun onViewCreated(view: View, s: Bundle?) {
        tools = WifiTools(requireContext())
        ifaceSpinner = view.findViewById(R.id.wifi_iface)
        monBtn = view.findViewById(R.id.wifi_monitor)
        scanBtn = view.findViewById(R.id.wifi_scan)
        status = view.findViewById(R.id.wifi_status)
        list = view.findViewById(R.id.wifi_list)
        view.findViewById<Button>(R.id.wifi_refresh).setOnClickListener { refreshIfaces() }
        monBtn.setOnClickListener { toggleMonitor() }
        scanBtn.setOnClickListener { if (scanning) stop() else start() }
        Thread { tools.ensure() }.start()
        refreshIfaces()
    }

    private fun selectedIface(): WifiIface.Iface? =
        ifaces.getOrNull(ifaceSpinner.selectedItemPosition)

    private fun refreshIfaces() {
        status.text = "Enumerating interfaces…"
        Thread {
            val found = WifiIface.list()
            if (!isAdded) return@Thread
            ifaces = found
            ifaceSpinner.post {
                if (!isAdded) return@post
                ifaceSpinner.adapter = ArrayAdapter(
                    requireContext(), android.R.layout.simple_spinner_dropdown_item,
                    if (found.isEmpty()) listOf("(no wireless interfaces)") else found.map { it.label() }
                )
                monitorIface = found.firstOrNull { it.mode == "monitor" }?.name
                syncMonButton()
                status.text = if (found.isEmpty())
                    "No wlan interfaces. Root required; attach an OTG adapter for an external radio."
                else "${found.size} interface(s). Tools:\n${tools.report()}"
            }
        }.start()
    }

    private fun syncMonButton() {
        val mon = monitorIface != null
        monBtn.text = if (mon) "Disable monitor" else "Enable monitor"
    }

    private fun toggleMonitor() {
        val mon = monitorIface
        if (mon != null) {
            status.text = "Disabling monitor on $mon…"
            Thread {
                val r = WifiIface.disableMonitor(mon)
                if (!isAdded) return@Thread
                monitorIface = if (r.ok) null else mon
                status.post {
                    syncMonButton()
                    status.text = (if (r.ok) "Monitor off, Wi-Fi restored." else "Disable failed.") +
                        "\n${r.log.trim()}"
                }
            }.start()
            return
        }
        val iface = selectedIface() ?: run { status.text = "Pick an interface first."; return }
        MaterialAlertDialogBuilder(requireContext())
            .setTitle("Enable monitor on ${iface.name}?")
            .setMessage(
                (if (iface.internal)
                    "This switches the phone's own radio (qcacld con_mode) into monitor mode. " +
                        "Normal Wi-Fi drops until you disable it. On this device monitor mode on the " +
                        "internal chip has crashed once before — an OTG USB adapter is safer. "
                else
                    "This switches the USB adapter ${iface.name} into monitor mode via iw. ") +
                    "Use only on networks you are authorised to test."
            )
            .setPositiveButton("Enable") { _, _ ->
                status.text = "Enabling monitor on ${iface.name}…"
                Thread {
                    val r = WifiIface.enableMonitor(iface.name, iface.internal)
                    if (!isAdded) return@Thread
                    monitorIface = if (r.ok) iface.name else null
                    status.post {
                        syncMonButton()
                        status.text = (if (r.ok) "Monitor on (${iface.name}, mode=${r.mode})."
                        else "Enable failed (mode=${r.mode}).") + "\n${r.log.trim()}"
                    }
                }.start()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun start() {
        aps.clear(); expanded.clear(); list.removeAllViews()
        scanning = true
        scanBtn.text = "Stop"
        val mon = monitorIface
        if (mon != null) startAirodump(mon) else startPassive()
    }

    private fun stop() {
        scanning = false
        scanBtn.text = "Scan"
        poller?.interrupt(); poller = null
        airodump?.let { ad -> Thread { ad.stop() }.start() }; airodump = null
        runCatching { requireContext().unregisterReceiver(scanRx) }
        status.text = "Stopped — ${aps.size} AP(s)."
    }

    // ---- passive WifiManager scan (managed mode) ------------------------------

    private val wifiMgr by lazy {
        requireContext().getSystemService(WifiManager::class.java)
    }

    @SuppressLint("MissingPermission")
    private fun startPassive() {
        status.text = "Passive scan (WifiManager) — enable monitor for airodump capture."
        Root.run("pm grant org.ghostwire android.permission.ACCESS_FINE_LOCATION 2>&1")
        val f = IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION)
        androidx.core.content.ContextCompat.registerReceiver(
            requireContext(), scanRx, f, androidx.core.content.ContextCompat.RECEIVER_EXPORTED
        )
        passiveResults()
        runCatching { @Suppress("DEPRECATION") wifiMgr?.startScan() }
    }

    private val scanRx = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) { passiveResults() }
    }

    @SuppressLint("MissingPermission")
    private fun passiveResults() {
        val results = runCatching { wifiMgr?.scanResults }.getOrNull() ?: return
        for (r in results) {
            @Suppress("DEPRECATION") val ssid = r.SSID
            val ap = aps.getOrPut(r.BSSID.uppercase()) { Ap(r.BSSID.uppercase()) }
            ap.channel = Wifi.channel(r.frequency)
            ap.power = r.level
            ap.essid = ssid?.takeIf { it.isNotBlank() }
            val sec = Wifi.security(r.capabilities)
            ap.enc = sec.enc; ap.auth = sec.auth; ap.pmf = sec.pmf; ap.wps = sec.wps
            ap.lastSeen = System.currentTimeMillis()
        }
        render()
        if (scanning && monitorIface == null)
            list.postDelayed({ if (scanning) { runCatching { @Suppress("DEPRECATION") wifiMgr?.startScan() } } }, 4000)
    }

    // ---- airodump scan (monitor mode) -----------------------------------------

    private fun startAirodump(iface: String) {
        status.text = "airodump-ng on $iface …"
        Thread {
            if (!tools.ensure()) {
                if (!isAdded) return@Thread
                status.post {
                    scanning = false; scanBtn.text = "Scan"
                    status.text = "aircrack-ng binaries not installed.\n${tools.report()}\n" +
                        "Drop aarch64 builds into assets/wifi/bin (+libs in assets/wifi/lib)."
                }
                return@Thread
            }
            val ad = Airodump(tools, iface).also { airodump = it }
            ad.start()
            poller = Thread {
                while (!Thread.currentThread().isInterrupted && scanning) {
                    val parsed = ad.poll()
                    if (parsed != null) mergeAirodump(parsed)
                    try { Thread.sleep(1000) } catch (_: InterruptedException) { break }
                }
            }.also { it.start() }
        }.start()
    }

    private fun mergeAirodump(p: Airodump.Parsed) {
        for (na in p.aps) {
            val ap = aps.getOrPut(na.bssid) { Ap(na.bssid) }
            ap.channel = na.channel; ap.enc = na.enc; ap.auth = na.auth
            ap.power = na.power; ap.beacons = na.beacons; ap.ivs = na.ivs
            if (na.essid != null) ap.essid = na.essid
            ap.wps = ap.wps || na.wps
            ap.lastSeen = System.currentTimeMillis()
        }
        for (st in p.stations) {
            val ap = aps[st.bssid] ?: continue
            ap.clients[st.mac] = st.also { it.lastSeen = System.currentTimeMillis() }
        }
        render()
    }

    // ---- table render ---------------------------------------------------------

    private fun render() {
        val sorted = aps.values.sortedByDescending { it.power.takeIf { p -> p != 0 } ?: -999 }
        list.post {
            if (!isAdded) return@post
            list.removeAllViews()
            val mode = if (monitorIface != null) "monitor" else "passive"
            status.text = "${if (scanning) "Scanning ($mode)" else "Stopped"} — ${sorted.size} AP(s)"
            for (ap in sorted) list.addView(row(ap))
        }
    }

    private fun row(ap: Ap): View = TextView(requireContext()).apply {
        setPadding(0, 10, 0, 10)
        typeface = android.graphics.Typeface.MONOSPACE
        textSize = 13f
        text = if (expanded.contains(ap.bssid)) detail(ap) else summary(ap)
        setOnClickListener {
            if (!expanded.add(ap.bssid)) expanded.remove(ap.bssid)
            text = if (expanded.contains(ap.bssid)) detail(ap) else summary(ap)
        }
        setOnLongClickListener { actions(ap); true }
    }

    private fun summary(ap: Ap): String {
        val wps = if (ap.wps) " WPS" else ""
        val cli = if (ap.clients.isNotEmpty()) " ·${ap.clients.size}cli" else ""
        return "%s  CH%-3d %-7s  %-20s%s%s ▸".format(
            Wifi.powerBar(ap.power), ap.channel, ap.encLabel(),
            ap.name().take(20), wps, cli
        )
    }

    private fun detail(ap: Ap): String = buildString {
        appendLine("${ap.name()}  ▾")
        appendLine("  bssid   : ${ap.bssid}")
        appendLine("  channel : ${ap.channel}    power: ${ap.power} dBm")
        appendLine("  enc     : ${ap.encLabel()}   beacons: ${ap.beacons}   ivs: ${ap.ivs}")
        if (ap.wps) appendLine("  wps     : yes")
        if (ap.clients.isNotEmpty()) {
            appendLine("  clients :")
            ap.clients.values.sortedByDescending { it.power }.forEach {
                appendLine("     ${it.mac}  ${it.power} dBm  ${it.packets} pkts")
            }
        }
        append("  (long-press for actions)")
    }

    /** Long-press actions on an AP — gated active operations. */
    private fun actions(ap: Ap) {
        val mon = monitorIface
        if (mon == null) {
            status.text = "Enable monitor mode first for capture/deauth."
            return
        }
        val items = arrayOf("Capture WPA handshake (deauth + wait)", "Deauth (burst)")
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(ap.name())
            .setItems(items) { _, which ->
                confirmActive(ap) {
                    when (which) {
                        0 -> captureHandshake(mon, ap)
                        1 -> deauth(mon, ap)
                    }
                }
            }
            .show()
    }

    private fun confirmActive(ap: Ap, go: () -> Unit) {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle("Authorised testing only")
            .setMessage("This sends frames at ${ap.name()} (${ap.bssid}). Only do this on a network " +
                "you own or are authorised to test.")
            .setPositiveButton("Proceed") { _, _ -> go() }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun deauth(iface: String, ap: Ap) {
        status.text = "Deauthing ${ap.name()}…"
        Thread {
            val out = tools.deauth(iface, ap.bssid, null)
            if (isAdded) status.post { status.text = "Deauth sent to ${ap.bssid}\n${out.trim()}" }
        }.start()
    }

    private fun captureHandshake(iface: String, ap: Ap) {
        status.text = "Capturing handshake for ${ap.name()} (up to 60 s)…"
        Thread {
            val ch = ap.channel.takeIf { it > 0 }
            val ad = Airodump(tools, iface, ch, ap.bssid, prefix = "hs")
            ad.start()
            var got: Boolean? = false
            val deadline = System.currentTimeMillis() + 60_000
            while (System.currentTimeMillis() < deadline && isAdded) {
                try { Thread.sleep(5000) } catch (_: InterruptedException) { break }
                tools.deauth(iface, ap.bssid, ap.clients.keys.firstOrNull(), bursts = 3)
                got = tools.hasHandshake(ad.capPath(), ap.bssid)
                if (got == true) break
            }
            val cap = ad.capPath()
            ad.stop()
            if (isAdded) status.post {
                status.text = when (got) {
                    true -> "Handshake captured ✓\n$cap"
                    false -> "No handshake in 60 s. Retry when a client is connected."
                    null -> "Capture saved ($cap) but no detector tool bundled " +
                        "(tshark/hcxpcapngtool) to confirm the handshake."
                }
            }
        }.start()
    }

    override fun onPause() {
        super.onPause()
        if (scanning) stop()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        if (scanning) stop()
    }
}
