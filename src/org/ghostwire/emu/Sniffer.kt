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

package org.ghostwire.emu

import android.app.Activity
import android.content.ComponentName
import android.nfc.NfcAdapter
import android.nfc.cardemulation.CardEmulation
import android.nfc.cardemulation.PollingFrame

/**
 * Passive NFC sniffing through Android's Observe Mode. With observe mode on,
 * the controller stops answering readers and instead hands every polling-loop
 * frame it hears (REQA/WUPA, REQB, SENSF, ...) to [GhostApduService] as a
 * [PollingFrame]. It sees what a nearby reader transmits, not card replies.
 *
 * Needs the HAL to report observe-mode support; on the OP9 that is the
 * NXP_EXTENDED_FIELD_DETECT_MODE=0x03 line in libnfc-nxp.conf.
 */
object Sniffer {

    @Volatile var sink: ((String) -> Unit)? = null

    fun supported(nfc: NfcAdapter): Boolean = nfc.isObserveModeSupported

    /** Makes GhostApduService the preferred service, routes every polling frame
     *  to it and turns observe mode on. Returns an error string, or null. */
    fun start(activity: Activity, nfc: NfcAdapter, onFrame: (String) -> Unit): String? {
        if (!nfc.isEnabled) return "NFC is off"
        if (!nfc.isObserveModeSupported) return "the NFC HAL reports observe mode unsupported"
        val ce = CardEmulation.getInstance(nfc)
        val svc = ComponentName(activity, GhostApduService::class.java)
        sink = onFrame
        ce.setPreferredService(activity, svc)
        if (!nfc.setObserveModeEnabled(true)) {
            stop(activity, nfc)
            return "the NFC service refused to enable observe mode"
        }
        return null
    }

    fun stop(activity: Activity, nfc: NfcAdapter) {
        sink = null
        runCatching { nfc.setObserveModeEnabled(false) }
        val ce = CardEmulation.getInstance(nfc)
        val svc = ComponentName(activity, GhostApduService::class.java)
        runCatching { ce.unsetPreferredService(activity) }
    }

    /** Called on the NFC binder thread by GhostApduService. */
    fun deliver(frames: List<PollingFrame>) {
        val s = sink ?: return
        frames.forEach { s(format(it)) }
    }

    fun format(f: PollingFrame): String {
        val type = when (f.type) {
            PollingFrame.POLLING_LOOP_TYPE_A -> "A"
            PollingFrame.POLLING_LOOP_TYPE_B -> "B"
            PollingFrame.POLLING_LOOP_TYPE_F -> "F"
            PollingFrame.POLLING_LOOP_TYPE_ON -> "field-on"
            PollingFrame.POLLING_LOOP_TYPE_OFF -> "field-off"
            else -> "unknown"
        }
        val data = f.data.joinToString("") { "%02X".format(it) }
        val gain = f.vendorSpecificGain.takeIf { it >= 0 }?.let { " gain=$it" } ?: ""
        return "${f.timestamp}us $type${if (data.isEmpty()) "" else " $data"}$gain"
    }
}
