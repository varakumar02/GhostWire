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

import android.nfc.cardemulation.HostApduService
import android.nfc.cardemulation.PollingFrame
import android.os.Bundle

/**
 * Serves the card armed in [CardEmulator] as an NFC Forum Type-4 tag. Android
 * routes a reader's APDUs here once it selects our NDEF application AID
 * (registered in res/xml/apduservice.xml). With nothing armed, every command
 * is refused, so the app never pretends to be a tag it was not asked to be.
 */
class GhostApduService : HostApduService() {

    private val notArmed = byteArrayOf(0x6A, 0x82.toByte()) // file/app not found

    override fun processCommandApdu(apdu: ByteArray?, extras: Bundle?): ByteArray {
        if (apdu == null) return notArmed
        val session = CardEmulator.session() ?: return notArmed
        return session.process(apdu)
    }

    /** Observe-mode frames (see [Sniffer]); also delivered while emulating. */
    override fun processPollingFrames(frames: List<PollingFrame>) = Sniffer.deliver(frames)

    override fun onDeactivated(reason: Int) {
        // Field lost or a different AID selected: reset the file-selection state
        // so the next tap starts a clean Type-4 walk. The card stays armed.
        CardEmulator.session()?.reset()
    }
}
