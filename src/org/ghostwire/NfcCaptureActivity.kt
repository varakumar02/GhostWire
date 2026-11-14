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

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity

/**
 * Invisible trampoline for auto-scan. The OS dispatches a tapped tag here
 * (TECH_DISCOVERED) only while this component is enabled, which
 * [AutoScanService] ties to the auto-scan toggle. It reads and saves the
 * card on a background thread and finishes at once — the translucent theme
 * means GhostWire's UI never comes to the foreground, so a tap in auto-scan
 * just adds a card silently in the background.
 */
class NfcCaptureActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        @Suppress("DEPRECATION")
        val tag = intent?.getParcelableExtra<Tag>(NfcAdapter.EXTRA_TAG)
        if (tag != null && AutoScanService.isEnabled(this)) {
            val app = applicationContext
            Thread {
                val card = runCatching { NfcCapture.read(tag, Mifare.allKeys(app)) }.getOrNull()
                if (card != null) {
                    val loc = Loc.last(app)
                    val saved = if (loc != null) card.copy(lat = loc.first, lon = loc.second) else card
                    val store = CardStore(app)
                    val list = store.load()
                    list.add(0, saved)
                    store.save(list)
                }
            }.start()
        }
        finish()
    }
}
