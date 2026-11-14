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

import org.ghostwire.Card

/**
 * Decides whether a saved [Card] can be emulated by the phone's own NFC, and
 * holds the one card that is currently armed for [GhostApduService] to serve.
 *
 * Host card emulation on this (NXP) controller reaches only the ISO-DEP /
 * Type-4 APDU layer, so the single faithful path is replaying a card's NDEF
 * message as an NFC Forum Type-4 tag. The controller assigns its own UID in
 * listen mode and runs MIFARE Classic crypto1 only inside the locked secure
 * element, so a captured UID, a MIFARE Classic dump, a raw Type-2 page dump or
 * a FeliCa IDm cannot be reproduced host-side — [plan] says so per card rather
 * than emulating something that silently won't match.
 */
object CardEmulator {

    enum class Mode { NDEF, NONE }

    /** [mode] NDEF when the card can be served as a Type-4 tag; NONE otherwise,
     *  with [reason] a user-facing explanation. [bytes] is the NDEF message. */
    data class Plan(val mode: Mode, val reason: String, val bytes: ByteArray? = null)

    @Volatile private var armedSession: Type4.Session? = null
    @Volatile var armedName: String? = null
        private set

    fun plan(card: Card): Plan {
        hexToBytes(card.ndefRaw)?.takeIf { it.isNotEmpty() }?.let {
            return Plan(Mode.NDEF, "NDEF payload (${it.size} B) served as a Type-4 tag", it)
        }
        val t = card.techList.joinToString(",") { it.lowercase() }
        val reason = when {
            "mifareclassic" in t ->
                "MIFARE Classic can't be emulated by the phone: its crypto1/UID logic lives in the " +
                "locked secure element, with no host (HCE) path. Clone it to a magic tag instead."
            "nfcf" in t ->
                "FeliCa host emulation (HCE-F) can only present an 02FE-prefixed NFCID2, so this " +
                "card's real IDm can't be replayed."
            "mifareultralight" in t || "nfca" in t || "nfcv" in t ->
                "No NDEF payload was captured. Host emulation can replay Type-4/NDEF content only — " +
                "a raw UID or a Type-2/15693 page dump can't. Clone it to a tag instead."
            else ->
                "This card has no NDEF payload to replay, and its low-level tech isn't reachable by " +
                "host emulation on this controller."
        }
        return Plan(Mode.NONE, reason)
    }

    /** Arms [card] if it is emulable; returns the plan either way. */
    fun arm(card: Card): Plan {
        val p = plan(card)
        if (p.mode == Mode.NDEF && p.bytes != null) {
            armedSession = Type4.Session(Type4.Prepared(p.bytes))
            armedName = card.name
        }
        return p
    }

    fun disarm() {
        armedSession = null
        armedName = null
    }

    fun isArmed(): Boolean = armedSession != null

    /** Read by [GhostApduService] on the NFC binder thread. */
    fun session(): Type4.Session? = armedSession

    /** Tolerant hex parse (ignores spaces/colons); null on odd or bad input. */
    private fun hexToBytes(s: String?): ByteArray? {
        if (s.isNullOrBlank()) return null
        val h = s.filter { !it.isWhitespace() && it != ':' }
        if (h.length % 2 != 0) return null
        return runCatching {
            ByteArray(h.length / 2) { ((h[it * 2].digitToInt(16) shl 4) or h[it * 2 + 1].digitToInt(16)).toByte() }
        }.getOrNull()
    }
}
