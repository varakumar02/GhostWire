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

/**
 * NFC Forum Type-4 Tag emulation, host side. Pure Kotlin (no Android) so it can
 * be unit-checked — see [selfTest]. An armed card's NDEF message is served to a
 * reader over the Type-4 APDU state machine that Android HCE delivers to a
 * [android.nfc.cardemulation.HostApduService].
 *
 * Scope is deliberately read-only: UpdateBinary is refused. We replay what the
 * card held; we do not let a reader rewrite the emulated tag.
 */
object Type4 {
    // NDEF Tag Application AID (NFC Forum T4T).
    val NDEF_AID = byteArrayOf(0xD2.toByte(), 0x76, 0, 0, 0x85.toByte(), 0x01, 0x01)

    private const val CC_FID = 0xE103
    private const val NDEF_FID = 0xE104

    // Status words.
    private val OK = byteArrayOf(0x90.toByte(), 0x00)
    private val NOT_FOUND = byteArrayOf(0x6A, 0x82.toByte())
    private val WRONG_P1P2 = byteArrayOf(0x6A, 0x86.toByte())
    private val WRONG_LEN = byteArrayOf(0x67, 0x00)
    private val INS_UNSUP = byteArrayOf(0x6D, 0x00)
    private val CLA_UNSUP = byteArrayOf(0x6E, 0x00)
    private val NOT_ALLOWED = byteArrayOf(0x69, 0x85.toByte())

    /** The two files a reader walks: the Capability Container and the NDEF file
     *  (2-byte NLEN + message). Built once when a card is armed. */
    class Prepared(ndefMessage: ByteArray) {
        val ndefFile: ByteArray
        val cc: ByteArray

        init {
            val nlen = ndefMessage.size
            // NDEF file: NLEN (2) + message.
            ndefFile = ByteArray(2 + nlen).also {
                it[0] = (nlen ushr 8).toByte()
                it[1] = (nlen and 0xFF).toByte()
                ndefMessage.copyInto(it, 2)
            }
            // Max NDEF file size we advertise = the file we actually hold,
            // clamped to the spec minimum of 5 and a sane 0x7FFF ceiling.
            val maxFile = ndefFile.size.coerceIn(5, 0x7FFF)
            cc = byteArrayOf(
                0x00, 0x0F,             // CCLEN = 15
                0x20,                   // mapping version 2.0
                0x00, 0xFF.toByte(),    // MLe (max R-APDU data)
                0x00, 0xFF.toByte(),    // MLc (max C-APDU data)
                0x04, 0x06,             // NDEF File Control TLV: T=04, L=06
                (NDEF_FID ushr 8).toByte(), (NDEF_FID and 0xFF).toByte(),
                (maxFile ushr 8).toByte(), (maxFile and 0xFF).toByte(),
                0x00,                   // read access granted
                0xFF.toByte(),          // write access denied (read-only replay)
            )
        }
    }

    private enum class Sel { NONE, APP, CC, NDEF }

    /** One tap = one session; HCE calls [process] per received C-APDU and
     *  [reset] on deactivation. Not thread-safe by itself — HCE serialises
     *  calls on one card, and a single armed card has one session. */
    class Session(private val p: Prepared) {
        private var sel = Sel.NONE

        fun reset() { sel = Sel.NONE }

        fun process(apdu: ByteArray): ByteArray {
            if (apdu.size < 4) return WRONG_LEN
            val cla = apdu[0].toInt() and 0xFF
            val ins = apdu[1].toInt() and 0xFF
            val p1 = apdu[2].toInt() and 0xFF
            val p2 = apdu[3].toInt() and 0xFF
            if (cla != 0x00) return CLA_UNSUP
            return when (ins) {
                0xA4 -> select(p1, p2, apdu)
                0xB0 -> readBinary(p1, p2, apdu)
                0xD6 -> NOT_ALLOWED          // UpdateBinary: read-only emulation
                else -> INS_UNSUP
            }
        }

        private fun select(p1: Int, p2: Int, apdu: ByteArray): ByteArray {
            // SELECT by name (application / AID): P1=04.
            if (p1 == 0x04) {
                val lc = if (apdu.size > 4) apdu[4].toInt() and 0xFF else 0
                val name = if (apdu.size >= 5 + lc) apdu.copyOfRange(5, 5 + lc) else ByteArray(0)
                return if (name.contentEquals(NDEF_AID)) { sel = Sel.APP; OK } else NOT_FOUND
            }
            // SELECT by file id: P1=00, P2=0C, Lc=02, Data=FID.
            if (p1 == 0x00 && p2 == 0x0C) {
                val lc = if (apdu.size > 4) apdu[4].toInt() and 0xFF else 0
                if (lc != 2 || apdu.size < 7) return WRONG_LEN
                val fid = ((apdu[5].toInt() and 0xFF) shl 8) or (apdu[6].toInt() and 0xFF)
                return when (fid) {
                    CC_FID -> { sel = Sel.CC; OK }
                    NDEF_FID -> { sel = Sel.NDEF; OK }
                    else -> NOT_FOUND
                }
            }
            return WRONG_P1P2
        }

        private fun readBinary(p1: Int, p2: Int, apdu: ByteArray): ByteArray {
            val file = when (sel) {
                Sel.CC -> p.cc
                Sel.NDEF -> p.ndefFile
                else -> return NOT_ALLOWED       // no file selected
            }
            val offset = (p1 shl 8) or p2
            // Le is the last byte; 0 means "up to 256".
            val le = if (apdu.size >= 5) (apdu[apdu.size - 1].toInt() and 0xFF).let { if (it == 0) 256 else it } else 0
            if (offset > file.size) return WRONG_P1P2
            val n = minOf(le, file.size - offset)
            val out = ByteArray(n + 2)
            file.copyInto(out, 0, offset, offset + n)
            OK.copyInto(out, n)
            return out
        }
    }

    // --- self-check (pure, no Android) --------------------------------------

    private fun sw(r: ByteArray) = ((r[r.size - 2].toInt() and 0xFF) shl 8) or (r[r.size - 1].toInt() and 0xFF)
    private fun body(r: ByteArray) = r.copyOfRange(0, r.size - 2)

    /**
     * Drives the standard reader walk (SELECT app, SELECT CC, read CC,
     * SELECT NDEF, read NLEN, read message) and confirms the bytes served
     * back reconstruct the original NDEF message, plus a few error paths.
     * Returns true on success; called from a test or a debug build.
     */
    fun selfTest(): Boolean {
        val msg = byteArrayOf(            // one NDEF URI record: https://ghostwire
            0xD1.toByte(), 0x01, 0x0A, 0x55, 0x04,
            'g'.code.toByte(), 'h'.code.toByte(), 'o'.code.toByte(), 's'.code.toByte(),
            't'.code.toByte(), 'w'.code.toByte(), 'i'.code.toByte(), 'r'.code.toByte(), 'e'.code.toByte(),
        )
        val s = Session(Prepared(msg))

        fun hex(vararg b: Int) = ByteArray(b.size) { b[it].toByte() }

        // Wrong app first -> not found.
        if (sw(s.process(hex(0x00, 0xA4, 0x04, 0x00, 0x02, 0x11, 0x22))) != 0x6A82) return false
        // SELECT NDEF app.
        val selApp = ByteArray(5 + NDEF_AID.size + 1)
        hex(0x00, 0xA4, 0x04, 0x00, NDEF_AID.size).copyInto(selApp)
        NDEF_AID.copyInto(selApp, 5)
        if (sw(s.process(selApp)) != 0x9000) return false
        // Read before selecting a file -> refused.
        if (sw(s.process(hex(0x00, 0xB0, 0x00, 0x00, 0x02))) != 0x6985) return false
        // SELECT + read CC (15 bytes), check the NDEF file-id is advertised.
        if (sw(s.process(hex(0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03))) != 0x9000) return false
        val cc = s.process(hex(0x00, 0xB0, 0x00, 0x00, 0x0F))
        if (sw(cc) != 0x9000 || body(cc).size != 15) return false
        if ((body(cc)[9].toInt() and 0xFF) != 0xE1 || (body(cc)[10].toInt() and 0xFF) != 0x04) return false
        // SELECT NDEF file, read NLEN, read the message.
        if (sw(s.process(hex(0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04))) != 0x9000) return false
        val nlenR = s.process(hex(0x00, 0xB0, 0x00, 0x00, 0x02))
        if (sw(nlenR) != 0x9000) return false
        val nlen = ((body(nlenR)[0].toInt() and 0xFF) shl 8) or (body(nlenR)[1].toInt() and 0xFF)
        if (nlen != msg.size) return false
        val read = s.process(hex(0x00, 0xB0, 0x00, 0x02, nlen))
        if (sw(read) != 0x9000) return false
        if (!body(read).contentEquals(msg)) return false
        // UpdateBinary must be refused.
        if (sw(s.process(hex(0x00, 0xD6, 0x00, 0x02, 0x01, 0xAA))) != 0x6985) return false
        return true
    }
}
