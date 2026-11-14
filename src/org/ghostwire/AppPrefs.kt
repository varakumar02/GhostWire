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

import android.content.Context

/** App-wide switches that more than one screen reads. */
object AppPrefs {
    private const val KEY_MUTED = "nfc_sound_muted"

    private fun prefs(ctx: Context) = ctx.getSharedPreferences("ghostwire", Context.MODE_PRIVATE)

    /** True: NFC reads run with FLAG_READER_NO_PLATFORM_SOUNDS (no tap beep). */
    fun muted(ctx: Context): Boolean = prefs(ctx).getBoolean(KEY_MUTED, false)

    fun setMuted(ctx: Context, on: Boolean) = prefs(ctx).edit().putBoolean(KEY_MUTED, on).apply()
}
