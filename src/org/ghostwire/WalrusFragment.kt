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

import android.Manifest
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.nfc.NfcAdapter
import android.os.Build
import android.nfc.Tag
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.ImageButton
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.FileProvider
import androidx.fragment.app.Fragment
import org.json.JSONArray
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.switchmaterial.SwitchMaterial
import org.ghostwire.emu.CardEmulator
import org.ghostwire.emu.Sniffer
import java.util.UUID

/**
 * Contactless lab: read a card with the phone's NFC, store it, browse the
 * wallet, and export. Card UI mirrors Walrus's layout (name header, logo,
 * info band) in GhostWire's Material theme. 13.56 MHz only — see [NfcCapture].
 */
class WalrusFragment : Fragment() {

    private lateinit var store: CardStore
    private val cards = ArrayList<Card>()
    private lateinit var adapter: CardAdapter
    private lateinit var status: TextView
    private var nfc: NfcAdapter? = null
    private var keys: List<ByteArray> = emptyList()
    @Volatile private var readerOn = false      // reader mode currently enabled
    @Volatile private var captureArmed = false  // user pressed "Read card" (one-shot save)
    @Volatile private var writeTarget: Card? = null

    private val importPicker =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            uri?.let { importFrom(it) }
        }

    private val notifPerm =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    private fun autoScan() = AutoScanService.isEnabled(requireContext())

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, s: Bundle?): View =
        inflater.inflate(R.layout.fragment_walrus, container, false)

    override fun onViewCreated(view: View, s: Bundle?) {
        store = CardStore(requireContext())
        cards.addAll(store.load())
        keys = Mifare.allKeys(requireContext())
        nfc = NfcAdapter.getDefaultAdapter(requireContext())
        status = view.findViewById(R.id.walrus_status)

        adapter = CardAdapter(cards, onClick = { showDetail(it) }, onWrite = { startWrite(it) },
            onEmulate = { startEmulate(it) })
        view.findViewById<RecyclerView>(R.id.card_list).also {
            it.layoutManager = LinearLayoutManager(requireContext())
            it.adapter = adapter
        }
        view.findViewById<Button>(R.id.card_read).setOnClickListener { startCapture() }
        view.findViewById<ImageButton>(R.id.card_share).setOnClickListener { exportCards() }
        view.findViewById<ImageButton>(R.id.card_import).setOnClickListener {
            importPicker.launch(arrayOf("*/*"))
        }
        view.findViewById<Button>(R.id.card_limits).setOnClickListener { showLimits() }
        view.findViewById<Button>(R.id.card_sniff).setOnClickListener { startSniff() }
        view.findViewById<Button>(R.id.card_bin).setOnClickListener { showBin() }
        view.findViewById<SwitchMaterial>(R.id.auto_scan).also { sw ->
            sw.isChecked = autoScan()
            sw.setOnCheckedChangeListener { _, on ->
                if (on) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                        notifPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
                    AutoScanService.start(requireContext())
                } else {
                    AutoScanService.stop(requireContext())
                }
                updateStatus()
            }
        }
        updateStatus()
    }

    override fun onResume() {
        super.onResume()
        // Hold reader mode the whole time this screen is up: it keeps NFC under
        // the app's control (so the OS plays no discovery sound, honouring the
        // mute toggle) and lets a tap be saved on demand. Saving still only
        // happens when capture is armed, a write is pending, or auto-scan is on.
        enableReader()
    }

    override fun onPause() {
        super.onPause()
        disableReader()
        CardEmulator.disarm()
        nfc?.let { Sniffer.stop(requireActivity(), it) }
    }

    /** Re-arm reader mode so a changed mute flag takes effect immediately. */
    fun onMuteChanged() {
        if (readerOn) { disableReader(); enableReader() }
    }

    private fun updateStatus() {
        status.text = when {
            nfc == null -> "NFC not available on this device"
            nfc?.isEnabled == false -> "NFC is off — enable it in system settings"
            CardEmulator.isArmed() -> "Emulating \"${CardEmulator.armedName}\" — hold the phone to a reader"
            writeTarget != null -> "Hold a blank/writable tag to the phone to write \"${writeTarget?.name}\"…"
            captureArmed -> "Tap a card to the phone…"
            else -> "${cards.size} card(s) saved"
        }
    }

    /** Arms a one-shot save: the next tap is captured and saved. */
    private fun startCapture() {
        captureArmed = true
        enableReader()
        updateStatus()
    }

    /** Arms write mode: the next tag tapped gets [card]'s data written to it. */
    private fun startWrite(card: Card) {
        writeTarget = card
        enableReader()
        updateStatus()
    }

    private fun enableReader() {
        val a = nfc ?: return
        if (!a.isEnabled) return
        a.enableReaderMode(
            requireActivity(), { tag -> onTag(tag) },
            NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or
                NfcAdapter.FLAG_READER_NFC_V or NfcAdapter.FLAG_READER_NFC_F or
                (if (AppPrefs.muted(requireContext())) NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS else 0),
            null,
        )
        readerOn = true
    }

    private fun disableReader() {
        if (readerOn) {
            readerOn = false
            runCatching { nfc?.disableReaderMode(requireActivity()) }
        }
        writeTarget = null
        captureArmed = false
    }

    // Runs on an NFC binder thread.
    private fun onTag(tag: Tag) {
        val target = writeTarget
        if (target != null) {
            val result = runCatching { NfcCapture.write(tag, target, keys) }
                .getOrElse { "write failed: ${it.message}" }
            activity?.runOnUiThread {
                writeTarget = null  // reader stays on
                status.text = result
            }
            return
        }
        // Only save when the user asked for it; otherwise swallow the tap (reader
        // mode already kept the OS from making a sound or launching a handler).
        if (!captureArmed && !autoScan()) {
            activity?.runOnUiThread { status.text = "card detected — press Read card to save it" }
            return
        }
        val card = runCatching {
            NfcCapture.read(tag, keys) { msg -> activity?.runOnUiThread { status.text = msg } }
        }.getOrNull()?.let {
            val loc = Loc.last(requireContext())
            if (loc != null) it.copy(lat = loc.first, lon = loc.second) else it
        }
        activity?.runOnUiThread {
            captureArmed = false  // one-shot consumed
            if (card != null) {
                cards.add(0, card)
                store.save(cards)
                adapter.notifyDataSetChanged()
                status.text = if (card.keys.isNotEmpty())
                    "saved — recovered ${card.keys.size} sector key(s) from the dictionary"
                else "${cards.size} card(s) saved"
            } else {
                updateStatus()
            }
        }
    }

    private fun exportCards() {
        if (cards.isEmpty()) {
            status.text = "nothing to export"
            return
        }
        val f = store.export(cards)
        val uri = FileProvider.getUriForFile(requireContext(), "org.ghostwire.fileprovider", f)
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "application/json"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_TITLE, f.name)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        startActivity(Intent.createChooser(send, "Share cards file"))
        status.text = "shared ${cards.size} card(s) — ${f.name}"
    }

    /** Merge a previously exported cards JSON into the wallet, skipping cards
     *  whose id is already present. */
    private fun importFrom(uri: Uri) {
        val text = runCatching {
            requireContext().contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
        }.getOrNull()
        val imported = text?.let {
            runCatching {
                val arr = JSONArray(it)
                List(arr.length()) { i -> Card.fromJson(arr.getJSONObject(i)) }
            }.getOrNull()
        }
        if (imported == null) {
            status.text = "import failed — not a valid cards file"
            return
        }
        val existing = cards.mapTo(HashSet()) { it.id }
        var added = 0
        imported.forEach { if (existing.add(it.id)) { cards.add(it); added++ } }
        store.save(cards)
        adapter.notifyDataSetChanged()
        status.text = "imported $added new card(s)"
    }

    /** Arms a saved card for host emulation (HCE). Only cards carrying an NDEF
     *  payload can be served as a Type-4 tag; anything else gets an honest
     *  explanation instead of a tag that would not match. */
    private fun startEmulate(card: Card) {
        if (nfc == null) {
            MaterialAlertDialogBuilder(requireContext())
                .setTitle("Emulate")
                .setMessage("This device has no NFC.")
                .setPositiveButton("OK", null)
                .show()
            return
        }
        // Reading and emulating can't run at once; drop reader mode first.
        disableReader()
        val plan = CardEmulator.arm(card)
        if (plan.mode != CardEmulator.Mode.NDEF) {
            MaterialAlertDialogBuilder(requireContext())
                .setTitle("Can't emulate this card")
                .setMessage(plan.reason)
                .setPositiveButton("OK", null)
                .show()
            updateStatus()
            return
        }
        updateStatus()
        MaterialAlertDialogBuilder(requireContext())
            .setTitle("Emulating \"${card.name}\"")
            .setMessage(
                "${plan.reason}.\n\n" +
                "Hold the phone flat against the reader. Emulation works while " +
                "GhostWire is open and the screen is on; a reader that checks the " +
                "card's UID or does MIFARE Classic auth won't be fooled — only the " +
                "NDEF content is replayed.",
            )
            .setCancelable(false)
            .setPositiveButton("Stop") { _, _ ->
                CardEmulator.disarm()
                enableReader()
                updateStatus()
            }
            .show()
    }

    /** Observe mode: list the polling frames nearby readers send until Stop. */
    private fun startSniff() {
        val a = nfc ?: return updateStatus()
        disableReader()
        CardEmulator.disarm()
        val view = LayoutInflater.from(requireContext()).inflate(R.layout.dialog_sniff, null)
        val log = view.findViewById<TextView>(R.id.sniff_log)
        log.text = "Listening — hold the phone near a reader…"
        val lines = ArrayDeque<String>()
        val err = Sniffer.start(requireActivity(), a) { line ->
            activity?.runOnUiThread {
                lines.addFirst(line)
                while (lines.size > 200) lines.removeLast()
                log.text = lines.joinToString("\n")
            }
        }
        if (err != null) {
            MaterialAlertDialogBuilder(requireContext())
                .setTitle("Sniff unavailable")
                .setMessage("Observe mode can't start: $err.")
                .setPositiveButton("OK", null)
                .show()
            return
        }
        MaterialAlertDialogBuilder(requireContext())
            .setView(view)
            .setCancelable(false)
            .setPositiveButton("Stop") { _, _ ->
                Sniffer.stop(requireActivity(), a)
                enableReader()
                updateStatus()
            }
            .show()
    }

    private fun showLimits() {
        val msg = """
            Phone NFC is 13.56 MHz only. Hard limits:

            • 125 kHz LF cards (HID Prox, EM4100, Indala): impossible on any phone — needs external hardware (Proxmark). [universal]

            • MIFARE Classic read: needs an NXP-class controller. This chip supports it; some (e.g. Broadcom) phones can't read Classic at all. [device-specific]

            • MIFARE Classic key cracking — nested / darkside / hardnested: NOT possible via Android NFC. The API never exposes the nonces/parity those attacks need (auth happens inside the controller). On-device cracking = dictionary only; real nonce attacks need a Proxmark/libnfc reader. [universal to phones]

            • Emulation (HCE): only NDEF/Type-4 cards can be replayed host-side — the "Emulate" action serves a saved card's NDEF payload as a Type-4 tag. MIFARE Classic, a captured UID and a raw Type-2 dump can't be emulated (crypto1/UID live in the locked secure element); clone those to a tag instead. [device-specific]

            • FeliCa (NfcF) block read and full ISO-DEP/EMV depth: vary by device/region.

            Some limits are universal; others depend on this phone's NFC controller and secure element.
        """.trimIndent()
        val view = LayoutInflater.from(requireContext()).inflate(R.layout.dialog_limits, null)
        view.findViewById<TextView>(R.id.limits_text).text = msg
        MaterialAlertDialogBuilder(requireContext())
            .setView(view)
            .setPositiveButton("Close", null)
            .show()
    }

    /** Read-only header: identity + protocol findings. The raw block values go
     *  in the editable field below, so they're not duplicated here. */
    private fun summaryText(card: Card): String {
        val sb = StringBuilder()
        sb.append("Type:  ${card.typeLabel}\n")
        sb.append("UID:   ${card.uid}")
        card.atqa?.let { sb.append("\nATQA:  $it") }
        card.sak?.let { sb.append("\nSAK:   $it") }
        card.ats?.let { sb.append("\nATS/hist: $it") }
        sb.append("\nTech:  ${card.techList.joinToString(", ")}")
        if (card.keys.isNotEmpty()) sb.append("\nKeys:  ${card.keys.size} sector(s) recovered")
        if (card.ndef.isNotEmpty()) { sb.append("\nNDEF:"); card.ndef.forEach { sb.append("\n  $it") } }
        if (card.extra.isNotEmpty()) card.extra.forEach { sb.append("\n  $it") }
        if (card.lat != null && card.lon != null)
            sb.append("\nGPS:   %.6f, %.6f".format(card.lat, card.lon))
        return sb.toString()
    }

    private fun blocksToText(card: Card): String =
        card.blocks.toSortedMap().entries.joinToString("\n") { (b, hex) -> "$b $hex" }

    /** Parse the editable "<block> <hex>" lines back into a block map, dropping
     *  lines that aren't a block number + even-length hex payload. */
    private fun parseBlocks(text: String): Map<Int, String> {
        val out = LinkedHashMap<Int, String>()
        text.lines().forEach { line ->
            val sp = line.trim().split(Regex("\\s+"), limit = 2)
            val b = sp[0].toIntOrNull() ?: return@forEach
            val hex = sp.getOrNull(1)?.replace(" ", "")?.uppercase() ?: return@forEach
            if (hex.isNotEmpty() && hex.length % 2 == 0 && hex.all { it in "0123456789ABCDEF" }) out[b] = hex
        }
        return out
    }

    /** Card detail/edit dialog: editable name + raw block values, with
     *  save / delete / duplicate grouped next to close in the top bar. */
    private fun showDetail(card: Card) {
        val view = LayoutInflater.from(requireContext()).inflate(R.layout.dialog_card_detail, null)
        val nameField = view.findViewById<EditText>(R.id.detail_name)
        val blocksField = view.findViewById<EditText>(R.id.detail_blocks)
        view.findViewById<TextView>(R.id.detail_info).text = summaryText(card)
        nameField.setText(card.name)
        blocksField.setText(blocksToText(card))

        val dialog = MaterialAlertDialogBuilder(requireContext()).setView(view).create()

        view.findViewById<ImageButton>(R.id.detail_close).setOnClickListener { dialog.dismiss() }
        view.findViewById<ImageButton>(R.id.detail_save).setOnClickListener {
            card.name = nameField.text.toString().ifBlank { card.name }
            card.blocks = parseBlocks(blocksField.text.toString())
            store.save(cards)
            adapter.notifyDataSetChanged()
            dialog.dismiss()
        }
        view.findViewById<ImageButton>(R.id.detail_delete).setOnClickListener {
            cards.remove(card)
            store.save(cards)
            store.trash(card)        // keep it in the recycle bin
            adapter.notifyDataSetChanged()
            updateStatus()
            dialog.dismiss()
        }
        view.findViewById<ImageButton>(R.id.detail_duplicate).setOnClickListener {
            cards.add(0, card.copy(
                id = UUID.randomUUID().toString(),
                name = "${card.name} (copy)",
                timestamp = System.currentTimeMillis(),
            ))
            store.save(cards)
            adapter.notifyDataSetChanged()
            updateStatus()
            dialog.dismiss()
        }
        dialog.show()
    }

    /** Recycle bin: a card list of everything you deleted, each row with a
     *  restore and a permanent-delete action, plus an Empty-bin button. */
    private fun showBin() {
        val view = LayoutInflater.from(requireContext()).inflate(R.layout.dialog_bin, null)
        val list = view.findViewById<android.widget.LinearLayout>(R.id.bin_list)
        val empty = view.findViewById<TextView>(R.id.bin_empty)
        val subtitle = view.findViewById<TextView>(R.id.bin_subtitle)

        val dialog = MaterialAlertDialogBuilder(requireContext())
            .setView(view)
            .setNeutralButton("Empty bin", null) // handled below so it doesn't dismiss
            .setPositiveButton("Close", null)
            .create()

        fun render() {
            val bin = store.loadBin()
            subtitle.text =
                if (bin.isEmpty()) "Deleted cards are kept here until you remove them."
                else "${bin.size} card(s) in the bin — restore or delete them."
            empty.visibility = if (bin.isEmpty()) View.VISIBLE else View.GONE
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL)?.isEnabled = bin.isNotEmpty()
            list.removeAllViews()
            bin.forEach { card ->
                val row = LayoutInflater.from(requireContext()).inflate(R.layout.item_bin, list, false)
                row.findViewById<TextView>(R.id.bin_name).text = card.name
                row.findViewById<TextView>(R.id.bin_type).text = card.typeLabel
                row.findViewById<ImageButton>(R.id.bin_restore).setOnClickListener {
                    removeFromBin(card)
                    if (cards.none { it.id == card.id }) {
                        cards.add(0, card)
                        store.save(cards)
                        adapter.notifyDataSetChanged()
                    }
                    status.text = "restored \"${card.name}\""
                    render()
                }
                row.findViewById<ImageButton>(R.id.bin_delete).setOnClickListener {
                    removeFromBin(card)
                    status.text = "deleted \"${card.name}\" permanently"
                    render()
                }
                list.addView(row)
            }
            updateStatus()
        }

        dialog.setOnShowListener {
            render()
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener {
                val n = store.loadBin().size
                if (n == 0) return@setOnClickListener
                MaterialAlertDialogBuilder(requireContext())
                    .setTitle("Empty bin?")
                    .setMessage("Permanently delete all $n card(s) in the bin?")
                    .setPositiveButton("Delete all") { _, _ ->
                        store.saveBin(emptyList())
                        status.text = "bin emptied"
                        render()
                    }
                    .setNegativeButton("Cancel", null)
                    .show()
            }
        }
        dialog.show()
    }

    private fun removeFromBin(card: Card) {
        val bin = store.loadBin()
        bin.removeAll { it.id == card.id }
        store.saveBin(bin)
    }

}

/** Walrus-style card list: name header, logo, human-readable info band, and a
 *  right-edge write-to-tag button. */
class CardAdapter(
    private val items: List<Card>,
    private val onClick: (Card) -> Unit,
    private val onWrite: (Card) -> Unit,
    private val onEmulate: (Card) -> Unit,
) : RecyclerView.Adapter<CardAdapter.VH>() {

    class VH(v: View) : RecyclerView.ViewHolder(v) {
        val name: TextView = v.findViewById(R.id.card_name)
        val type: TextView = v.findViewById(R.id.card_type)
        val info: TextView = v.findViewById(R.id.card_info)
        val write: View = v.findViewById(R.id.card_write)
        val emulate: View = v.findViewById(R.id.card_emulate)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH =
        VH(LayoutInflater.from(parent.context).inflate(R.layout.item_card, parent, false))

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(h: VH, position: Int) {
        val c = items[position]
        h.name.text = c.name
        h.type.text = c.typeLabel
        h.info.text = "UID ${c.uid}"
        h.itemView.setOnClickListener { onClick(c) }
        h.write.setOnClickListener { onWrite(c) }
        h.emulate.setOnClickListener { onEmulate(c) }
    }
}
