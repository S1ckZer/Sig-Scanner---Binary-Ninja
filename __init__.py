# Sig Scanner - Binary Ninja Signature Scanner Plugin
# Copyright (c) 2026 S1ckZer
# Licensed under the MIT License - see LICENSE file for details
#
# https://github.com/S1ckZer/Sig-Scanner---Binary-Ninja

import re
import json
import os
import binaryninja
from binaryninja import BackgroundTaskThread, log_info, log_error

_HISTORY_FILE = os.path.join(os.path.dirname(__file__), "sig_history.json")
_MAX_HISTORY = 10


def _load_history():
    try:
        with open(_HISTORY_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


def _save_history(history):
    try:
        with open(_HISTORY_FILE, "w") as f:
            json.dump(history[:_MAX_HISTORY], f)
    except Exception:
        pass


def _add_to_history(sig):
    history = _load_history()
    sig = sig.strip()
    if sig in history:
        history.remove(sig)
    history.insert(0, sig)
    _save_history(history)


if binaryninja.core_ui_enabled():
    from binaryninjaui import (
        Sidebar,
        SidebarWidget,
        SidebarWidgetType,
        SidebarWidgetLocation,
        SidebarContextSensitivity,
        UIContext,
    )

    from PySide6.QtCore import Qt
    from PySide6.QtGui import QImage, QFont, QPainter, QPen, QColor, QCursor
    from PySide6.QtWidgets import (
        QVBoxLayout,
        QHBoxLayout,
        QComboBox,
        QPushButton,
        QTableWidget,
        QTableWidgetItem,
        QHeaderView,
        QLabel,
        QSpinBox,
        QCheckBox,
        QAbstractItemView,
        QApplication,
        QMenu,
        QDialog,
        QDialogButtonBox,
        QTextEdit,
        QGridLayout,
    )

    def parse_signature(signature):
        parts = signature.strip().split()
        pattern_bytes = []
        for part in parts:
            part = part.strip().strip("[]")
            if part in ("?", "??"):
                pattern_bytes.append(b".")
            elif re.fullmatch(r"[0-9a-fA-F]{2}", part):
                pattern_bytes.append(re.escape(bytes([int(part, 16)])))
            else:
                continue
        if not pattern_bytes:
            return None
        return re.compile(b"".join(pattern_bytes), re.DOTALL)

    # ── Sig Generator ────────────────────────────────────────────────────

    def _find_displacement_bytes(raw, current_addr, instr_length, ref_addr):
        """
        Locate the 4-byte RIP-relative displacement encoding within a raw
        instruction and return (start_index, end_index) — exclusive end.
        Returns (None, None) if not found.

        For RIP-relative addressing the CPU adds the displacement to the
        address of the *next* instruction (current_addr + instr_length).
        """
        next_addr = current_addr + instr_length
        disp = ref_addr - next_addr
        try:
            disp_bytes = disp.to_bytes(4, byteorder="little", signed=True)
        except OverflowError:
            return None, None
        raw_bytes = bytes(raw)
        idx = raw_bytes.find(disp_bytes)
        if idx != -1:
            return idx, idx + 4
        return None, None

    def generate_sig_at(bv, addr, num_instructions=10):
        """
        Generate a signature from an address.
        Returns list of (byte_value, is_wildcard, instr_index) tuples.

        Relocatable operand bytes (RIP-relative displacements and branch
        targets) are found by computing the expected encoded displacement and
        searching for it inside the raw instruction bytes.  This correctly
        handles instructions that carry BOTH a mid-instruction RIP-relative
        address and a trailing immediate (e.g. ``cmp [rip+x], imm8`` or
        ``mov [rip+x], imm32``) — the old length-based heuristic failed on
        those because it only wildcarded the final 4 bytes.
        """
        if not bv.arch:
            return [], []

        sig_bytes = []
        instr_boundaries = []
        current_addr = addr

        for i in range(num_instructions):
            instr_data = bv.read(current_addr, bv.arch.max_instr_length)
            if not instr_data:
                break
            info = bv.arch.get_instruction_info(instr_data, current_addr)
            if info is None or info.length == 0:
                break

            raw = bv.read(current_addr, info.length)
            text_result = bv.arch.get_instruction_text(instr_data, current_addr)
            disasm = ""
            if text_result:
                tokens, _ = text_result
                disasm = "".join(str(t) for t in tokens)

            # Collect all referenced addresses from this instruction so we can
            # locate their encoded displacement bytes precisely.
            ref_addrs = []
            code_refs = list(bv.get_code_refs_from(current_addr))
            data_refs = list(bv.get_data_refs_from(current_addr, info.length))
            ref_addrs.extend(r.address if hasattr(r, "address") else r for r in code_refs)
            ref_addrs.extend(r.address if hasattr(r, "address") else r for r in data_refs)

            # Also collect branch targets.
            if info.branches:
                for br in info.branches:
                    if br.target and br.target != 0:
                        ref_addrs.append(br.target)

            has_refs = bool(ref_addrs)

            # Build a set of byte indices that belong to relocatable fields.
            wildcard_indices = set()
            if has_refs:
                for ref_addr_val in ref_addrs:
                    start, end = _find_displacement_bytes(
                        raw, current_addr, info.length, ref_addr_val
                    )
                    if start is not None:
                        for k in range(start, end):
                            wildcard_indices.add(k)

                # Fallback: if displacement-byte search found nothing (e.g. a
                # short branch whose 1-byte offset was not located as a full
                # 4-byte field), fall back to the safe heuristic of wildcarding
                # everything after the first opcode byte.
                if not wildcard_indices:
                    wc_from = (
                        info.length - 4 if info.length >= 5
                        else 1 if info.length >= 2
                        else 0
                    )
                    for k in range(wc_from, info.length):
                        wildcard_indices.add(k)

            instr_boundaries.append({
                "addr": current_addr,
                "offset": len(sig_bytes),
                "length": info.length,
                "disasm": disasm,
                "has_refs": has_refs,
            })

            for j in range(info.length):
                sig_bytes.append({
                    "value": raw[j],
                    "wildcard": j in wildcard_indices,
                    "marked": False,
                    "instr_idx": i,
                })

            current_addr += info.length

        return sig_bytes, instr_boundaries

    def format_sig(sig_bytes):
        """Format sig_bytes into a signature string with [] for marked bytes."""
        parts = []
        in_marked = False
        for b in sig_bytes:
            if b["marked"] and not in_marked:
                parts.append("[")
                in_marked = True
            elif not b["marked"] and in_marked:
                parts.append("]")
                in_marked = False

            if b["wildcard"] or b["marked"]:
                parts.append("?")
            else:
                parts.append(f"{b['value']:02X}")
        if in_marked:
            parts.append("]")
        return " ".join(parts)

    class SigGeneratorDialog(QDialog):
        def __init__(self, bv, addr, parent=None, end_addr=None):
            super().__init__(parent)
            self.bv = bv
            self.addr = addr
            self.end_addr = end_addr  # If set, generate sig covering this range
            self.setWindowTitle(f"Generate Signature at 0x{addr:x}")
            self.resize(750, 500)

            layout = QVBoxLayout()

            # Controls
            ctrl = QHBoxLayout()
            ctrl.addWidget(QLabel("Instructions:"))
            self.num_instr = QSpinBox()
            self.num_instr.setRange(2, 50)
            if end_addr and end_addr > addr:
                # Estimate instruction count from range (avg ~4 bytes per instr on x86)
                est = max(2, min(50, (end_addr - addr) // 3))
                self.num_instr.setValue(est)
            else:
                self.num_instr.setValue(10)
            self.num_instr.valueChanged.connect(self._regenerate)
            ctrl.addWidget(self.num_instr)
            ctrl.addStretch()

            help_label = QLabel("Click instruction to toggle: fixed / wildcard / [marked]")
            help_label.setStyleSheet("color: gray;")
            ctrl.addWidget(help_label)
            layout.addLayout(ctrl)

            # Instruction list
            self.instr_table = QTableWidget(0, 4)
            self.instr_table.setHorizontalHeaderLabels(["Address", "Bytes", "Disassembly", "State"])
            self.instr_table.horizontalHeader().setStretchLastSection(True)
            self.instr_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
            self.instr_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Interactive)
            self.instr_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
            self.instr_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
            self.instr_table.verticalHeader().setVisible(False)
            self.instr_table.setSelectionBehavior(QAbstractItemView.SelectRows)
            self.instr_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            self.instr_table.cellClicked.connect(self._on_instr_click)
            layout.addWidget(self.instr_table)

            # Signature output
            layout.addWidget(QLabel("Generated Signature:"))
            self.sig_output = QTextEdit()
            self.sig_output.setMaximumHeight(80)
            self.sig_output.setFont(QFont("Consolas", 10))
            self.sig_output.setReadOnly(True)
            layout.addWidget(self.sig_output)

            # Buttons
            btn_row = QHBoxLayout()
            copy_btn = QPushButton("Copy Signature")
            copy_btn.clicked.connect(self._copy_sig)
            btn_row.addWidget(copy_btn)

            scan_btn = QPushButton("Scan This Signature")
            scan_btn.clicked.connect(self._scan_sig)
            btn_row.addWidget(scan_btn)

            btn_row.addStretch()

            close_btn = QPushButton("Close")
            close_btn.clicked.connect(self.close)
            btn_row.addWidget(close_btn)
            layout.addLayout(btn_row)

            self.setLayout(layout)
            self.sig_bytes = []
            self.instr_bounds = []
            self._regenerate()

        def _regenerate(self):
            num = self.num_instr.value()
            # If we have an end address, generate enough instructions to cover the range
            if self.end_addr and self.end_addr > self.addr:
                self.sig_bytes, self.instr_bounds = generate_sig_at(
                    self.bv, self.addr, 200  # generate plenty
                )
                # Trim to instructions within the selected range
                trimmed_bytes = []
                trimmed_bounds = []
                for ib in self.instr_bounds:
                    if ib["addr"] >= self.end_addr:
                        break
                    trimmed_bounds.append(ib)
                if trimmed_bounds:
                    last = trimmed_bounds[-1]
                    end_offset = last["offset"] + last["length"]
                    trimmed_bytes = self.sig_bytes[:end_offset]
                self.sig_bytes = trimmed_bytes
                self.instr_bounds = trimmed_bounds
                self.num_instr.setValue(len(trimmed_bounds))
            else:
                self.sig_bytes, self.instr_bounds = generate_sig_at(
                    self.bv, self.addr, num
                )
            self._update_table()
            self._update_sig()

        def _update_table(self):
            self.instr_table.setRowCount(len(self.instr_bounds))
            mono = QFont("Consolas", 9)
            for i, ib in enumerate(self.instr_bounds):
                # Address
                addr_item = QTableWidgetItem(f"0x{ib['addr']:x}")
                addr_item.setFont(mono)
                self.instr_table.setItem(i, 0, addr_item)

                # Bytes with coloring
                instr_bytes = self.sig_bytes[ib["offset"]:ib["offset"] + ib["length"]]
                byte_strs = []
                for b in instr_bytes:
                    if b["marked"]:
                        byte_strs.append("[?]")
                    elif b["wildcard"]:
                        byte_strs.append("?")
                    else:
                        byte_strs.append(f"{b['value']:02X}")
                bytes_item = QTableWidgetItem(" ".join(byte_strs))
                bytes_item.setFont(mono)
                self.instr_table.setItem(i, 1, bytes_item)

                # Disassembly
                dis_item = QTableWidgetItem(ib["disasm"])
                dis_item.setFont(mono)
                self.instr_table.setItem(i, 2, dis_item)

                # State
                has_wc = any(b["wildcard"] for b in instr_bytes)
                has_mk = any(b["marked"] for b in instr_bytes)
                if has_mk:
                    state = "[MARKED]"
                elif has_wc:
                    state = "WILDCARD"
                else:
                    state = "FIXED"
                state_item = QTableWidgetItem(state)
                state_item.setTextAlignment(Qt.AlignCenter)
                self.instr_table.setItem(i, 3, state_item)

        def _on_instr_click(self, row, col):
            if row >= len(self.instr_bounds):
                return
            ib = self.instr_bounds[row]
            instr_bytes = self.sig_bytes[ib["offset"]:ib["offset"] + ib["length"]]

            # Cycle: if any marked -> all fixed, if any wildcard -> all marked, else -> all wildcard
            has_mk = any(b["marked"] for b in instr_bytes)
            has_wc = any(b["wildcard"] for b in instr_bytes)
            all_fixed = not has_wc and not has_mk

            if has_mk:
                # marked -> fixed
                for b in instr_bytes:
                    b["wildcard"] = False
                    b["marked"] = False
            elif has_wc:
                # wildcard -> marked
                for b in instr_bytes:
                    if b["wildcard"]:
                        b["wildcard"] = False
                        b["marked"] = True
            else:
                # fixed -> wildcard
                # Re-run displacement detection to restore the correct wildcards.
                if ib["has_refs"]:
                    raw = self.bv.read(ib["addr"], ib["length"])
                    code_refs = list(self.bv.get_code_refs_from(ib["addr"]))
                    data_refs = list(self.bv.get_data_refs_from(ib["addr"], ib["length"]))
                    ref_addrs = []
                    ref_addrs.extend(r.address if hasattr(r, "address") else r for r in code_refs)
                    ref_addrs.extend(r.address if hasattr(r, "address") else r for r in data_refs)
                    instr_data = self.bv.read(ib["addr"], self.bv.arch.max_instr_length)
                    info = self.bv.arch.get_instruction_info(instr_data, ib["addr"])
                    if info and info.branches:
                        for br in info.branches:
                            if br.target and br.target != 0:
                                ref_addrs.append(br.target)
                    wildcard_indices = set()
                    for ref_addr_val in ref_addrs:
                        start, end = _find_displacement_bytes(
                            raw, ib["addr"], ib["length"], ref_addr_val
                        )
                        if start is not None:
                            for k in range(start, end):
                                wildcard_indices.add(k)
                    if not wildcard_indices:
                        length = ib["length"]
                        wc_from = length - 4 if length >= 5 else (1 if length >= 2 else 0)
                        wildcard_indices = set(range(wc_from, length))
                    for j, b in enumerate(instr_bytes):
                        if j in wildcard_indices:
                            b["wildcard"] = True
                else:
                    # No refs: wildcard everything after the first opcode byte
                    for j, b in enumerate(instr_bytes):
                        if j >= 1:
                            b["wildcard"] = True

            self._update_table()
            self._update_sig()

        def _update_sig(self):
            self.sig_output.setPlainText(format_sig(self.sig_bytes))

        def _copy_sig(self):
            QApplication.clipboard().setText(self.sig_output.toPlainText())

        def _scan_sig(self):
            sig_text = self.sig_output.toPlainText()
            self.close()
            # Find the sidebar widget and trigger a scan
            ctx = UIContext.activeContext()
            if ctx:
                sb = ctx.sidebar()
                if sb:
                    # Put the sig in clipboard for easy paste
                    QApplication.clipboard().setText(sig_text)

    # ── Scanner Task ─────────────────────────────────────────────────────

    class SigScanTask(BackgroundTaskThread):
        def __init__(self, widget, bv, regex, max_results, all_segments):
            super().__init__("Scanning for signature...", True)
            self.widget = widget
            self.bv = bv
            self.regex = regex
            self.max_results = max_results
            self.all_segments = all_segments

        def run(self):
            bv = self.bv
            if self.all_segments:
                segments = list(bv.segments)
            else:
                segments = [seg for seg in bv.segments if seg.executable]
                if not segments:
                    segments = list(bv.segments)

            image_base = bv.start

            results = []
            for segment in segments:
                if self.cancelled:
                    break
                data = bv.read(segment.start, segment.length)
                for match in self.regex.finditer(data):
                    if len(results) >= self.max_results or self.cancelled:
                        break
                    addr = segment.start + match.start()

                    funcs = bv.get_functions_containing(addr)
                    func_name = funcs[0].name if funcs else ""

                    # Disassembly
                    disasm = ""
                    if bv.arch:
                        instr_data = bv.read(addr, 16)
                        text_result = bv.arch.get_instruction_text(instr_data, addr)
                        if text_result:
                            tokens, length = text_result
                            disasm = "".join(str(t) for t in tokens)

                    # RVA
                    rva = addr - image_base

                    # Section name
                    sections = bv.get_sections_at(addr)
                    section_name = sections[0].name if sections else ""

                    results.append((addr, func_name, disasm, rva, section_name))

                self.progress = f"Scanning... {len(results)} matches found"
                if len(results) >= self.max_results:
                    break

            self.widget._on_results(results)

    # ── Sidebar Widget ───────────────────────────────────────────────────

    class SigScannerWidget(SidebarWidget):
        def __init__(self, name, frame, data):
            SidebarWidget.__init__(self, name)
            self.frame = frame
            self.data = data
            self.task = None

            layout = QVBoxLayout()
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(4)

            # Signature input with history dropdown
            input_row = QHBoxLayout()
            input_row.setContentsMargins(4, 4, 4, 0)
            self.sig_input = QComboBox()
            self.sig_input.setEditable(True)
            self.sig_input.setInsertPolicy(QComboBox.NoInsert)
            self.sig_input.lineEdit().setPlaceholderText("48 89 5C 24 ?? 48 89 74 24 ??")
            self.sig_input.lineEdit().returnPressed.connect(self._on_scan)
            self._load_history()
            input_row.addWidget(self.sig_input)
            layout.addLayout(input_row)

            # Controls row
            ctrl_row = QHBoxLayout()
            ctrl_row.setContentsMargins(4, 0, 4, 0)
            ctrl_row.addWidget(QLabel("Max:"))
            self.max_spin = QSpinBox()
            self.max_spin.setRange(1, 10000)
            self.max_spin.setValue(500)
            self.max_spin.setFixedWidth(70)
            ctrl_row.addWidget(self.max_spin)

            self.all_seg_cb = QCheckBox("All Segments")
            self.all_seg_cb.setToolTip("Scan all segments, not just executable ones")
            ctrl_row.addWidget(self.all_seg_cb)

            ctrl_row.addStretch()
            self.scan_btn = QPushButton("Scan")
            self.scan_btn.clicked.connect(self._on_scan)
            ctrl_row.addWidget(self.scan_btn)
            layout.addLayout(ctrl_row)

            # Status label
            self.status_label = QLabel("")
            self.status_label.setContentsMargins(4, 0, 4, 0)
            layout.addWidget(self.status_label)

            # Results table
            self.table = QTableWidget(0, 6)
            self.table.setHorizontalHeaderLabels(["#", "Address", "RVA", "Section", "Function", "Instruction"])
            self.table.horizontalHeader().setStretchLastSection(True)
            self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
            self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Interactive)
            self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Interactive)
            self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Interactive)
            self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Interactive)
            self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
            self.table.verticalHeader().setVisible(False)
            self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
            self.table.setSelectionMode(QAbstractItemView.SingleSelection)
            self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            self.table.cellClicked.connect(self._on_navigate)
            self.table.setContextMenuPolicy(Qt.CustomContextMenu)
            self.table.customContextMenuRequested.connect(self._on_context_menu)
            layout.addWidget(self.table)

            self.setLayout(layout)

        def _load_history(self):
            self.sig_input.clear()
            for sig in _load_history():
                self.sig_input.addItem(sig)
            # Clear the text so placeholder shows
            self.sig_input.setCurrentText("")

        def _on_scan(self):
            if not self.data:
                self.status_label.setText("No binary loaded.")
                return

            sig_text = self.sig_input.currentText().strip()
            if not sig_text:
                self.status_label.setText("Enter a signature.")
                return

            regex = parse_signature(sig_text)
            if not regex:
                self.status_label.setText("Invalid signature.")
                return

            # Save to history
            _add_to_history(sig_text)
            self._load_history()
            self.sig_input.setCurrentText(sig_text)

            self.table.setRowCount(0)
            self.status_label.setText("Scanning...")
            self.scan_btn.setEnabled(False)

            self.task = SigScanTask(
                self, self.data, regex, self.max_spin.value(),
                self.all_seg_cb.isChecked()
            )
            self.task.start()

        def _on_results(self, results):
            self.table.setRowCount(len(results))
            mono = QFont("Consolas", 9)
            for i, (addr, func_name, disasm, rva, section) in enumerate(results):
                idx_item = QTableWidgetItem(str(i))
                idx_item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(i, 0, idx_item)

                addr_item = QTableWidgetItem(f"0x{addr:x}")
                addr_item.setData(Qt.UserRole, addr)
                addr_item.setFont(mono)
                self.table.setItem(i, 1, addr_item)

                rva_item = QTableWidgetItem(f"0x{rva:x}")
                rva_item.setFont(mono)
                self.table.setItem(i, 2, rva_item)

                self.table.setItem(i, 3, QTableWidgetItem(section))
                self.table.setItem(i, 4, QTableWidgetItem(func_name))

                disasm_item = QTableWidgetItem(disasm)
                disasm_item.setFont(mono)
                self.table.setItem(i, 5, disasm_item)

            self.status_label.setText(f"Found {len(results)} matches")
            self.scan_btn.setEnabled(True)

        def _on_navigate(self, row, col):
            addr_item = self.table.item(row, 1)
            if addr_item and self.data:
                addr = addr_item.data(Qt.UserRole)
                self.data.navigate(self.data.view, addr)

        def _on_context_menu(self, pos):
            item = self.table.itemAt(pos)
            if not item:
                return
            row = item.row()
            addr_item = self.table.item(row, 1)
            func_item = self.table.item(row, 4)
            rva_item = self.table.item(row, 2)
            if not addr_item:
                return

            addr = addr_item.data(Qt.UserRole)
            addr_text = addr_item.text()
            func_text = func_item.text() if func_item else ""
            rva_text = rva_item.text() if rva_item else ""

            menu = QMenu(self.table)

            go_addr = menu.addAction(f"Go to Address  ({addr_text})")
            go_func = None
            if func_text:
                go_func = menu.addAction(f"Go to Function  ({func_text})")

            menu.addSeparator()

            gen_sig = menu.addAction("Generate Signature from here...")

            menu.addSeparator()

            copy_addr = menu.addAction(f"Copy Address  ({addr_text})")
            copy_rva = menu.addAction(f"Copy RVA  ({rva_text})")
            copy_func = None
            if func_text:
                copy_func = menu.addAction(f"Copy Function Name  ({func_text})")

            action = menu.exec_(QCursor.pos())
            if action == go_addr:
                self.data.navigate(self.data.view, addr)
            elif go_func and action == go_func:
                funcs = self.data.get_functions_containing(addr) if self.data else []
                if funcs:
                    self.data.navigate(self.data.view, funcs[0].start)
            elif action == gen_sig:
                self._open_sig_generator(addr)
            elif action == copy_addr:
                QApplication.clipboard().setText(addr_text)
            elif action == copy_rva:
                QApplication.clipboard().setText(rva_text)
            elif copy_func and action == copy_func:
                QApplication.clipboard().setText(func_text)

        def _open_sig_generator(self, addr):
            if self.data:
                dlg = SigGeneratorDialog(self.data, addr, self)
                dlg.show()

        def notifyViewChanged(self, frame):
            self.frame = frame
            if frame:
                self.data = frame.getCurrentBinaryView()
            else:
                self.data = None

    # ── Sidebar Type ─────────────────────────────────────────────────────

    class SigScannerWidgetType(SidebarWidgetType):
        def __init__(self):
            icon = QImage(56, 56, QImage.Format_ARGB32)
            icon.fill(0)
            p = QPainter(icon)
            p.setRenderHint(QPainter.Antialiasing)
            pen = QPen(QColor(255, 255, 255), 5)
            p.setPen(pen)
            p.drawEllipse(6, 6, 26, 26)
            p.drawLine(30, 30, 48, 48)
            p.end()
            SidebarWidgetType.__init__(self, icon, "Sig Scanner")

        def createWidget(self, frame, data):
            return SigScannerWidget("Sig Scanner", frame, data)

        def defaultLocation(self):
            return SidebarWidgetLocation.LeftContent

        def contextSensitivity(self):
            return SidebarContextSensitivity.SelfManagedSidebarContext

    Sidebar.addSidebarWidgetType(SigScannerWidgetType())

    # ── Also register as a command for "Generate Sig" from context menu ──

    from binaryninja import PluginCommand

    def _gen_sig_command(bv, addr):
        dlg = SigGeneratorDialog(bv, addr)
        dlg.exec_()

    def _gen_sig_range_command(bv, addr, length):
        end_addr = addr + length
        dlg = SigGeneratorDialog(bv, addr, end_addr=end_addr)
        dlg.exec_()

    PluginCommand.register_for_address(
        "Sig Scanner\\Generate Signature at Address",
        "Generate a byte signature starting from this address",
        _gen_sig_command,
    )

    PluginCommand.register_for_range(
        "Sig Scanner\\Generate Signature from Selection",
        "Generate a byte signature covering the selected range",
        _gen_sig_range_command,
    )
