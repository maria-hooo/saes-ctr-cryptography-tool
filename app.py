"""
S-AES CTR — Graphical User Interface
=====================================
Run with:  python saes_gui.py
Requires:  Python 3.8+  (tkinter is built-in, no pip installs needed)
"""
 
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
 
# ═══════════════════════════════════════════════════════
#  S-AES CORE  (no external libraries)
# ═══════════════════════════════════════════════════════
 
SBOX     = [0x9,0x4,0xA,0xB,0xD,0x1,0x8,0x5,0x6,0x2,0x0,0x3,0xC,0xE,0xF,0x7]
INV_SBOX = [0xA,0x5,0x9,0xB,0x1,0x7,0x8,0xF,0x6,0x0,0x2,0x3,0xC,0x4,0xD,0xE]
RCON1, RCON2 = 0x80, 0x30
 
def gf_mult(a, b):
    p = 0
    for _ in range(4):
        if b & 1: p ^= a
        hi = a & 0x8
        a = (a << 1) & 0xF
        if hi: a ^= 0x3
        b >>= 1
    return p
 
def sub_nibbles_byte(byte):
    return (SBOX[(byte >> 4) & 0xF] << 4) | SBOX[byte & 0xF]
 
def key_schedule(key):
    w0, w1 = (key >> 8) & 0xFF, key & 0xFF
    w2 = w0 ^ RCON1 ^ sub_nibbles_byte(w1)
    w3 = w2 ^ w1
    w4 = w2 ^ RCON2 ^ sub_nibbles_byte(w3)
    w5 = w4 ^ w3
    return (w0<<8)|w1, (w2<<8)|w3, (w4<<8)|w5
 
def get_nibble(s, r, c): return (s >> (12-(c*8+r*4))) & 0xF
def set_nibble(s, r, c, v):
    sh = 12-(c*8+r*4)
    return (s & ~(0xF<<sh) & 0xFFFF) | ((v&0xF)<<sh)
 
def nibble_sub(s, inv=False):
    box = INV_SBOX if inv else SBOX
    r = 0
    for i in range(4): r |= box[(s>>(i*4))&0xF] << (i*4)
    return r
 
def shift_rows(s):
    r = set_nibble(0,   0,0, get_nibble(s,0,0))
    r = set_nibble(r,   1,0, get_nibble(s,1,1))
    r = set_nibble(r,   0,1, get_nibble(s,0,1))
    r = set_nibble(r,   1,1, get_nibble(s,1,0))
    return r
 
def mix_columns(s):
    r = 0
    for c in range(2):
        a,b = get_nibble(s,0,c), get_nibble(s,1,c)
        r = set_nibble(r,0,c, a ^ gf_mult(4,b))
        r = set_nibble(r,1,c, gf_mult(4,a) ^ b)
    return r
 
def inv_mix_columns(s):
    r = 0
    for c in range(2):
        a,b = get_nibble(s,0,c), get_nibble(s,1,c)
        r = set_nibble(r,0,c, gf_mult(9,a)^gf_mult(2,b))
        r = set_nibble(r,1,c, gf_mult(2,a)^gf_mult(9,b))
    return r
 
def saes_encrypt_block(pt, key):
    K0,K1,K2 = key_schedule(key)
    s = pt ^ K0
    s = nibble_sub(s); s = shift_rows(s); s = mix_columns(s); s ^= K1
    s = nibble_sub(s); s = shift_rows(s); s ^= K2
    return s & 0xFFFF
 
def ctr_process(data: bytes, key: int, nonce: int) -> bytes:
    out = bytearray()
    ctr = 0
    i = 0
    while i < len(data):
        cb = ((nonce & 0xFF) << 8) | (ctr & 0xFF)
        ks = saes_encrypt_block(cb, key)
        for kb in [(ks>>8)&0xFF, ks&0xFF]:
            if i < len(data):
                out.append(data[i] ^ kb); i += 1
        ctr = (ctr+1) & 0xFF
    return bytes(out)
 
def brute_force(ciphertext, nonce, known_plaintext=None,
                plaintext_hint=None, progress_cb=None):
    results = []
    for key in range(0x10000):
        candidate = ctr_process(ciphertext, key, nonce)
        if known_plaintext:
            if candidate[:len(known_plaintext)] == known_plaintext:
                results.append((key, candidate)); break
        elif plaintext_hint:
            try:
                t = candidate.decode('utf-8', errors='strict')
                if plaintext_hint.lower() in t.lower():
                    results.append((key, candidate))
            except: pass
        else:
            if all(0x20<=b<0x7F or b in(9,10,13) for b in candidate):
                results.append((key, candidate))
        if progress_cb and key % 2048 == 0:
            progress_cb(key)
    return results
 
def frequency_analysis(data):
    freq = {}
    for b in data: freq[b] = freq.get(b,0)+1
    n = len(data)
    ioc = sum(f*(f-1) for f in freq.values())/(n*(n-1)) if n>1 else 0
    return freq, round(ioc,6)
 
def parse_num(s):
    s = s.strip()
    if s.startswith(('0x','0X')): return int(s,16)
    return int(s)
 
 
# ═══════════════════════════════════════════════════════
#  COLOUR PALETTE
# ═══════════════════════════════════════════════════════
 
BG       = "#0d1117"
PANEL    = "#161b22"
BORDER   = "#30363d"
CYAN     = "#58a6ff"
GREEN    = "#3fb950"
ORANGE   = "#f0883e"
RED      = "#f85149"
MUTED    = "#8b949e"
TEXT     = "#e6edf3"
ENTRY_BG = "#0d1117"
BTN_BG   = "#21262d"
BTN_HOV  = "#30363d"
 
FONT_TITLE  = ("Consolas", 22, "bold")
FONT_HEAD   = ("Consolas", 11, "bold")
FONT_BODY   = ("Consolas", 10)
FONT_SMALL  = ("Consolas",  9)
FONT_MONO   = ("Consolas", 10)
 
 
# ═══════════════════════════════════════════════════════
#  REUSABLE WIDGETS
# ═══════════════════════════════════════════════════════
 
class FlatButton(tk.Button):
    def __init__(self, master, text, command, color=CYAN, **kw):
        kw.setdefault("padx", 18)
        kw.setdefault("pady", 8)
        kw.setdefault("font", FONT_HEAD)
        super().__init__(master, text=text, command=command,
                         bg=BTN_BG, fg=color, activebackground=BTN_HOV,
                         activeforeground=color, relief="flat", bd=0,
                         cursor="hand2", **kw)
        self.bind("<Enter>", lambda e: self.config(bg=BTN_HOV))
        self.bind("<Leave>", lambda e: self.config(bg=BTN_BG))
 
class SectionLabel(tk.Label):
    def __init__(self, master, text, **kw):
        super().__init__(master, text=f"  {text}",
                         bg=PANEL, fg=CYAN, font=FONT_HEAD,
                         anchor="w", pady=6, **kw)
 
class ParamEntry(tk.Frame):
    """Label + Entry + hint line combo."""
    def __init__(self, master, label, placeholder="", **kw):
        super().__init__(master, bg=PANEL, **kw)
        tk.Label(self, text=label, bg=PANEL, fg=MUTED,
                 font=FONT_SMALL, anchor="w").pack(fill="x")
        self.var = tk.StringVar(value=placeholder)
        self.entry = tk.Entry(self, textvariable=self.var,
                              bg=ENTRY_BG, fg=TEXT, insertbackground=TEXT,
                              relief="flat", bd=0, font=FONT_MONO,
                              highlightthickness=1,
                              highlightbackground=BORDER,
                              highlightcolor=CYAN)
        self.entry.pack(fill="x", ipady=6, pady=(2,0))
        self.hint = tk.Label(self, text="", bg=PANEL,
                             fg=MUTED, font=FONT_SMALL, anchor="w")
        self.hint.pack(fill="x")
 
    def get(self): return self.var.get()
    def set_hint(self, msg, ok=True):
        self.hint.config(text=msg, fg=GREEN if ok else RED)
 
class OutputBox(tk.Frame):
    """Read-only text area with copy button."""
    def __init__(self, master, height=6, **kw):
        super().__init__(master, bg=PANEL, **kw)
        bar = tk.Frame(self, bg=PANEL)
        bar.pack(fill="x")
        self._title = tk.Label(bar, text="Output", bg=PANEL,
                               fg=MUTED, font=FONT_SMALL, anchor="w")
        self._title.pack(side="left")
        FlatButton(bar, "⎘ Copy", self._copy,
                   color=MUTED, padx=8, pady=2,
                   font=FONT_SMALL).pack(side="right")
        self.text = tk.Text(self, height=height,
                            bg=ENTRY_BG, fg=GREEN,
                            font=FONT_MONO, relief="flat", bd=0,
                            state="disabled", wrap="word",
                            insertbackground=TEXT,
                            highlightthickness=1,
                            highlightbackground=BORDER)
        self.text.pack(fill="both", expand=True, pady=(4,0))
 
    def set_title(self, t): self._title.config(text=t)
 
    def set(self, content, color=GREEN):
        self.text.config(state="normal", fg=color)
        self.text.delete("1.0","end")
        self.text.insert("end", content)
        self.text.config(state="disabled")
 
    def append(self, content):
        self.text.config(state="normal")
        self.text.insert("end", content)
        self.text.see("end")
        self.text.config(state="disabled")
 
    def clear(self):
        self.text.config(state="normal")
        self.text.delete("1.0","end")
        self.text.config(state="disabled")
 
    def _copy(self):
        content = self.text.get("1.0","end").strip()
        self.text.clipboard_clear()
        self.text.clipboard_append(content)
 
def divider(parent):
    tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", pady=8)
 
 
# ═══════════════════════════════════════════════════════
#  MAIN APPLICATION
# ═══════════════════════════════════════════════════════
 
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("S-AES CTR · Cryptography Tool")
        self.geometry("860x680")
        self.minsize(760, 580)
        self.configure(bg=BG)
 
        # shared state
        self._last_cipher     = b""
        self._last_key        = 0
        self._last_nonce      = 0
        self._enc_file_path   = ""
 
        self._build_header()
        self._build_tabs()
 
    # ── HEADER ──────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self, bg=BG, pady=14)
        hdr.pack(fill="x", padx=24)
        tk.Label(hdr, text="S-AES", bg=BG, fg=CYAN,
                 font=("Consolas",26,"bold")).pack(side="left")
        tk.Label(hdr, text=" · CTR Mode", bg=BG, fg=TEXT,
                 font=("Consolas",18)).pack(side="left")
        tk.Label(hdr, text="IN410 Cryptography Project",
                 bg=BG, fg=MUTED, font=FONT_SMALL).pack(side="right")
 
    # ── TABS ─────────────────────────────────────────────
    def _build_tabs(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook",
                        background=BG, borderwidth=0, tabmargins=0)
        style.configure("TNotebook.Tab",
                        background=PANEL, foreground=MUTED,
                        font=FONT_HEAD, padding=[18,8],
                        borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", BTN_HOV)],
                  foreground=[("selected", CYAN)])
        style.configure("TFrame", background=BG)
 
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=12, pady=(0,12))
 
        tabs = [
            ("🔐  Encrypt",    self._tab_encrypt),
            ("🔓  Decrypt",    self._tab_decrypt),
            ("💀  Brute Force",self._tab_brute),
            ("📊  Analysis",   self._tab_analysis),
        ]
        for label, builder in tabs:
            frame = tk.Frame(nb, bg=BG)
            nb.add(frame, text=label)
            builder(frame)
 
    # ── HELPERS ──────────────────────────────────────────
    def _scrollable(self, parent):
        """Returns a scrollable inner frame."""
        canvas = tk.Canvas(parent, bg=BG, highlightthickness=0)
        sb = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas, bg=BG)
        inner.bind("<Configure>",
                   lambda e: canvas.configure(
                       scrollregion=canvas.bbox("all")))
        canvas.create_window((0,0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(-1*(e.delta//120),"units"))
        return inner
 
    def _card(self, parent, title=None):
        outer = tk.Frame(parent, bg=PANEL,
                         highlightthickness=1,
                         highlightbackground=BORDER)
        outer.pack(fill="x", padx=16, pady=6)
        inner = tk.Frame(outer, bg=PANEL)
        inner.pack(fill="x", padx=14, pady=10)
        if title:
            SectionLabel(inner, title).pack(fill="x")
            tk.Frame(inner, bg=BORDER, height=1).pack(fill="x", pady=(4,8))
        return inner
 
    def _validate_key(self, entry_widget, bits):
        try:
            v = parse_num(entry_widget.get())
            if v < 0 or v >= (1<<bits):
                raise ValueError
            entry_widget.set_hint(
                f"✓  0x{v:04X}  =  {v}  =  {v:0{bits}b}b", ok=True)
            return v
        except:
            entry_widget.set_hint(f"✗  Must be 0 – {(1<<bits)-1}", ok=False)
            return None
 
    # ════════════════════════════════════════════════════
    #  TAB 1 — ENCRYPT
    # ════════════════════════════════════════════════════
    def _tab_encrypt(self, parent):
        f = self._scrollable(parent)
 
        # — Parameters card —
        c = self._card(f, "Parameters")
        row = tk.Frame(c, bg=PANEL); row.pack(fill="x")
        self.enc_key   = ParamEntry(row, "Key  (16-bit, 0–65535)",   "0x006F")
        self.enc_nonce = ParamEntry(row, "Nonce / IV  (8-bit, 0–255)","111")
        self.enc_key.pack(side="left", fill="x", expand=True, padx=(0,8))
        self.enc_nonce.pack(side="left", fill="x", expand=True)
        self.enc_key.entry.bind("<FocusOut>",
            lambda e: self._validate_key(self.enc_key, 16))
        self.enc_nonce.entry.bind("<FocusOut>",
            lambda e: self._validate_key(self.enc_nonce, 8))
 
        # — Input card —
        c2 = self._card(f, "Input")
 
        # mode switcher
        self._enc_mode = tk.StringVar(value="text")
        mrow = tk.Frame(c2, bg=PANEL); mrow.pack(fill="x", pady=(0,8))
        for val, lbl in [("text","📝  Text"), ("file","📁  File / Image")]:
            rb = tk.Radiobutton(mrow, text=lbl, variable=self._enc_mode,
                                value=val, bg=PANEL, fg=TEXT,
                                selectcolor=PANEL, activebackground=PANEL,
                                font=FONT_BODY, cursor="hand2",
                                command=self._toggle_enc_input)
            rb.pack(side="left", padx=(0,16))
 
        # text area
        self._enc_text_frame = tk.Frame(c2, bg=PANEL)
        self._enc_text_frame.pack(fill="x")
        tk.Label(self._enc_text_frame, text="Plaintext",
                 bg=PANEL, fg=MUTED, font=FONT_SMALL, anchor="w").pack(fill="x")
        self.enc_text = tk.Text(self._enc_text_frame, height=5,
                                bg=ENTRY_BG, fg=TEXT, font=FONT_MONO,
                                relief="flat", insertbackground=TEXT,
                                highlightthickness=1,
                                highlightbackground=BORDER,
                                highlightcolor=CYAN)
        self.enc_text.pack(fill="x", pady=(2,0))
        self.enc_text.insert("end","Hello, this is my IN410 project!")
 
        # file picker
        self._enc_file_frame = tk.Frame(c2, bg=PANEL)
        frow = tk.Frame(self._enc_file_frame, bg=PANEL)
        frow.pack(fill="x")
        self._enc_file_label = tk.Label(frow, text="No file selected",
                                        bg=ENTRY_BG, fg=MUTED,
                                        font=FONT_MONO, anchor="w",
                                        padx=8, pady=8,
                                        highlightthickness=1,
                                        highlightbackground=BORDER)
        self._enc_file_label.pack(side="left", fill="x", expand=True, padx=(0,8))
        FlatButton(frow, "Browse…", self._pick_enc_file,
                   color=ORANGE).pack(side="right")
 
        # — Output card —
        c3 = self._card(f, "Output")
        self.enc_out = OutputBox(c3, height=4)
        self.enc_out.set_title("Ciphertext (hex)")
        self.enc_out.pack(fill="x")
        self.enc_out.set("— Click Encrypt to see output —", color=MUTED)
 
        self.enc_b64 = OutputBox(c3, height=3)
        self.enc_b64.set_title("Ciphertext (Base64)")
        self.enc_b64.pack(fill="x", pady=(8,0))
        self.enc_b64.set("—", color=MUTED)
 
        brow = tk.Frame(c3, bg=PANEL); brow.pack(fill="x", pady=(10,0))
        FlatButton(brow, "⚡  Encrypt", self._do_encrypt,
                   color=CYAN).pack(side="left", padx=(0,8))
        FlatButton(brow, "⬇  Download .enc", self._download_enc,
                   color=ORANGE).pack(side="left")
 
        self.enc_status = tk.Label(c3, text="", bg=PANEL,
                                   fg=MUTED, font=FONT_SMALL, anchor="w")
        self.enc_status.pack(fill="x", pady=(6,0))
 
    def _toggle_enc_input(self):
        if self._enc_mode.get() == "text":
            self._enc_file_frame.pack_forget()
            self._enc_text_frame.pack(fill="x")
        else:
            self._enc_text_frame.pack_forget()
            self._enc_file_frame.pack(fill="x")
 
    def _pick_enc_file(self):
        path = filedialog.askopenfilename(title="Select file to encrypt")
        if path:
            self._enc_file_path = path
            name = os.path.basename(path)
            size = os.path.getsize(path)
            self._enc_file_label.config(
                text=f"📄  {name}  ({size:,} bytes)", fg=TEXT)
 
    def _do_encrypt(self):
        key = self._validate_key(self.enc_key, 16)
        if key is None: return
        nonce = self._validate_key(self.enc_nonce, 8)
        if nonce is None: return
 
        if self._enc_mode.get() == "text":
            txt = self.enc_text.get("1.0","end").strip()
            if not txt:
                messagebox.showerror("Error","Please enter some plaintext."); return
            data = txt.encode()
        else:
            if not self._enc_file_path:
                messagebox.showerror("Error","Please select a file first."); return
            with open(self._enc_file_path,"rb") as f:
                data = f.read()
 
        cipher = ctr_process(data, key, nonce)
        self._last_cipher = cipher
        self._last_key    = key
        self._last_nonce  = nonce
 
        hex_out = cipher.hex()
        import base64
        b64_out = base64.b64encode(cipher).decode()
 
        self.enc_out.set(hex_out)
        self.enc_b64.set(b64_out)
        self.enc_status.config(
            text=f"✓  Encrypted {len(data):,} bytes  ·  Key: 0x{key:04X}  ·  Nonce: {nonce}",
            fg=GREEN)
 
    def _download_enc(self):
        if not self._last_cipher:
            messagebox.showinfo("Nothing to save","Encrypt something first."); return
        path = filedialog.asksaveasfilename(
            defaultextension=".enc",
            filetypes=[("Encrypted","*.enc"),("All","*.*")],
            initialfile="ciphertext.enc")
        if path:
            with open(path,"wb") as f: f.write(self._last_cipher)
            messagebox.showinfo("Saved", f"Ciphertext saved to:\n{path}")
 
    # ════════════════════════════════════════════════════
    #  TAB 2 — DECRYPT
    # ════════════════════════════════════════════════════
    def _tab_decrypt(self, parent):
        f = self._scrollable(parent)
 
        c = self._card(f, "Parameters")
        row = tk.Frame(c, bg=PANEL); row.pack(fill="x")
        self.dec_key   = ParamEntry(row, "Key  (16-bit)", "0x006F")
        self.dec_nonce = ParamEntry(row, "Nonce / IV  (8-bit)", "111")
        self.dec_key.pack(side="left", fill="x", expand=True, padx=(0,8))
        self.dec_nonce.pack(side="left", fill="x", expand=True)
        self.dec_key.entry.bind("<FocusOut>",
            lambda e: self._validate_key(self.dec_key,16))
        self.dec_nonce.entry.bind("<FocusOut>",
            lambda e: self._validate_key(self.dec_nonce,8))
 
        # paste button
        FlatButton(c, "⬆  Paste key/nonce from Encrypt tab",
                   self._paste_params, color=MUTED,
                   font=FONT_SMALL).pack(anchor="w", pady=(6,0))
 
        # input
        c2 = self._card(f, "Ciphertext Input")
        self._dec_mode = tk.StringVar(value="hex")
        mrow = tk.Frame(c2, bg=PANEL); mrow.pack(fill="x", pady=(0,8))
        for val,lbl in [("hex","🔡  Paste Hex"), ("file","📁  Load .enc File")]:
            tk.Radiobutton(mrow, text=lbl, variable=self._dec_mode,
                           value=val, bg=PANEL, fg=TEXT,
                           selectcolor=PANEL, activebackground=PANEL,
                           font=FONT_BODY, cursor="hand2",
                           command=self._toggle_dec_input).pack(side="left",padx=(0,16))
 
        self._dec_hex_frame = tk.Frame(c2, bg=PANEL)
        self._dec_hex_frame.pack(fill="x")
        tk.Label(self._dec_hex_frame, text="Ciphertext (hex)",
                 bg=PANEL, fg=MUTED, font=FONT_SMALL, anchor="w").pack(fill="x")
        self.dec_hex = tk.Text(self._dec_hex_frame, height=4,
                               bg=ENTRY_BG, fg=TEXT, font=FONT_MONO,
                               relief="flat", insertbackground=TEXT,
                               highlightthickness=1,
                               highlightbackground=BORDER,
                               highlightcolor=CYAN)
        self.dec_hex.pack(fill="x", pady=(2,0))
 
        FlatButton(c2,"⬆  Paste ciphertext from Encrypt tab",
                   self._paste_cipher, color=MUTED,
                   font=FONT_SMALL).pack(anchor="w", pady=(6,0))
 
        self._dec_file_frame = tk.Frame(c2, bg=PANEL)
        drow = tk.Frame(self._dec_file_frame, bg=PANEL); drow.pack(fill="x")
        self._dec_file_label = tk.Label(drow, text="No file selected",
                                        bg=ENTRY_BG, fg=MUTED,
                                        font=FONT_MONO, anchor="w",
                                        padx=8, pady=8,
                                        highlightthickness=1,
                                        highlightbackground=BORDER)
        self._dec_file_label.pack(side="left",fill="x",expand=True,padx=(0,8))
        FlatButton(drow,"Browse…",self._pick_dec_file,color=ORANGE).pack(side="right")
        self._dec_file_bytes = None
 
        # output
        c3 = self._card(f, "Decrypted Output")
        self.dec_out = OutputBox(c3, height=6)
        self.dec_out.set_title("Plaintext")
        self.dec_out.pack(fill="x")
        self.dec_out.set("— Click Decrypt to see output —", color=MUTED)
 
        brow = tk.Frame(c3,bg=PANEL); brow.pack(fill="x",pady=(10,0))
        FlatButton(brow,"🔓  Decrypt",self._do_decrypt,color=ORANGE).pack(side="left",padx=(0,8))
        FlatButton(brow,"⬇  Save Decrypted File",self._save_decrypted,color=MUTED).pack(side="left")
 
        self.dec_status = tk.Label(c3,text="",bg=PANEL,fg=MUTED,
                                   font=FONT_SMALL,anchor="w")
        self.dec_status.pack(fill="x",pady=(6,0))
        self._dec_out_bytes = None
 
    def _toggle_dec_input(self):
        if self._dec_mode.get()=="hex":
            self._dec_file_frame.pack_forget()
            self._dec_hex_frame.pack(fill="x")
        else:
            self._dec_hex_frame.pack_forget()
            self._dec_file_frame.pack(fill="x")
 
    def _pick_dec_file(self):
        path = filedialog.askopenfilename(title="Select encrypted file")
        if path:
            with open(path,"rb") as f: self._dec_file_bytes = f.read()
            name = os.path.basename(path)
            self._dec_file_label.config(
                text=f"🔒  {name}  ({len(self._dec_file_bytes):,} bytes)", fg=TEXT)
 
    def _paste_params(self):
        self.dec_key.var.set(self.enc_key.get())
        self.dec_nonce.var.set(self.enc_nonce.get())
        self._validate_key(self.dec_key,16)
        self._validate_key(self.dec_nonce,8)
 
    def _paste_cipher(self):
        self.dec_hex.delete("1.0","end")
        self.dec_hex.insert("end", self._last_cipher.hex())
 
    def _do_decrypt(self):
        key = self._validate_key(self.dec_key,16)
        if key is None: return
        nonce = self._validate_key(self.dec_nonce,8)
        if nonce is None: return
 
        if self._dec_mode.get()=="hex":
            raw = self.dec_hex.get("1.0","end").strip().replace(" ","")
            if not raw:
                messagebox.showerror("Error","Paste ciphertext hex first."); return
            try: ct = bytes.fromhex(raw)
            except: messagebox.showerror("Error","Invalid hex string."); return
        else:
            if not self._dec_file_bytes:
                messagebox.showerror("Error","Select encrypted file first."); return
            ct = self._dec_file_bytes
 
        pt = ctr_process(ct, key, nonce)
        self._dec_out_bytes = pt
        try:
            text = pt.decode("utf-8", errors="replace")
            self.dec_out.set(text, color=GREEN)
        except:
            self.dec_out.set(pt.hex(), color=ORANGE)
        self.dec_status.config(
            text=f"✓  Decrypted {len(ct):,} bytes  ·  Key: 0x{key:04X}  ·  Nonce: {nonce}",
            fg=GREEN)
 
    def _save_decrypted(self):
        if not self._dec_out_bytes:
            messagebox.showinfo("Nothing to save","Decrypt something first."); return
        path = filedialog.asksaveasfilename(
            defaultextension=".dec",
            filetypes=[("All files","*.*")],
            initialfile="decrypted_output")
        if path:
            with open(path,"wb") as f: f.write(self._dec_out_bytes)
            messagebox.showinfo("Saved",f"File saved to:\n{path}")
 
    # ════════════════════════════════════════════════════
    #  TAB 3 — BRUTE FORCE
    # ════════════════════════════════════════════════════
    def _tab_brute(self, parent):
        f = self._scrollable(parent)
 
        c = self._card(f, "Target Ciphertext")
        tk.Label(c, text="Ciphertext (hex)  —  yours or another group's",
                 bg=PANEL, fg=MUTED, font=FONT_SMALL, anchor="w").pack(fill="x")
        self.bf_cipher = tk.Text(c, height=4,
                                 bg=ENTRY_BG, fg=TEXT, font=FONT_MONO,
                                 relief="flat", insertbackground=TEXT,
                                 highlightthickness=1,
                                 highlightbackground=BORDER,
                                 highlightcolor=CYAN)
        self.bf_cipher.pack(fill="x", pady=(2,8))
 
        nr = tk.Frame(c, bg=PANEL); nr.pack(fill="x")
        self.bf_nonce = ParamEntry(nr, "Nonce (8-bit)", "111")
        self.bf_nonce.pack(side="left", fill="x", expand=True, padx=(0,8))
        self.bf_nonce.entry.bind("<FocusOut>",
            lambda e: self._validate_key(self.bf_nonce,8))
        FlatButton(nr,"⬆  Use my ciphertext",self._prefill_bf,
                   color=MUTED,font=FONT_SMALL).pack(side="right",pady=(14,0))
 
        # attack mode
        c2 = self._card(f, "Attack Mode")
        self._bf_mode = tk.StringVar(value="hint")
        modes = [
            ("hint",  "🔍  Keyword Hint  —  I know a word in the message"),
            ("kpa",   "🎯  Known Plaintext  —  I know the exact beginning"),
            ("ascii", "📄  ASCII Heuristic  —  No prior knowledge (slowest)"),
        ]
        for val,lbl in modes:
            rb = tk.Radiobutton(c2, text=lbl, variable=self._bf_mode,
                                value=val, bg=PANEL, fg=TEXT,
                                selectcolor=PANEL, activebackground=PANEL,
                                font=FONT_BODY, cursor="hand2",
                                command=self._toggle_bf_mode)
            rb.pack(anchor="w", pady=2)
 
        self._bf_hint_frame = tk.Frame(c2, bg=PANEL)
        self.bf_hint = ParamEntry(self._bf_hint_frame,
                                  "Keyword (a word you expect in the message)",
                                  "project")
        self.bf_hint.pack(fill="x")
        self._bf_hint_frame.pack(fill="x", pady=(8,0))
 
        self._bf_kpa_frame = tk.Frame(c2, bg=PANEL)
        self.bf_known = ParamEntry(self._bf_kpa_frame,
                                   "Known plaintext (beginning of message)",
                                   "Hello")
        self.bf_known.pack(fill="x")
 
        # progress
        c3 = self._card(f, "Attack Progress")
        self._bf_prog_var = tk.DoubleVar()
        self.bf_prog = ttk.Progressbar(c3, variable=self._bf_prog_var,
                                       maximum=65536, length=400,
                                       style="green.Horizontal.TProgressbar")
        style = ttk.Style()
        style.configure("green.Horizontal.TProgressbar",
                        troughcolor=ENTRY_BG, background=GREEN,
                        borderwidth=0, lightcolor=GREEN, darkcolor=GREEN)
        self.bf_prog.pack(fill="x", pady=(0,6))
        self.bf_prog_label = tk.Label(c3, text="Ready",
                                      bg=PANEL, fg=MUTED, font=FONT_SMALL, anchor="w")
        self.bf_prog_label.pack(fill="x")
 
        brow = tk.Frame(c3,bg=PANEL); brow.pack(fill="x",pady=(10,0))
        self._bf_btn = FlatButton(brow,"💀  Launch Brute Force  (65,536 keys)",
                                  self._run_bf, color=RED)
        self._bf_btn.pack(side="left")
 
        # results
        c4 = self._card(f, "Results")
        self.bf_out = OutputBox(c4, height=10)
        self.bf_out.set_title("Candidates found")
        self.bf_out.pack(fill="x")
        self.bf_out.set("— Results will appear here —", color=MUTED)
 
    def _toggle_bf_mode(self):
        self._bf_hint_frame.pack_forget()
        self._bf_kpa_frame.pack_forget()
        m = self._bf_mode.get()
        if m=="hint": self._bf_hint_frame.pack(fill="x",pady=(8,0))
        elif m=="kpa": self._bf_kpa_frame.pack(fill="x",pady=(8,0))
 
    def _prefill_bf(self):
        self.bf_cipher.delete("1.0","end")
        self.bf_cipher.insert("end", self._last_cipher.hex())
        self.bf_nonce.var.set(str(self._last_nonce))
        self._validate_key(self.bf_nonce,8)
 
    def _run_bf(self):
        raw = self.bf_cipher.get("1.0","end").strip().replace(" ","")
        if not raw:
            messagebox.showerror("Error","Paste ciphertext first."); return
        try: ct = bytes.fromhex(raw)
        except: messagebox.showerror("Error","Invalid hex."); return
        nonce = self._validate_key(self.bf_nonce,8)
        if nonce is None: return
 
        mode  = self._bf_mode.get()
        hint  = self.bf_hint.get().strip()
        known = self.bf_known.get().strip().encode()
 
        self._bf_btn.config(state="disabled")
        self._bf_prog_var.set(0)
        self.bf_prog_label.config(text="Starting…", fg=MUTED)
        self.bf_out.clear()
 
        def worker():
            results = []
            for key in range(0x10000):
                candidate = ctr_process(ct, key, nonce)
                if mode=="kpa":
                    if candidate[:len(known)]==known:
                        results.append((key,candidate)); break
                elif mode=="hint":
                    try:
                        t = candidate.decode("utf-8",errors="strict")
                        if hint.lower() in t.lower():
                            results.append((key,candidate))
                    except: pass
                else:
                    if all(0x20<=b<0x7F or b in(9,10,13) for b in candidate):
                        results.append((key,candidate))
 
                if key % 2048 == 0:
                    self._bf_prog_var.set(key)
                    self.bf_prog_label.config(
                        text=f"Scanning…  {key:,} / 65,536  ·  {len(results)} hit(s)",
                        fg=MUTED)
                    self.update_idletasks()
 
            self._bf_prog_var.set(65536)
            self._bf_btn.config(state="normal")
 
            if results:
                self.bf_prog_label.config(
                    text=f"✓  Done  ·  Found {len(results)} candidate(s)", fg=GREEN)
                lines = []
                for k,pt in results[:50]:
                    try: text = pt.decode("utf-8",errors="replace")
                    except: text = pt.hex()
                    lines.append(
                        f"Key: 0x{k:04X}  ({k})  →  {text[:80]}")
                self.bf_out.set("\n".join(lines), color=GREEN)
            else:
                self.bf_prog_label.config(
                    text="✗  No candidates found — try a different mode", fg=RED)
                self.bf_out.set("No results found.\nTry: ASCII mode, or check your nonce.", color=RED)
 
        threading.Thread(target=worker, daemon=True).start()
 
    # ════════════════════════════════════════════════════
    #  TAB 4 — FREQUENCY ANALYSIS
    # ════════════════════════════════════════════════════
    def _tab_analysis(self, parent):
        f = self._scrollable(parent)
 
        c = self._card(f, "Input")
        tk.Label(c, text="Ciphertext (hex)",
                 bg=PANEL, fg=MUTED, font=FONT_SMALL, anchor="w").pack(fill="x")
        self.ana_hex = tk.Text(c, height=4,
                               bg=ENTRY_BG, fg=TEXT, font=FONT_MONO,
                               relief="flat", insertbackground=TEXT,
                               highlightthickness=1,
                               highlightbackground=BORDER,
                               highlightcolor=CYAN)
        self.ana_hex.pack(fill="x", pady=(2,8))
 
        brow = tk.Frame(c,bg=PANEL); brow.pack(fill="x")
        FlatButton(brow,"📊  Analyse",self._do_analysis,color=CYAN).pack(side="left",padx=(0,8))
        FlatButton(brow,"⬆  Use my ciphertext",self._prefill_ana,
                   color=MUTED,font=FONT_SMALL).pack(side="left")
 
        c2 = self._card(f,"Results")
        self.ana_out = OutputBox(c2, height=18)
        self.ana_out.set_title("Frequency Analysis Report")
        self.ana_out.pack(fill="x")
        self.ana_out.set("— Click Analyse to see results —", color=MUTED)
 
    def _prefill_ana(self):
        self.ana_hex.delete("1.0","end")
        self.ana_hex.insert("end", self._last_cipher.hex())
 
    def _do_analysis(self):
        raw = self.ana_hex.get("1.0","end").strip().replace(" ","")
        if not raw:
            messagebox.showerror("Error","Paste ciphertext first."); return
        try: data = bytes.fromhex(raw)
        except: messagebox.showerror("Error","Invalid hex."); return
 
        freq, ioc = frequency_analysis(data)
        n = len(data)
        unique = len(freq)
 
        lines = []
        lines.append("═"*52)
        lines.append("  S-AES CTR — Frequency Analysis Report")
        lines.append("═"*52)
        lines.append(f"\n  Total bytes   : {n:,}")
        lines.append(f"  Unique bytes  : {unique}")
        lines.append(f"\n  Index of Coincidence (IoC)")
        lines.append(f"  ─────────────────────────")
        lines.append(f"  Your ciphertext : {ioc:.6f}")
        lines.append(f"  English text    : ~0.065000  (structured)")
        lines.append(f"  Random / CTR    : ~0.038000  (flat)")
 
        if ioc < 0.045:
            lines.append(f"\n  ✓  IoC is low → CTR mode is working correctly.")
            lines.append(f"     Output looks pseudo-random (good!)")
        else:
            lines.append(f"\n  ⚠  IoC is high → output may not be random.")
 
        lines.append(f"\n  Top 10 most frequent bytes")
        lines.append(f"  ──────────────────────────")
        lines.append(f"  {'Byte':>6}  {'Hex':>5}  {'Count':>6}  {'Bar'}")
        lines.append(f"  {'─'*6}  {'─'*5}  {'─'*6}  {'─'*20}")
        top = sorted(freq.items(), key=lambda x:-x[1])[:10]
        max_c = top[0][1] if top else 1
        for b,cnt in top:
            bar = "█" * int(cnt/max_c*20)
            lines.append(f"  {b:>6}  0x{b:02X}  {cnt:>6}  {bar}")
 
        lines.append(f"\n  Full byte distribution ({unique} unique values)")
        lines.append(f"  ─────────────────────────────────────────")
        for b in range(256):
            if b in freq:
                lines.append(f"  0x{b:02X} ({b:3d}) : {'▪'*freq[b]} {freq[b]}")
 
        self.ana_out.set("\n".join(lines), color=GREEN)
 
 
# ═══════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════
 
if __name__ == "__main__":
    app = App()
    app.mainloop()
 
saes_gui.py
 