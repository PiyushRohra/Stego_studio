"""
Stego Studio
------------
Hide encrypted text inside an image (LSB steganography) with public-key crypto.

Install:   pip install pillow cryptography customtkinter
Run:       python stego_studio.py

Keys (paste with or without BEGIN/END lines, or load from a file):
  PEM, bare base64 / base64url, hex, DER, OpenSSH public keys
  RSA (any size), EC (P-256/384/521, secp256k1...), X25519, X448
Not supported: signing-only keys (Ed25519, Ed448, DSA), password-protected keys.
Need a key pair? Open the "Keys" page in the app and generate one.

Images are always saved as PNG. JPEG would destroy the hidden data.
"""

import base64
import binascii
import math
import os
import queue
import re
import struct
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog

import customtkinter as ctk
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519, x448
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from PIL import Image

MAGIC = b"STG3"          # marks an image as containing our data
HEADER_SIZE = 8          # 4 bytes magic + 4 bytes payload length
RSA_BYTES = 2048 // 8

OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(), label=None)


# ============================================================================
# Crypto layer (any asymmetric key: PUBLIC key encrypts, PRIVATE key decrypts)
# ============================================================================
SCHEME_RSA, SCHEME_EC, SCHEME_X25519, SCHEME_X448 = 1, 2, 3, 4
PUB_TYPES = (rsa.RSAPublicKey, ec.EllipticCurvePublicKey,
             x25519.X25519PublicKey, x448.X448PublicKey)
PRIV_TYPES = (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey,
              x25519.X25519PrivateKey, x448.X448PrivateKey)
PEM_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END", re.S)


def _decode_blob(text: str) -> bytes:
    """Decode bare base64 / base64url / hex text into bytes."""
    t = re.sub(r"\s+", "", text)
    if not t:
        raise ValueError("Key is empty.")
    for decoder in (lambda s: base64.b64decode(s + "=" * (-len(s) % 4), validate=True),
                    lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)),
                    bytes.fromhex):
        try:
            return decoder(t)
        except (binascii.Error, ValueError):
            continue
    raise ValueError("Key is not valid PEM, base64, hex or OpenSSH text.")


def _pem_rebuilt(text: str):
    """Re-wrap a PEM block even if newlines/spaces got mangled by pasting."""
    m = PEM_RE.search(text)
    if not m:
        return None
    label, body = m.group(1), re.sub(r"\s+", "", m.group(2))
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return (f"-----BEGIN {label}-----\n" + "\n".join(lines)
            + f"\n-----END {label}-----\n").encode()


def _check_pub(key):
    if isinstance(key, PUB_TYPES):
        return key
    raise ValueError("This key type can't encrypt (signing-only keys such as "
                     "Ed25519/DSA are not supported). Use RSA, EC, X25519 or X448.")


def parse_public_key(text: str):
    text = text.strip()
    if not text:
        raise ValueError("Key is empty.")
    try:
        pem = _pem_rebuilt(text)
        if pem:
            try:
                return _check_pub(serialization.load_pem_public_key(pem))
            except ValueError as e:
                if "can't encrypt" in str(e):
                    raise
                return _check_pub(serialization.load_pem_private_key(pem, None).public_key())
        if text.startswith(("ssh-", "ecdsa-", "sk-")):
            return _check_pub(serialization.load_ssh_public_key(text.encode()))
        data = _decode_blob(text)
        if len(data) == 32:
            return x25519.X25519PublicKey.from_public_bytes(data)
        if len(data) == 56:
            return x448.X448PublicKey.from_public_bytes(data)
        try:
            return _check_pub(serialization.load_der_public_key(data))
        except ValueError as e:
            if "can't encrypt" in str(e):
                raise
            return _check_pub(serialization.load_der_private_key(data, None).public_key())
    except ValueError as e:
        if "can't encrypt" in str(e) or "not valid" in str(e) or "empty" in str(e):
            raise
        raise ValueError("Could not read this as a public key.")
    except Exception:
        raise ValueError("Could not read this as a public key.")


def parse_private_key(text: str):
    text = text.strip()
    if not text:
        raise ValueError("Key is empty.")
    try:
        pem = _pem_rebuilt(text)
        if pem:
            key = serialization.load_pem_private_key(pem, None)
        else:
            data = _decode_blob(text)
            if len(data) == 32:
                key = x25519.X25519PrivateKey.from_private_bytes(data)
            elif len(data) == 56:
                key = x448.X448PrivateKey.from_private_bytes(data)
            else:
                key = serialization.load_der_private_key(data, None)
    except Exception:
        raise ValueError("Could not read this as a private key "
                         "(password-protected keys are not supported).")
    if not isinstance(key, PRIV_TYPES):
        raise ValueError("This key type can't decrypt (use RSA, EC, X25519 or X448).")
    return key


def _kdf(shared: bytes) -> bytes:
    k = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"stego-v3").derive(shared)
    return base64.urlsafe_b64encode(k)          # Fernet key format


def wrapped_len(pub) -> int:
    """Length of the per-message key material stored in the image."""
    if isinstance(pub, rsa.RSAPublicKey):
        return pub.key_size // 8
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return 1 + 2 * ((pub.curve.key_size + 7) // 8)
    if isinstance(pub, x25519.X25519PublicKey):
        return 32
    return 56


def encrypt_text(message: str, pub) -> bytes:
    """scheme(1) + wrapped_len(2) + wrapped + Fernet token."""
    if isinstance(pub, rsa.RSAPublicKey):
        scheme, aes = SCHEME_RSA, Fernet.generate_key()
        wrapped = pub.encrypt(aes, OAEP)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        scheme = SCHEME_EC
        eph = ec.generate_private_key(pub.curve)
        aes = _kdf(eph.exchange(ec.ECDH(), pub))
        wrapped = eph.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    else:
        scheme, cls = ((SCHEME_X25519, x25519.X25519PrivateKey)
                       if isinstance(pub, x25519.X25519PublicKey)
                       else (SCHEME_X448, x448.X448PrivateKey))
        eph = cls.generate()
        aes = _kdf(eph.exchange(pub))
        wrapped = eph.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    token = Fernet(aes).encrypt(message.encode("utf-8"))
    return bytes([scheme]) + struct.pack(">H", len(wrapped)) + wrapped + token


def decrypt_text(blob: bytes, priv) -> str:
    if len(blob) < 3:
        raise ValueError("Hidden data is corrupted.")
    scheme, wl = blob[0], struct.unpack(">H", blob[1:3])[0]
    wrapped, token = blob[3:3 + wl], blob[3 + wl:]
    try:
        if scheme == SCHEME_RSA and isinstance(priv, rsa.RSAPrivateKey):
            aes = priv.decrypt(wrapped, OAEP)
        elif scheme == SCHEME_EC and isinstance(priv, ec.EllipticCurvePrivateKey):
            peer = ec.EllipticCurvePublicKey.from_encoded_point(priv.curve, wrapped)
            aes = _kdf(priv.exchange(ec.ECDH(), peer))
        elif scheme == SCHEME_X25519 and isinstance(priv, x25519.X25519PrivateKey):
            aes = _kdf(priv.exchange(x25519.X25519PublicKey.from_public_bytes(wrapped)))
        elif scheme == SCHEME_X448 and isinstance(priv, x448.X448PrivateKey):
            aes = _kdf(priv.exchange(x448.X448PublicKey.from_public_bytes(wrapped)))
        else:
            raise ValueError("This image was encrypted with a different key type.")
        return Fernet(aes).decrypt(token).decode("utf-8")
    except InvalidToken:
        raise ValueError("Wrong private key, or the image has been modified.")
    except ValueError as e:
        if "different key type" in str(e):
            raise
        raise ValueError("Wrong private key, or the image has been modified.")


def estimate_payload_size(plain_len: int, wrap_bytes: int = RSA_BYTES) -> int:
    """Size of header + wrapped key + Fernet token for a plaintext of plain_len bytes."""
    padded = (plain_len // 16 + 1) * 16
    raw = 1 + 8 + 16 + padded + 32
    return 3 + wrap_bytes + 4 * math.ceil(raw / 3)


def describe_key(key) -> str:
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return f"RSA-{key.key_size}"
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return f"EC {key.curve.name}"
    if isinstance(key, (x25519.X25519PublicKey, x25519.X25519PrivateKey)):
        return "X25519"
    return "X448"


ALGOS = {
    "X25519  (small, fast, recommended)": lambda: x25519.X25519PrivateKey.generate(),
    "RSA 2048": lambda: rsa.generate_private_key(65537, 2048),
    "RSA 3072": lambda: rsa.generate_private_key(65537, 3072),
    "RSA 4096": lambda: rsa.generate_private_key(65537, 4096),
    "EC P-256": lambda: ec.generate_private_key(ec.SECP256R1()),
    "EC P-384": lambda: ec.generate_private_key(ec.SECP384R1()),
    "EC P-521": lambda: ec.generate_private_key(ec.SECP521R1()),
    "X448": lambda: x448.X448PrivateKey.generate(),
}


def generate_keypair(name: str):
    k = ALGOS[name]()
    pub = k.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    priv = k.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    return pub, priv


# ============================================================================
# Steganography layer (LSB embedding)
# ============================================================================
def capacity_from_size(size) -> int:
    w, h = size
    return max((w * h * 3) // 8 - HEADER_SIZE, 0)


def embed(image_path: str, payload: bytes, out_path: str) -> None:
    img = Image.open(image_path).convert("RGB")
    cap = capacity_from_size(img.size)
    if len(payload) > cap:
        raise ValueError(f"Message too large. Needs {len(payload)} bytes, image holds {cap}.")
    data = MAGIC + struct.pack(">I", len(payload)) + payload
    raw = bytearray(img.tobytes())
    for i in range(len(data) * 8):
        bit = (data[i // 8] >> (7 - i % 8)) & 1
        raw[i] = (raw[i] & 0xFE) | bit
    Image.frombytes("RGB", img.size, bytes(raw)).save(out_path, "PNG")


def _read_bytes(raw: bytes, start: int, n: int) -> bytes:
    out = bytearray()
    for j in range(start, start + n):
        val = 0
        for k in range(8):
            val = (val << 1) | (raw[j * 8 + k] & 1)
        out.append(val)
    return bytes(out)


def extract(image_path: str) -> bytes:
    img = Image.open(image_path).convert("RGB")
    raw = img.tobytes()
    if len(raw) // 8 < HEADER_SIZE:
        raise ValueError("Image is too small to contain hidden data.")
    header = _read_bytes(raw, 0, HEADER_SIZE)
    if header[:4] != MAGIC:
        raise ValueError("No hidden message found in this image.")
    length = struct.unpack(">I", header[4:])[0]
    if length > capacity_from_size(img.size):
        raise ValueError("Hidden data is corrupted.")
    return _read_bytes(raw, HEADER_SIZE, length)


# ============================================================================
# Look and feel
# ============================================================================
IS_WIN = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"
MONO = "Consolas" if IS_WIN else "Menlo" if IS_MAC else "DejaVu Sans Mono"

# (light, dark) pairs
BG = ("#eef1f5", "#0d1218")
SIDEBAR = ("#ffffff", "#111820")
CARD = ("#ffffff", "#151d26")
INSET = ("#f1f4f8", "#0f161d")
LINE = ("#dde3ea", "#25303c")
TEXT = ("#101828", "#e6ebf1")
MUTED = ("#5b6676", "#8b98a8")
HOVER = ("#e6ebf1", "#1e2833")
NAV_ON = ("#e3e9ff", "#1b2748")
ACCENT, ACCENT_H = "#3d5afe", "#2f48d6"
GREEN, RED, AMBER = "#22b573", "#ef4444", "#f59e0b"

PREVIEW_W, PREVIEW_H = 340, 260


def F(size=13, bold=False):
    return ctk.CTkFont(size=size, weight="bold" if bold else "normal")


def ghost(parent, text, command, width=64, height=26):
    return ctk.CTkButton(parent, text=text, command=command, width=width, height=height,
                         corner_radius=8, fg_color="transparent", border_width=1,
                         border_color=LINE, text_color=TEXT, hover_color=HOVER, font=F(12))


def primary(parent, text, command, height=46):
    return ctk.CTkButton(parent, text=text, command=command, height=height, corner_radius=12,
                         fg_color=ACCENT, hover_color=ACCENT_H, text_color="white",
                         font=F(15, True))


class Card(ctk.CTkFrame):
    def __init__(self, master, **kw):
        super().__init__(master, corner_radius=16, fg_color=CARD, border_width=1,
                         border_color=LINE, **kw)


def title_block(parent, title, subtitle):
    box = ctk.CTkFrame(parent, fg_color="transparent")
    ctk.CTkLabel(box, text=title, font=F(18, True), text_color=TEXT, anchor="w"
                 ).pack(fill="x")
    ctk.CTkLabel(box, text=subtitle, font=F(12), text_color=MUTED, anchor="w",
                 justify="left", wraplength=420).pack(fill="x", pady=(2, 0))
    return box


def show_in_folder(path):
    try:
        if IS_WIN:
            subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
        elif IS_MAC:
            subprocess.Popen(["open", "-R", path])
        else:
            subprocess.Popen(["xdg-open", os.path.dirname(path) or "."])
    except Exception:
        pass


def read_key_file(path):
    data = open(path, "rb").read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return base64.b64encode(data).decode()      # raw DER file


# ============================================================================
# Reusable widgets
# ============================================================================
class ImageCard(Card):
    """Image preview + choose button. Click the preview to choose too."""

    def __init__(self, master, title, subtitle, button_text, on_load):
        super().__init__(master)
        self.on_load = on_load
        self.path = None
        self.size = None

        title_block(self, title, subtitle).pack(fill="x", padx=22, pady=(20, 14))

        self.preview = ctk.CTkLabel(
            self, text="🖼\n\nClick to choose an image", width=PREVIEW_W, height=PREVIEW_H,
            fg_color=INSET, corner_radius=12, text_color=MUTED, font=F(13))
        self.preview.pack(padx=22)
        self.preview.bind("<Button-1>", lambda e: self.choose())

        self.info = ctk.CTkLabel(self, text="PNG, JPG, BMP or WebP", text_color=MUTED,
                                 justify="left", anchor="w", font=F(12))
        self.info.pack(fill="x", padx=22, pady=(12, 0))

        ctk.CTkButton(self, text=button_text, height=40, corner_radius=10,
                      fg_color="transparent", border_width=1, border_color=LINE,
                      text_color=TEXT, hover_color=HOVER, font=F(14, True),
                      command=self.choose).pack(fill="x", padx=22, pady=(12, 22), side="bottom")

    def choose(self):
        path = filedialog.askopenfilename(
            title="Select image",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.webp"), ("All files", "*.*")])
        if path:
            self.load(path)

    def load(self, path):
        try:
            img = Image.open(path)
            img.load()
        except Exception as e:
            self.on_load(None, None, error=str(e))
            return
        self.path, self.size = path, img.size
        thumb = img.convert("RGB")
        thumb.thumbnail((PREVIEW_W - 8, PREVIEW_H - 8))
        self._photo = ctk.CTkImage(light_image=thumb, dark_image=thumb, size=thumb.size)
        self.preview.configure(image=self._photo, text="")
        self.info.configure(
            text=f"{os.path.basename(path)}\n{img.size[0]} × {img.size[1]} px  ·  "
                 f"holds up to {capacity_from_size(img.size):,} bytes")
        self.on_load(path, img.size)


class KeyBox(ctk.CTkFrame):
    """Editable key field with paste / load / clear and live validation."""

    def __init__(self, master, title, kind, on_change=None, height=110):
        super().__init__(master, fg_color="transparent")
        self.kind, self.on_change, self.key, self._job = kind, on_change, None, None
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(1, weight=1)
        ctk.CTkLabel(top, text=title, font=F(13, True), text_color=TEXT
                     ).grid(row=0, column=0, sticky="w")
        self.badge = ctk.CTkLabel(top, text="", font=F(12), text_color=MUTED, anchor="w")
        self.badge.grid(row=0, column=1, sticky="w", padx=(10, 0))
        btns = ctk.CTkFrame(top, fg_color="transparent")
        btns.grid(row=0, column=2, sticky="e")
        ghost(btns, "Paste", self.paste, 56).pack(side="left", padx=(0, 4))
        ghost(btns, "Open file", self.load_file, 74).pack(side="left", padx=(0, 4))
        ghost(btns, "Clear", lambda: self.set(""), 52).pack(side="left")

        self.box = ctk.CTkTextbox(self, height=height, corner_radius=10, border_width=1,
                                  border_color=LINE, fg_color=INSET, text_color=TEXT,
                                  font=ctk.CTkFont(family=MONO, size=11), wrap="char")
        self.box.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        self.box.bind("<KeyRelease>", lambda e: self._changed())
        self.box.bind("<<Paste>>", lambda e: self._changed())

    def get(self):
        return self.box.get("1.0", "end").strip()

    def set(self, text):
        self.box.delete("1.0", "end")
        self.box.insert("1.0", text)
        self._validate()

    def paste(self):
        try:
            self.set(self.clipboard_get())
        except tk.TclError:
            self.badge.configure(text="Clipboard is empty", text_color=AMBER)

    def load_file(self):
        path = filedialog.askopenfilename(title="Open key file",
                                          filetypes=[("Key files", "*.pem *.pub *.key *.der *.txt"),
                                                     ("All files", "*.*")])
        if path:
            try:
                self.set(read_key_file(path))
            except Exception as e:
                self.badge.configure(text=f"Cannot read file: {e}", text_color=RED)

    def _changed(self):
        if self._job:
            self.after_cancel(self._job)
        self._job = self.after(250, self._validate)

    def _validate(self):
        self._job = None
        text = self.get()
        self.key = None
        if not text:
            self.badge.configure(text="", text_color=MUTED)
        else:
            try:
                parse = parse_public_key if self.kind == "public" else parse_private_key
                self.key = parse(text)
                self.badge.configure(text=f"✔  {describe_key(self.key)} {self.kind} key",
                                     text_color=GREEN)
            except Exception as e:
                msg = str(e)
                if "can't" in msg:
                    short = "Signing-only key, can't be used"
                elif "password" in msg:
                    short = "Password-protected keys aren't supported"
                else:
                    short = "Not recognised as a key"
                self.badge.configure(text=f"✖  {short}", text_color=RED)
        if self.on_change:
            self.on_change()


class KeyView(ctk.CTkFrame):
    """Read-only key display with action buttons."""

    def __init__(self, master, title, hint, actions):
        super().__init__(master, fg_color="transparent")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        ctk.CTkLabel(self, text=title, font=F(14, True), text_color=TEXT, anchor="w"
                     ).grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(self, text=hint, font=F(12), text_color=MUTED, anchor="w",
                     justify="left", wraplength=360).grid(row=1, column=0, sticky="ew", pady=(2, 8))
        self.box = ctk.CTkTextbox(self, corner_radius=10, border_width=1, border_color=LINE,
                                  fg_color=INSET, text_color=TEXT, wrap="char",
                                  font=ctk.CTkFont(family=MONO, size=11), state="disabled")
        self.box.grid(row=2, column=0, sticky="nsew")
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        for text, cmd in actions:
            ghost(row, text, cmd, width=10, height=30).pack(side="left", padx=(0, 6))

    def set(self, text):
        self.box.configure(state="normal")
        self.box.delete("1.0", "end")
        self.box.insert("1.0", text)
        self.box.configure(state="disabled")

    def get(self):
        return self.box.get("1.0", "end").strip()


# ============================================================================
# Pages
# ============================================================================
class HidePage(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app, self.saved = app, None
        self.columnconfigure(0, weight=4, uniform="c")
        self.columnconfigure(1, weight=5, uniform="c")
        self.rowconfigure(0, weight=1)

        self.card = ImageCard(self, "Cover image",
                              "The image that will carry your message.",
                              "Choose cover image…", self._on_image)
        self.card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        right = Card(self)
        right.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        right.columnconfigure(0, weight=1)
        right.rowconfigure(3, weight=1)
        pad = dict(padx=22, sticky="ew")

        title_block(right, "Message and key",
                    "Only the owner of the matching private key can read it."
                    ).grid(row=0, pady=(20, 12), **pad)

        self.msg = ctk.CTkTextbox(right, height=100, corner_radius=10, border_width=1,
                                  border_color=LINE, fg_color=INSET, text_color=TEXT,
                                  font=F(13))
        self.msg.grid(row=1, **pad)
        self.msg.bind("<KeyRelease>", lambda e: self._update_capacity())

        meter = ctk.CTkFrame(right, fg_color="transparent")
        meter.grid(row=2, pady=(10, 14), **pad)
        meter.columnconfigure(0, weight=1)
        self.cap_label = ctk.CTkLabel(meter, text="Choose an image to see how much fits.",
                                      text_color=MUTED, font=F(12), anchor="w")
        self.cap_label.grid(row=0, column=0, sticky="ew")
        self.cap_bar = ctk.CTkProgressBar(meter, height=6, progress_color=ACCENT,
                                          fg_color=INSET)
        self.cap_bar.set(0)
        self.cap_bar.grid(row=1, column=0, sticky="ew", pady=(6, 0))

        self.key = KeyBox(right, "Receiver's public key", "public",
                          on_change=self._update_capacity, height=110)
        self.key.grid(row=3, pady=(0, 14), **{**pad, "sticky": "nsew"})

        self.btn = primary(right, "Encrypt and hide", self.do_hide)
        self.btn.grid(row=4, **pad)
        self.open_btn = ctk.CTkButton(
            right, text="Show saved file", height=34, corner_radius=10, state="disabled",
            fg_color="transparent", border_width=1, border_color=LINE, text_color=TEXT,
            hover_color=HOVER, font=F(13), command=lambda: show_in_folder(self.saved))
        self.open_btn.grid(row=5, pady=(8, 22), **pad)

    def _on_image(self, path, size, error=None):
        if error:
            return self.app.set_status(f"Can't open that image: {error}", "error")
        self.app.set_status(f"Loaded {os.path.basename(path)}", "info")
        self._update_capacity()

    def _update_capacity(self):
        if not self.card.size:
            return
        cap = capacity_from_size(self.card.size)
        n = len(self.msg.get("1.0", "end").strip().encode("utf-8"))
        wl = wrapped_len(self.key.key) if self.key.key is not None else RSA_BYTES
        used = estimate_payload_size(n, wl) if n else 0
        ratio = used / cap if cap else 1
        self.cap_bar.set(min(ratio, 1))
        color = RED if ratio > 1 else AMBER if ratio > 0.7 else ACCENT
        self.cap_bar.configure(progress_color=color)
        if ratio > 1:
            self.cap_label.configure(
                text=f"Too long: needs {used:,} bytes, this image holds {cap:,}.",
                text_color=RED)
        else:
            self.cap_label.configure(
                text=f"Uses {used:,} of {cap:,} bytes ({ratio:.0%})", text_color=MUTED)

    def do_hide(self):
        msg = self.msg.get("1.0", "end").strip()
        key_text = self.key.get()
        if not self.card.path:
            return self.app.set_status("Choose a cover image first.", "error")
        if not msg:
            return self.app.set_status("Type the message you want to hide.", "error")
        if not key_text:
            return self.app.set_status("Paste the receiver's public key.", "error")
        try:
            pub = parse_public_key(key_text)
        except ValueError as e:
            return self.app.set_status(str(e), "error")
        size = estimate_payload_size(len(msg.encode("utf-8")), wrapped_len(pub))
        if size > capacity_from_size(self.card.size):
            return self.app.set_status("The message is too long for this image. "
                                       "Shorten it or pick a larger image.", "error")
        out = filedialog.asksaveasfilename(
            title="Save image with hidden message", defaultextension=".png",
            initialfile="hidden.png", filetypes=[("PNG image", "*.png")])
        if not out:
            return
        self.btn.configure(state="disabled", text="Working…")
        self.open_btn.configure(state="disabled")
        self.app.set_status("Encrypting and embedding…", "info")
        src = self.card.path
        self.app.run_async(lambda: embed(src, encrypt_text(msg, pub), out),
                           lambda _res, err: self._done(err, out))

    def _done(self, err, out):
        self.btn.configure(state="normal", text="Encrypt and hide")
        if err:
            self.app.set_status(err, "error")
        else:
            self.saved = out
            self.open_btn.configure(state="normal")
            self.app.set_status(f"Message hidden. Saved to {out}", "ok")


class RevealPage(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.columnconfigure(0, weight=4, uniform="c")
        self.columnconfigure(1, weight=5, uniform="c")
        self.rowconfigure(0, weight=1)

        self.card = ImageCard(self, "Image with hidden message",
                              "Use the PNG file you were sent, not a screenshot or JPEG.",
                              "Choose image…", self._on_image)
        self.card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        right = Card(self)
        right.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        right.columnconfigure(0, weight=1)
        right.rowconfigure(4, weight=1)
        pad = dict(padx=22, sticky="ew")

        title_block(right, "Your private key",
                    "It stays on this computer and is never saved."
                    ).grid(row=0, pady=(20, 12), **pad)

        self.key = KeyBox(right, "Private key", "private", height=100)
        self.key.grid(row=1, pady=(0, 14), **pad)

        self.btn = primary(right, "Extract and decrypt", self.do_reveal)
        self.btn.grid(row=2, pady=(0, 16), **pad)

        ctk.CTkLabel(right, text="Recovered message", font=F(13, True), text_color=TEXT,
                     anchor="w").grid(row=3, pady=(0, 6), **pad)
        self.out = ctk.CTkTextbox(right, corner_radius=10, border_width=1, border_color=LINE,
                                  fg_color=INSET, text_color=TEXT, font=F(13),
                                  state="disabled")
        self.out.grid(row=4, **{**pad, "sticky": "nsew"})

        row = ctk.CTkFrame(right, fg_color="transparent")
        row.grid(row=5, pady=(10, 22), **pad)
        ghost(row, "Copy", self.copy, width=80, height=32).pack(side="left", padx=(0, 6))
        ghost(row, "Save as .txt", self.save, width=100, height=32).pack(side="left")

    def _on_image(self, path, size, error=None):
        if error:
            return self.app.set_status(f"Can't open that image: {error}", "error")
        if path.lower().endswith((".jpg", ".jpeg")):
            self.app.set_status("JPEG files lose hidden data. Use the original PNG.", "warn")
        else:
            self.app.set_status(f"Loaded {os.path.basename(path)}", "info")

    def _set_output(self, text):
        self.out.configure(state="normal")
        self.out.delete("1.0", "end")
        self.out.insert("1.0", text)
        self.out.configure(state="disabled")

    def do_reveal(self):
        key_text = self.key.get()
        if not self.card.path:
            return self.app.set_status("Choose the image first.", "error")
        if not key_text:
            return self.app.set_status("Paste your private key.", "error")
        try:
            priv = parse_private_key(key_text)
        except ValueError as e:
            return self.app.set_status(str(e), "error")
        self.btn.configure(state="disabled", text="Working…")
        self.app.set_status("Extracting and decrypting…", "info")
        path = self.card.path
        self.app.run_async(lambda: decrypt_text(extract(path), priv), self._done)

    def _done(self, text, err):
        self.btn.configure(state="normal", text="Extract and decrypt")
        if err:
            self._set_output("")
            self.app.set_status(err, "error")
        else:
            self._set_output(text)
            self.app.set_status("Message recovered.", "ok")

    def _text(self):
        return self.out.get("1.0", "end").strip()

    def copy(self):
        text = self._text()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.app.set_status("Copied to clipboard.", "ok")

    def save(self):
        text = self._text()
        if not text:
            return self.app.set_status("There is no message to save yet.", "error")
        path = filedialog.asksaveasfilename(title="Save message", defaultextension=".txt",
                                            initialfile="message.txt",
                                            filetypes=[("Text file", "*.txt")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            self.app.set_status(f"Saved to {path}", "ok")


class KeysPage(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        card = Card(self)
        card.grid(row=0, column=0, sticky="nsew")
        card.columnconfigure((0, 1), weight=1, uniform="k")
        card.rowconfigure(2, weight=1)

        title_block(card, "Generate a key pair",
                    "Give the public key to anyone who wants to send you a hidden message. "
                    "Keep the private key to yourself."
                    ).grid(row=0, column=0, columnspan=2, sticky="ew", padx=24, pady=(22, 14))

        bar = ctk.CTkFrame(card, fg_color="transparent")
        bar.grid(row=1, column=0, columnspan=2, sticky="ew", padx=24, pady=(0, 16))
        self.algo = ctk.CTkOptionMenu(bar, values=list(ALGOS), width=280, height=40,
                                      corner_radius=10, font=F(13), dropdown_font=F(13),
                                      fg_color=INSET, button_color=LINE,
                                      button_hover_color=HOVER, text_color=TEXT)
        self.algo.pack(side="left")
        self.gen = ctk.CTkButton(bar, text="Generate keys", height=40, width=160,
                                 corner_radius=10, fg_color=ACCENT, hover_color=ACCENT_H,
                                 text_color="white", font=F(14, True), command=self.generate)
        self.gen.pack(side="left", padx=(12, 0))

        self.pub = KeyView(card, "Public key", "Safe to share.",
                           [("Copy", lambda: self._copy(self.pub)),
                            ("Save file", lambda: self._save(self.pub, "public_key.pem", False)),
                            ("Use on Hide page", self._to_hide)])
        self.pub.grid(row=2, column=0, sticky="nsew", padx=(24, 10), pady=(0, 24))
        self.priv = KeyView(card, "Private key", "Never share this. Anyone with it can read your messages.",
                            [("Copy", lambda: self._copy(self.priv)),
                             ("Save file", lambda: self._save(self.priv, "private_key.pem", True)),
                             ("Use on Reveal page", self._to_reveal)])
        self.priv.grid(row=2, column=1, sticky="nsew", padx=(10, 24), pady=(0, 24))

    def generate(self):
        name = self.algo.get()
        self.gen.configure(state="disabled", text="Generating…")
        self.app.set_status(f"Generating {name.split('  ')[0]} key pair…", "info")
        self.app.run_async(lambda: generate_keypair(name), self._done)

    def _done(self, res, err):
        self.gen.configure(state="normal", text="Generate keys")
        if err:
            return self.app.set_status(err, "error")
        self.pub.set(res[0].strip())
        self.priv.set(res[1].strip())
        self.app.set_status("Key pair ready. Save the private key somewhere safe.", "ok")

    def _copy(self, view):
        text = view.get()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.app.set_status("Copied to clipboard.", "ok")
        else:
            self.app.set_status("Generate a key pair first.", "error")

    def _save(self, view, name, private):
        text = view.get()
        if not text:
            return self.app.set_status("Generate a key pair first.", "error")
        path = filedialog.asksaveasfilename(title="Save key", defaultextension=".pem",
                                            initialfile=name,
                                            filetypes=[("PEM key", "*.pem")])
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        if private:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        self.app.set_status(f"Saved to {path}", "ok")

    def _to_hide(self):
        if not self.pub.get():
            return self.app.set_status("Generate a key pair first.", "error")
        self.app.pages["hide"].key.set(self.pub.get())
        self.app.show_page("hide")
        self.app.set_status("Public key added to the Hide page.", "ok")

    def _to_reveal(self):
        if not self.priv.get():
            return self.app.set_status("Generate a key pair first.", "error")
        self.app.pages["reveal"].key.set(self.priv.get())
        self.app.show_page("reveal")
        self.app.set_status("Private key added to the Reveal page.", "ok")


# ============================================================================
# Main window
# ============================================================================
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.title("Stego Studio")
        self.geometry("1120x800")
        self.minsize(1020, 760)
        self.configure(fg_color=BG)

        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        # ---- sidebar ----
        side = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color=SIDEBAR)
        side.grid(row=0, column=0, rowspan=2, sticky="nsew")
        side.grid_propagate(False)
        side.rowconfigure(5, weight=1)
        side.columnconfigure(0, weight=1)

        ctk.CTkLabel(side, text="Stego Studio", font=F(21, True), text_color=TEXT
                     ).grid(row=0, column=0, padx=22, pady=(30, 2), sticky="w")
        ctk.CTkLabel(side, text="Hide encrypted text\ninside images", text_color=MUTED,
                     font=F(12), justify="left").grid(row=1, column=0, padx=22, pady=(0, 26),
                                                      sticky="w")

        self.nav = {}
        items = [("hide", "🔒   Hide message"), ("reveal", "🔓   Reveal message"),
                 ("keys", "🔑   Keys")]
        for i, (key, label) in enumerate(items):
            b = ctk.CTkButton(side, text=label, anchor="w", height=42, corner_radius=10,
                              fg_color="transparent", text_color=TEXT, hover_color=HOVER,
                              font=F(14, True), command=lambda k=key: self.show_page(k))
            b.grid(row=2 + i, column=0, padx=14, pady=3, sticky="ew")
            self.nav[key] = b

        self.mode = ctk.CTkSwitch(side, text="Dark mode", command=self._toggle_mode,
                                  text_color=TEXT, progress_color=ACCENT, font=F(13))
        self.mode.select()
        self.mode.grid(row=6, column=0, padx=22, pady=(0, 10), sticky="w")
        ctk.CTkLabel(side, text="RSA · EC · X25519 · X448\nAES encryption · LSB",
                     text_color=MUTED, font=F(11), justify="left"
                     ).grid(row=7, column=0, padx=22, pady=(0, 22), sticky="w")

        # ---- pages ----
        holder = ctk.CTkFrame(self, fg_color="transparent")
        holder.grid(row=0, column=1, sticky="nsew", padx=22, pady=(22, 12))
        holder.rowconfigure(0, weight=1)
        holder.columnconfigure(0, weight=1)
        self.pages = {"hide": HidePage(holder, self), "reveal": RevealPage(holder, self),
                      "keys": KeysPage(holder, self)}
        for p in self.pages.values():
            p.grid(row=0, column=0, sticky="nsew")

        # ---- status bar ----
        bar = ctk.CTkFrame(self, height=42, corner_radius=12, fg_color=CARD,
                           border_width=1, border_color=LINE)
        bar.grid(row=1, column=1, sticky="ew", padx=22, pady=(0, 18))
        bar.columnconfigure(1, weight=1)
        self.status_icon = ctk.CTkLabel(bar, text="●", text_color=MUTED, font=F(13), width=20)
        self.status_icon.grid(row=0, column=0, padx=(14, 4), pady=9)
        self.status_text = ctk.CTkLabel(bar, text="Ready.", anchor="w", text_color=TEXT,
                                        font=F(13))
        self.status_text.grid(row=0, column=1, sticky="ew")
        self.spinner = ctk.CTkProgressBar(bar, mode="indeterminate", width=110, height=5,
                                          progress_color=ACCENT, fg_color=INSET)
        self.spinner.grid(row=0, column=2, padx=14)
        self.spinner.grid_remove()

        self.show_page("hide")

    def show_page(self, key):
        self.pages[key].tkraise()
        for k, b in self.nav.items():
            b.configure(fg_color=NAV_ON if k == key else "transparent")

    def run_async(self, func, callback):
        """Run func in a thread; call callback(result, error) on the UI thread."""
        q = queue.Queue()
        self.spinner.grid()
        self.spinner.start()

        def work():
            try:
                q.put((func(), None))
            except Exception as e:
                q.put((None, str(e)))

        def poll():
            try:
                result, err = q.get_nowait()
            except queue.Empty:
                self.after(80, poll)
                return
            self.spinner.stop()
            self.spinner.grid_remove()
            callback(result, err)

        threading.Thread(target=work, daemon=True).start()
        self.after(80, poll)

    def _toggle_mode(self):
        ctk.set_appearance_mode("dark" if self.mode.get() else "light")

    def set_status(self, text, kind="info"):
        icon, color = {"ok": ("✔", GREEN), "error": ("✖", RED),
                       "info": ("●", ACCENT), "warn": ("▲", AMBER)}[kind]
        self.status_icon.configure(text=icon, text_color=color)
        self.status_text.configure(text=text)


if __name__ == "__main__":
    App().mainloop()