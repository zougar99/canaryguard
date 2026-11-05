import io
import os
import secrets
import struct
import threading
import time
import zlib
from datetime import datetime

from PIL import Image

from .config import get_store
from .decoys import beacon_url, new_token_id

DEFAULT_FOLDER = os.path.join(os.path.expanduser("~"), "CanaryDecoys", "embedded")


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _mask(value):
    return int.from_bytes(value.encode("utf-8"), "big")


def _unmask(n):
    try:
        return n.to_bytes((n.bit_length() + 7) // 8, "big").decode("utf-8")
    except Exception:
        return "?"


class EmbedTokenManager:
    """Embedded honeytoken protocol.

    Generates files that look 100% normal (image / text / pdf) but carry a
    hidden identifier + beacon URL:
      * image  -> token hidden via LSB steganography in the pixels + EXIF tag
      * txt    -> token hidden as zero-width characters in a comment line
      * pdf    -> token in the PDF Info dict + a hidden content stream

    Detection is layered:
      * the embedded beacon URL (visible in metadata / content) trips the
        /t/<token> endpoint when the attacker follows it
      * the access scanner (atime) + folder watcher trip on file open/read
      * `extract()` can recover the hidden token to prove the file was ours
    """

    def __init__(self, config, alerts=None, logger=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        self.folder = config.get("secrets", "embed_folder", default=DEFAULT_FOLDER)
        self.beacon_host = config.get("decoys", "beacon_host", default="127.0.0.1")
        self._cooldown = {}

    # ---------- low-level embedding ----------

    def _lsb_encode(self, image, payload):
        """Embed payload bytes in the least-significant bits of pixel RGB."""
        img = image.convert("RGB")
        pix = img.load()
        bits = "".join(f"{b:08b}" for b in payload)
        bits += "1"  # terminator
        w, h = img.size
        if len(bits) > w * h * 3:
            raise ValueError("payload too large for image")
        i = 0
        for y in range(h):
            for x in range(w):
                if i >= len(bits):
                    return img
                r, g, b = pix[x, y]
                if i < len(bits):
                    r = (r & 0xFE) | int(bits[i]); i += 1
                if i < len(bits):
                    g = (g & 0xFE) | int(bits[i]); i += 1
                if i < len(bits):
                    b = (b & 0xFE) | int(bits[i]); i += 1
                pix[x, y] = (r, g, b)
        return img

    def _lsb_decode(self, image):
        """Recover the payload previously embedded by _lsb_encode."""
        img = image.convert("RGB")
        pix = img.load()
        w, h = img.size
        bits = []
        for y in range(h):
            for x in range(w):
                r, g, b = pix[x, y]
                bits.append(str(r & 1)); bits.append(str(g & 1)); bits.append(str(b & 1))
        # find the 1-terminator, take complete bytes before it
        stream = "".join(bits)
        term = stream.find("1" * 8)  # a full run of 8 terminator bits
        # better: stop at first '1' at a byte boundary after data
        end = len(stream) // 8
        raw = bytearray()
        for i in range(0, len(stream) - 8, 8):
            byte = stream[i:i + 8]
            if byte == "11111111":
                break
            if byte == "00000000":
                # could be a legit zero byte in payload; accept
                raw.append(0)
                continue
            # treat as long as the value parses
            raw.append(int(byte, 2))
        return bytes(raw)

    # ---------- generation ----------

    def _register(self, kind, label, path, hidden=True):
        token_id = new_token_id(kind)
        beacon = beacon_url(self.config, token_id)
        self.store.register_decoy(token_id, kind, label, path, beacon)
        return token_id, beacon

    def make_image(self, name="photo.png"):
        os.makedirs(self.folder, exist_ok=True)
        token_id, beacon = self._register("embed_image", f"photo ({name})", os.path.join(self.folder, name))
        payload = f"CGTOKEN:{token_id}|{beacon}".encode("utf-8")
        img = Image.new("RGB", (640, 480))
        pix = img.load()
        # pleasant, normal-looking gradient
        for y in range(480):
            for x in range(640):
                pix[x, y] = ((x * 3) % 256, (y * 3) % 256, ((x + y) * 2) % 256)
        img = self._lsb_encode(img, payload)
        # also drop the token in EXIF metadata (recoverable + beacon readable)
        exif = Image.Exif()
        exif[0x010E] = f"photo {name}"
        exif[0x9286] = beacon  # UserComment holds the beacon URL
        buf = io.BytesIO()
        img.save(buf, format="PNG", exif=exif)
        path = os.path.join(self.folder, name)
        with open(path, "wb") as fh:
            fh.write(buf.getvalue())
        self.logger(f"[embed] image {path} token={token_id}")
        return path, token_id, beacon

    def make_txt(self, name="notes.txt"):
        os.makedirs(self.folder, exist_ok=True)
        token_id, beacon = self._register("embed_txt", f"notes ({name})", os.path.join(self.folder, name))
        path = os.path.join(self.folder, name)
        zws = "\u200b\u200b\u200b\u200c\u200c\u200c\u200b\u200c"
        hidden = zws + token_id + zws
        body = (
            "# Shopping list\n"
            "milk, eggs, bread, coffee\n\n"
            "# Project ideas\n"
            "- rewrite auth module\n"
            "- deploy canary to staging\n\n"
            f"# todo (ignored)\n{hidden}\n"
            f"# backup mirror: {beacon}\n"
        )
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        self.logger(f"[embed] txt {path} token={token_id}")
        return path, token_id, beacon

    def make_pdf(self, name="report.pdf"):
        os.makedirs(self.folder, exist_ok=True)
        token_id, beacon = self._register("embed_pdf", f"report ({name})", os.path.join(self.folder, name))
        path = os.path.join(self.folder, name)
        text = "Quarterly report - confidential"
        # hidden stream carries the token, Info dict carries the beacon
        content = f"BT /F1 12 Tf 50 750 Td 20 TL ({text}) Tj ET"
        hidden_stream = f"CGTOKEN:{token_id}|{beacon}"
        objects = [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
            f"<< /Length {len(content)} >>\nstream\n{content}\nendstream",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            f"<< /Producer (CanaryGuard) /Subject ({hidden_stream}) >>",
        ]
        out = ["%PDF-1.4"]
        offsets = []
        for i, obj in enumerate(objects, 1):
            offsets.append(len(b"\n".join(x.encode() for x in out)) + len(out) - 1)
            out.append(f"{i} 0 obj\n{obj}\nendobj")
        xref_pos = len(b"\n".join(x.encode() for x in out)) + len(out) - 1
        xref = f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n"
        for off in offsets:
            xref += f"{off:010d} 00000 n \n"
        trailer = f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF"
        with open(path, "wb") as fh:
            fh.write(b"\n".join(x.encode() for x in out))
            fh.write(b"\n")
            fh.write(xref.encode())
            fh.write(trailer.encode())
        self.logger(f"[embed] pdf {path} token={token_id}")
        return path, token_id, beacon

    def make_custom(self, kind, name, secret, subfolder=""):
        """Embed a user-supplied secret (key/token/API key) inside a file.

        kind: 'image'|'txt'|'pdf'
        Returns (path, token_id, beacon).
        """
        os.makedirs(self.folder, exist_ok=True)
        folder = os.path.join(self.folder, subfolder) if subfolder else self.folder
        os.makedirs(folder, exist_ok=True)
        token_id = new_token_id(f"custom_{kind}")
        beacon = beacon_url(self.config, token_id)
        # payload embedded in the file carries secret + token + beacon
        payload = f"CGTOKEN:{token_id}|{beacon}|{secret}"
        path = os.path.join(folder, name)
        if kind == "image":
            img = Image.new("RGB", (640, 480))
            pix = img.load()
            for y in range(480):
                for x in range(640):
                    pix[x, y] = ((x * 3) % 256, (y * 3) % 256, ((x + y) * 2) % 256)
            img = self._lsb_encode(img, payload.encode("utf-8"))
            exif = Image.Exif()
            exif[0x010E] = f"photo {name}"
            exif[0x9286] = beacon
            buf = io.BytesIO()
            img.save(buf, format="PNG", exif=exif)
            with open(path, "wb") as fh:
                fh.write(buf.getvalue())
        elif kind == "pdf":
            text = "Quarterly report - confidential"
            content = f"BT /F1 12 Tf 50 750 Td 20 TL ({text}) Tj ET"
            hidden_stream = payload
            objects = [
                "<< /Type /Catalog /Pages 2 0 R >>",
                "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
                f"<< /Length {len(content)} >>\nstream\n{content}\nendstream",
                "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
                f"<< /Producer (CanaryGuard) /Subject ({hidden_stream}) >>",
            ]
            out = ["%PDF-1.4"]
            offsets = []
            for i, obj in enumerate(objects, 1):
                offsets.append(len(b"\n".join(x.encode() for x in out)) + len(out) - 1)
                out.append(f"{i} 0 obj\n{obj}\nendobj")
            xref_pos = len(b"\n".join(x.encode() for x in out)) + len(out) - 1
            xref = f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n"
            for off in offsets:
                xref += f"{off:010d} 00000 n \n"
            trailer = f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF"
            with open(path, "wb") as fh:
                fh.write(b"\n".join(x.encode() for x in out))
                fh.write(b"\n")
                fh.write(xref.encode())
                fh.write(trailer.encode())
        else:  # txt
            zws = "\u200b\u200b\u200b\u200c\u200c\u200c\u200b\u200c"
            hidden = zws + token_id + zws
            body = (
                "# Meeting notes\n"
                "discussed deployment timeline, resource allocation\n\n"
                "# Ideas (draft)\n"
                "- migrate db to new host\n"
                "- enable 2fa everywhere\n\n"
                f"# private\n{hidden}\n"
                f"# mirror: {beacon}\n"
            )
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
        self.store.register_decoy(token_id, f"custom_{kind}", f"custom {kind} ({name})", path, beacon)
        self.logger(f"[embed] custom {kind} {path} token={token_id}")
        return path, token_id, beacon

    def generate(self, kinds=None, force=False):
        kinds = kinds or ["image", "txt", "pdf"]
        created = []
        for kind in kinds:
            fn = getattr(self, f"make_{kind}")
            # default names so restart doesn't recreate with new tokens
            name = {"image": "photo.png", "txt": "notes.txt", "pdf": "report.pdf"}[kind]
            path = os.path.join(self.folder, name)
            if not force and os.path.exists(path):
                self.logger(f"[embed] {path} exists, keeping existing token")
                row = self.store.decoys()
                existing = [d for d in row if d["kind"] == f"embed_{kind}" and os.path.normpath(d["path"]) == os.path.normpath(path)]
                if existing:
                    created.append({"path": path, "token_id": existing[-1]["token_id"], "beacon": existing[-1]["beacon"]})
                    continue
            path, token_id, beacon = fn(name)
            created.append({"path": path, "token_id": token_id, "beacon": beacon})
        self.logger(f"[embed] generated {len(created)} embedded tokens in {self.folder}")
        return created

    # ---------- verification / extraction ----------

    def extract(self, path):
        """Recover the hidden token from a file. Returns token or None."""
        ext = os.path.splitext(path)[1].lower()
        try:
            if ext == ".png":
                with Image.open(path) as im:
                    raw = self._lsb_decode(im)
                for part in raw.split(b"|"):
                    if part.startswith(b"CGTOKEN:"):
                        return part.decode("utf-8", "replace").split(":", 1)[1]
            elif ext == ".txt":
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
                for line in text.splitlines():
                    if line.startswith("\u200b"):
                        tok = line.replace("\u200b", "").replace("\u200c", "").strip()
                        if tok:
                            return tok
            elif ext == ".pdf":
                with open(path, "rb") as fh:
                    data = fh.read()
                m = data.find(b"CGTOKEN:")
                if m != -1:
                    end = data.find(b"|", m)
                    if end != -1:
                        return data[m + 8:end].decode("utf-8", "replace")
        except Exception as exc:
            self.logger(f"[embed] extract failed {path}: {exc}")
        return None

    def verify_all(self):
        """Check every registered embedded token is still intact on disk."""
        results = []
        for d in self.store.decoys():
            if not d["kind"].startswith("embed"):
                continue
            p = d["path"]
            if not os.path.exists(p):
                results.append((d["kind"], d["token_id"], "missing", p))
                continue
            tok = self.extract(p)
            if tok == d["token_id"]:
                results.append((d["kind"], d["token_id"], "intact", p))
            else:
                results.append((d["kind"], d["token_id"], "tampered", p))
        return results


class EmbedAccessScanner:
    """atime scanner for embedded token files (read/open detection)."""

    def __init__(self, config, manager: EmbedTokenManager, logger=None, interval=5.0):
        self.config = config
        self.logger = logger or print
        self.manager = manager
        self.alerts = manager.alerts
        self.folder = config.get("secrets", "embed_folder", default=DEFAULT_FOLDER)
        self.interval = interval
        self._baseline = {}
        self._cooldown = {}
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._snapshot(baseline=True)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.logger(f"[embed] access scanning {self.folder}")

    def stop(self):
        self._stop.set()

    def _snapshot(self, baseline=False):
        snap = {}
        if os.path.isdir(self.folder):
            for root, _, files in os.walk(self.folder):
                for f in files:
                    p = os.path.join(root, f)
                    try:
                        st = os.stat(p)
                        snap[p] = (st.st_atime, st.st_mtime, st.st_size)
                    except OSError:
                        continue
        if baseline:
            self._baseline = snap
        return snap

    def _run(self):
        time.sleep(self.interval)
        while not self._stop.is_set():
            try:
                snap = self._snapshot()
                for path, (atime, mtime, size) in snap.items():
                    base = self._baseline.get(path)
                    label = os.path.basename(path)
                    if base is None:
                        self._trip(f"embed:{label}", "created", f"new embedded file appeared", path)
                        continue
                    b_atime, b_mtime, b_size = base
                    if mtime > b_mtime or size != b_size:
                        self._trip(f"embed:{label}", "modified", f"embedded file modified", path)
                    elif atime > b_atime:
                        self._trip(f"embed:{label}", "accessed", f"embedded file OPENED/READ", path)
                for path in set(self._baseline) - set(snap):
                    self._trip(f"embed:{os.path.basename(path)}", "deleted", f"embedded file REMOVED", path)
                self._baseline = snap
            except Exception as exc:
                self.logger(f"[embed] scanner error: {exc}")
            self._stop.wait(self.interval)

    def _trip(self, key, kind, label, path):
        now = time.monotonic()
        if now - self._cooldown.get(key, 0) < int(self.config.get("decoys", "cooldown_seconds", default=60)):
            return
        self._cooldown[key] = now
        if self.alerts:
            event = {
                "src_host": "",
                "src_port": -1,
                "dst_port": -1,
                "local_time": _now(),
                "ts": _now(),
            }
            self.alerts.send(event, "decoy:embedded", "critical",
                             f"EMBEDDED TOKEN ({kind})\npath: {path}\nlabel: {label}")
        self.logger(f"[embed] TRIP {kind} {label} path={path}")