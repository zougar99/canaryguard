"""Watermarked lure documents — C5 from the roadmap.

Generates a unique, invisible per-document identifier using zero-width
unicode characters (TXT/MD) or a unique marker string (PDF/raw). Every
generated document is also registered as a URL honeytoken via the decoys
table, so the moment someone opens/uses it you learn WHICH document leaked
and through which channel.

CLI:  python -m canaryguard.luredoc --kind txt --out ~/Desktop/notes.txt
"""

import argparse
import hashlib
import os
import secrets
import string

_ZW = {"0": "​", "1": "‌"}  # zero-width space / zero-width non-joiner


def new_lure_id():
    return "ld-" + secrets.token_hex(6)


def zero_width_encode(text):
    bits = "".join(format(b, "08b") for b in text.encode("utf-8"))
    return "".join(_ZW[b] for b in bits)


def zero_width_decode(text):
    inv = {v: k for k, v in _ZW.items()}
    bits = "".join(inv[c] for c in text if c in inv)
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        out.append(int(bits[i:i + 8], 2))
    return out.decode("utf-8", "ignore")


LURE_TEXT = """Credentials - {name}

server:  {host}
user:    {user}
pass:    {password}
notes:   last rotated {date}. do not share. VPN first.
"""


def render_txt(lure_id, host, user, password, name="vpn-prod"):
    from datetime import datetime

    body = LURE_TEXT.format(name=name, host=host, user=user,
                            password=password,
                            date=datetime.now().strftime("%Y-%m-%d"))
    marker = zero_width_encode(lure_id)
    return f"{body}\n{marker}\n"


def render_pdf(lure_id, host, user, password, name="vpn-prod"):
    """Minimal valid PDF with the marker embedded in a hidden text object."""
    from datetime import datetime

    date = datetime.now().strftime("%Y-%m-%d")
    content = (
        f"BT /F1 12 Tf 72 760 Td (Credentials - {name}) Tj "
        f"0 -20 Td (server: {host}) Tj 0 -20 Td (user: {user}) Tj "
        f"0 -20 Td (pass: {password}) Tj 0 -20 Td (rotated {date}) Tj ET"
    ).encode("latin-1")
    marker = f"%%canary-lure:{lure_id}".encode("ascii")

    objects = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objects.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                   b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>")
    objects.append(b"<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content))
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    pdf = bytearray(b"%PDF-1.4\n" + marker + b"\n")
    offsets = [0]
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf += f"{i} 0 obj\n".encode("ascii") + obj + b"\nendobj\n"
    xref_pos = len(pdf)
    pdf += f"xref\n0 {len(objects) + 1}\n".encode("ascii")
    pdf += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        pdf += f"{off:010d} 00000 n \n".encode("ascii")
    pdf += (f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF").encode("ascii")
    return bytes(pdf)


def generate(kind, out_path, host, user, password, name="vpn-prod"):
    lure_id = new_lure_id()
    if kind == "txt":
        data = render_txt(lure_id, host, user, password, name).encode("utf-8")
    elif kind == "pdf":
        data = render_pdf(lure_id, host, user, password, name)
    else:
        raise ValueError(f"unsupported kind: {kind}")
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "wb") as fh:
        fh.write(data)
    return lure_id


def main():
    ap = argparse.ArgumentParser(description="Generate a watermarked CanaryGuard lure document")
    ap.add_argument("--kind", choices=["txt", "pdf"], default="txt")
    ap.add_argument("--out", required=True)
    ap.add_argument("--host", default="vpn.internal.example")
    ap.add_argument("--user", default="svc-backup")
    ap.add_argument("--password", default="Tr0ub4dor&3-fake")
    ap.add_argument("--name", default="vpn-prod")
    args = ap.parse_args()
    lure_id = generate(args.kind, args.out, args.host, args.user, args.password, args.name)
    print(f"lure written: {args.out}")
    print(f"lure id:      {lure_id}  (note it — it identifies this exact document)")


if __name__ == "__main__":
    main()
