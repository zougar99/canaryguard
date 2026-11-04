# -*- coding: utf-8 -*-
"""
CanaryGuard Desktop App
Control panel for the CanaryGuard stack running on this PC.

Talks to the local dashboard at http://127.0.0.1:8080 (same auth as web).
Tabs: Overview | Events | Actions | Manage
"""
import base64
import io
import json
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox

import requests

try:
    from PIL import Image, ImageTk
except Exception:  # Pillow optional for screenshot preview
    Image = None
    ImageTk = None

BASE_URL = "http://127.0.0.1:8080"
UI_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "CanaryGuard")
UI_FILE = os.path.join(UI_DIR, "ui.json")

MONITOR_LABELS = {
    "lan": "📶 LAN devices",
    "downloads": "⬇️ Downloads sentinel",
    "cam": "📸 Cam/mic watch",
    "staging": "🗜️ Staging detector",
    "browser": "🕵️ Browser creds watch",
    "persist": "⛳ Persistence watchdog",
    "theft": "🚨 Theft alarm",
    "evidence": "📦 Evidence backup",
    "procs": "🚀 Process monitor",
    "usb": "🔌 USB monitor",
    "net": "🌐 Network monitor",
    "clip": "📋 Clipboard sensor",
    "panic": "🔐 Panic idle",
}


def load_creds():
    try:
        with open(UI_FILE, "r", encoding="utf-8") as fh:
            d = json.load(fh)
        return base64.b64decode(d["u"]).decode(), base64.b64decode(d["p"]).decode()
    except Exception:
        return "", ""


def save_creds(user, pwd):
    try:
        os.makedirs(UI_DIR, exist_ok=True)
        with open(UI_FILE, "w", encoding="utf-8") as fh:
            json.dump({"u": base64.b64encode(user.encode()).decode(),
                       "p": base64.b64encode(pwd.encode()).decode()}, fh)
    except Exception:
        pass


class GuardApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CanaryGuard Desktop")
        self.root.geometry("980x640")
        self.root.minsize(860, 560)
        self.session = requests.Session()
        self.online = tk.BooleanVar(value=False)
        self._refresh_job = None
        self.splash = None
        self._build_splash()
        self._try_connect()

    # ---------- plumbing ----------

    def ui(self, fn, *args):
        """Run fn on the Tk thread."""
        self.root.after(0, lambda: self._safe(fn, *args))

    def _safe(self, fn, *args):
        try:
            fn(*args)
        except Exception:
            pass

    def _worker(self, fn, done=None):
        def run():
            try:
                res = fn()
            except Exception as exc:
                res = exc
            if done:
                self.ui(done, res)
        threading.Thread(target=run, daemon=True).start()

    def _get(self, path, timeout=8):
        r = self.session.get(BASE_URL + path, timeout=timeout)
        r.raise_for_status()
        return r

    def _post(self, path, payload=None, timeout=10):
        r = self.session.post(BASE_URL + path, json=payload or {}, timeout=timeout)
        r.raise_for_status()
        return r

    # ---------- login ----------

    def _build_splash(self):
        """Small 'connecting' window shown while the dashboard starts up."""
        win = tk.Toplevel(self.root)
        self.splash = win
        win.title("CanaryGuard")
        win.geometry("420x170")
        win.resizable(False, False)
        frm = tk.Frame(win, padx=20, pady=18)
        frm.pack(fill="both", expand=True)
        tk.Label(frm, text="🛡️ CanaryGuard Desktop",
                 font=("Segoe UI", 14, "bold")).pack()
        self._splash_lbl = tk.Label(frm, text="connecting to dashboard...", fg="#666")
        self._splash_lbl.pack(pady=(10, 8))
        tk.Button(frm, text="Retry now", width=16,
                  command=self._try_connect).pack()

    def _try_connect(self):
        """Go straight to the control panel when the dashboard has no password."""
        if self.splash is not None:
            try:
                self._splash_lbl.config(text="connecting to dashboard...", fg="#666")
            except Exception:
                pass

        def work():
            try:
                r = self.session.get(BASE_URL + "/api/stats", timeout=4)
                return r.status_code
            except Exception as exc:
                return exc

        def done(res):
            if isinstance(res, Exception):
                if self.splash is not None:
                    self._splash_lbl.config(
                        text="dashboard offline - retrying every 3s\n"
                             "start it: schtasks /run /tn \"CanaryGuard\"",
                        fg="#c0392b")
                self.root.after(3000, self._try_connect)
                return
            if res == 200:
                self._close_splash()
                self._build_main()
                return
            if res in (401, 403):
                # A password is still configured (401) or remote-only guard (403)
                self._close_splash()
                self._build_login()
                return
            if self.splash is not None:
                self._splash_lbl.config(text=f"unexpected HTTP {res} - retrying...",
                                        fg="#c0392b")
            self.root.after(3000, self._try_connect)

        self._worker(work, done)

    def _close_splash(self):
        if self.splash is not None:
            try:
                self.splash.destroy()
            except Exception:
                pass
            self.splash = None

    def _build_login(self):
        win = tk.Toplevel(self.root)
        self.login_win = win
        win.title("Sign in")
        win.protocol("WM_DELETE_WINDOW", self._quit_all)
        frm = tk.Frame(win, padx=18, pady=16)
        frm.pack()
        tk.Label(frm, text="🛡️ CanaryGuard Desktop", font=("Segoe UI", 14, "bold")).grid(row=0, column=0, columnspan=2, pady=(0, 10))
        tk.Label(frm, text="username:").grid(row=1, column=0, sticky="e", pady=3)
        u = tk.Entry(frm, width=26)
        u.grid(row=1, column=1, pady=3)
        tk.Label(frm, text="password:").grid(row=2, column=0, sticky="e", pady=3)
        p = tk.Entry(frm, width=26, show="*")
        p.grid(row=2, column=1, pady=3)
        saved_u, saved_p = load_creds()
        u.insert(0, saved_u or "admin")
        p.insert(0, saved_p)
        self._login_status = tk.Label(frm, text="", fg="#666")
        self._login_status.grid(row=4, column=0, columnspan=2, pady=(8, 0))
        b = tk.Button(frm, text="Sign in", width=20, command=lambda: self._do_login(u.get(), p.get()))
        b.grid(row=3, column=0, columnspan=2, pady=(10, 2))

        def enter(e):
            self._do_login(u.get(), p.get())
        win.bind("<Return>", enter)
        p.focus_set()

    def _do_login(self, user, pwd):
        self._login_status.config(text="connecting...", fg="#666")

        def work():
            try:
                resp = self.session.post(BASE_URL + "/login",
                                         data={"username": user, "password": pwd},
                                         timeout=6, allow_redirects=False)
                return resp
            except Exception as exc:
                return exc

        def done(resp):
            if isinstance(resp, Exception):
                self._login_status.config(text=f"offline: {resp}", fg="#c0392b")
                return
            if resp.status_code in (302, 303) or (resp.ok and "cg_authed" in str(resp.headers.get("Set-Cookie", ""))):
                save_creds(user, pwd)
                self.login_win.destroy()
                self._build_main()
            else:
                self._login_status.config(text="wrong username or password", fg="#c0392b")
        self._worker(work, done)

    def _quit_all(self):
        try:
            self.root.destroy()
        except Exception:
            pass
        sys.exit(0)

    # ---------- main window ----------

    def _build_main(self):
        self.root.deiconify()
        bar = tk.Frame(self.root, bg="#12343b", height=46)
        bar.pack(fill="x")
        tk.Label(bar, text="🛡️ CanaryGuard", bg="#12343b", fg="white",
                 font=("Segoe UI", 12, "bold")).pack(side="left", padx=12, pady=8)
        self.status_lbl = tk.Label(bar, text=">", bg="#12343b", fg="#bbb")
        self.status_lbl.pack(side="right", padx=12)

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True)
        self._tab_overview(nb)
        self._tab_events(nb)
        self._tab_actions(nb)
        self._tab_manage(nb)

        self._poll()

    # Tab 1: overview
    def _tab_overview(self, nb):
        f = tk.Frame(nb)
        nb.add(f, text="  Overview  ")
        self.ov_cards = tk.Frame(f)
        self.ov_cards.pack(fill="x", padx=14, pady=12)
        self.ov_monitors = ttk.Treeview(f, columns=("name", "state"), show="headings", height=9)
        self.ov_monitors.heading("name", text="Monitor")
        self.ov_monitors.heading("state", text="State")
        self.ov_monitors.column("name", width=260)
        self.ov_monitors.column("state", width=130, anchor="center")
        self.ov_monitors.pack(fill="both", expand=True, padx=14, pady=(0, 10))

    # Tab 2: events
    def _tab_events(self, nb):
        f = tk.Frame(nb)
        nb.add(f, text="  Events  ")
        cols = ("time", "sev", "cat", "src")
        self.ev_tree = ttk.Treeview(f, columns=cols, show="headings")
        for cid, txt, w in (("time", "Time", 160), ("sev", "Severity", 90),
                            ("cat", "Category", 200), ("src", "Source", 240)):
            self.ev_tree.heading(cid, text=txt)
            self.ev_tree.column(cid, width=w)
        ysb = ttk.Scrollbar(f, orient="vertical", command=self.ev_tree.yview)
        self.ev_tree.configure(yscrollcommand=ysb.set)
        self.ev_tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="left", fill="y")
        self.ev_tree.tag_configure("critical", foreground="#c0392b")
        self.ev_tree.tag_configure("high", foreground="#d35400")
        self.ev_tree.tag_configure("medium", foreground="#b7950b")
        self.ev_tree.tag_configure("low", foreground="#7f8c8d")

    # Tab 3: actions
    def _tab_actions(self, nb):
        f = tk.Frame(nb)
        nb.add(f, text="  Actions  ")
        wrap = tk.Frame(f)
        wrap.pack(fill="both", expand=True, padx=14, pady=12)

        grp = tk.LabelFrame(wrap, text=" PC control ", padx=10, pady=8)
        grp.pack(fill="x", pady=(0, 10))
        tk.Button(grp, text="🔒 Lock PC", width=16, command=self._do_lock).pack(side="left", padx=6)
        tk.Button(grp, text="🚨 Panic (lock + alert)", width=22, command=self._do_panic).pack(side="left", padx=6)
        tk.Button(grp, text="📸 Screenshot", width=16, command=self._do_shot).pack(side="left", padx=6)

        grp2 = tk.LabelFrame(wrap, text=" Alerts ", padx=10, pady=8)
        grp2.pack(fill="x", pady=(0, 10))
        tk.Button(grp2, text="🧪 Test alert", width=16, command=self._do_test).pack(side="left", padx=6)
        tk.Button(grp2, text="📰 Digest now", width=16, command=self._do_digest).pack(side="left", padx=6)
        self.mute_entry = tk.Entry(grp2, width=14)
        self.mute_entry.insert(0, "proc:start")
        self.mute_entry.pack(side="left", padx=(18, 4))
        tk.Button(grp2, text="🔇 Mute cat", command=self._do_mute).pack(side="left", padx=3)
        tk.Button(grp2, text="🔊 Unmute", command=self._do_unmute).pack(side="left", padx=3)
        tk.Button(grp2, text="🔊 Unmute ALL", command=self._do_unmute_all).pack(side="left", padx=3)

        grp3 = tk.LabelFrame(wrap, text=" Firewall IP block ", padx=10, pady=8)
        grp3.pack(fill="x", pady=(0, 10))
        self.ip_entry = tk.Entry(grp3, width=18)
        self.ip_entry.insert(0, "0.0.0.0")
        self.ip_entry.pack(side="left", padx=6)
        tk.Button(grp3, text="🚫 Block IP", command=self._do_block_ip).pack(side="left", padx=3)
        tk.Button(grp3, text="✅ Unblock IP", command=self._do_unblock_ip).pack(side="left", padx=3)
        self.ip_list = tk.Listbox(grp3, height=4)
        self.ip_list.pack(fill="x", pady=(8, 0))
        self.ip_list.bind("<Double-1>", lambda e: self.ip_entry.delete(0, "end") or self.ip_entry.insert(0, self.ip_list.get(self.ip_list.curindex())))

        self.action_status = tk.Label(wrap, text="", fg="#145a32")
        self.action_status.pack(anchor="w")

    # Tab 4: manage monitors
    def _tab_manage(self, nb):
        f = tk.Frame(nb)
        nb.add(f, text="  Manage  ")
        self.mng_tree = ttk.Treeview(f, columns=("name", "state", "on"), show="headings")
        for cid, txt, w in (("name", "Monitor", 280), ("state", "State", 120), ("on", "Toggle", 110)):
            self.mng_tree.heading(cid, text=txt)
            self.mng_tree.column(cid, width=w, anchor=("w" if cid == "name" else "center"))
        self.mng_tree.pack(fill="both", expand=True, padx=14, pady=12)
        btnf = tk.Frame(f)
        btnf.pack(pady=(0, 12))
        tk.Button(btnf, text="▶ Enable selected", width=18, command=lambda: self._toggle_monitor(True)).pack(side="left", padx=6)
        tk.Button(btnf, text="⏹ Disable selected", width=18, command=lambda: self._toggle_monitor(False)).pack(side="left", padx=6)
        tk.Button(btnf, text="🔄 Refresh", width=12, command=self._refresh_monitors).pack(side="left", padx=6)

    # ---------- actions ----------

    def _set_action(self, txt, ok=True):
        self.ui(lambda: self.action_status.config(text=txt, fg="#145a32" if ok else "#c0392b"))

    def _act(self, path, name, silent=False):
        def work():
            try:
                self._post(path)
                return None
            except Exception as exc:
                return exc
        def done(err):
            if err:
                self._set_action(f"{name}: {err}", ok=False)
            elif not silent:
                self._set_action(f"{name} ✓")
        self._worker(work, done)

    def _do_lock(self):
        self._act("/api/lock", "🔒 Locked")

    def _do_panic(self):
        self._act("/api/panic", "🚨 Panic sent")

    def _do_test(self):
        self._act("/api/test_alert", "🧪 Test alert sent")

    def _do_digest(self):
        self._act("/api/digest", "📰 Digest sent")

    def _do_mute(self):
        cat = self.mute_entry.get().strip()
        def work():
            try:
                self._post("/api/mute", {"category": cat})
                return None
            except Exception as exc:
                return exc
        def done(err):
            self._set_action(f"🔇 muted: {cat}" if not err else f"{err}", ok=not err)
            self._refresh_monitors()
        self._worker(work, done)

    def _do_unmute(self):
        cat = self.mute_entry.get().strip()
        def work():
            try:
                self._post("/api/unmute", {"category": cat})
                return None
            except Exception as exc:
                return exc
        def done(err):
            self._set_action(f"🔊 unmuted: {cat}" if not err else f"{err}", ok=not err)
            self._refresh_monitors()
        self._worker(work, done)

    def _do_unmute_all(self):
        def work():
            try:
                self._post("/api/unmute", {"all": True})
                return None
            except Exception as exc:
                return exc
        def done(err):
            self._set_action("🔊 all muted cleared" if not err else f"{err}", ok=not err)
            self._refresh_monitors()
        self._worker(work, done)

    def _do_block_ip(self):
        ip = self.ip_entry.get().strip()
        def work():
            try:
                self._post("/api/ipblock/block", {"ip": ip})
                return None
            except Exception as exc:
                return exc
        def done(err):
            self._set_action(f"🚫 blocked {ip}" if not err else f"{err}", ok=not err)
            self._refresh_ips()
        self._worker(work, done)

    def _do_unblock_ip(self):
        ip = self.ip_entry.get().strip()
        def work():
            try:
                self._post("/api/ipblock/remove", {"ip": ip})
                return None
            except Exception as exc:
                return exc
        def done(err):
            self._set_action(f"✅ unblocked {ip}" if not err else f"{err}", ok=not err)
            self._refresh_ips()
        self._worker(work, done)

    def _do_shot(self):
        def work():
            try:
                r = self._get("/api/screenshot", timeout=15)
                return r.content
            except Exception as exc:
                return exc
        def done(data):
            if isinstance(data, Exception):
                self._set_action(f"screenshot: {data}", ok=False)
                return
            top = tk.Toplevel(self.root)
            top.title("📸 Screenshot @ " + __import__("datetime").datetime.now().strftime("%H:%M:%S"))
            if Image and ImageTk:
                img = Image.open(io.BytesIO(data))
                w, h = img.size
                scale = min(1.0, 900 / w, 560 / h)
                img = img.resize((int(w * scale), int(h * scale)))
                ph = ImageTk.PhotoImage(img)
                top.geometry(f"{img.width}x{img.height}")
                lbl = tk.Label(top, image=ph)
                lbl.image = ph
                lbl.pack()
                def saveit():
                    from datetime import datetime as _dt
                    sp = os.path.join(os.path.expanduser("~"), "Desktop",
                                      f"shot_{_dt.now().strftime('%Y%m%d_%H%M%S')}.jpg")
                    with open(sp, "wb") as fh:
                        fh.write(data)
                    messagebox.showinfo("Saved", sp, parent=top)
                tk.Button(top, text="💾 Save to Desktop", command=saveit).pack(pady=6)
            else:
                sp = os.path.join(os.path.expanduser("~"), "Desktop", "cg_screenshot.jpg")
                with open(sp, "wb") as fh:
                    fh.write(data)
                tk.Label(top, text=f"no Pillow - saved to {sp}").pack(padx=20, pady=20)
        self._worker(work, done)

    # ---------- refresh loops ----------

    def _poll(self):
        self._refresh_stats()
        self._refresh_events()
        self._refresh_monitors()
        self._refresh_ips()
        self._refresh_job = self.root.after(5000, self._poll)

    def _refresh_stats(self):
        def work():
            try:
                r = self._get("/api/stats")
                return r.json()
            except Exception:
                return None
        def done(data):
            online = data is not None
            self.online.set(online)
            self.ui(lambda: self._paint_status(online))
            if not data:
                return
            cats = data.get("categories", {})
            total = data.get("total", 0)
            sev = data.get("severities", {})
            cards = [
                ("Events", str(total)),
                ("Creds", str(data.get("creds", 0))),
                ("High+Critical", str(int(sev.get("high", 0)) + int(sev.get("critical", 0)))),
                ("Categories", str(len(cats))),
            ]
            self.ui(lambda: self._paint_cards(cards))
        self._worker(work, done)

    def _paint_status(self, online):
        if online:
            self.status_lbl.config(text="● ONLINE", fg="#7dcea0")
        else:
            self.status_lbl.config(text="● OFFLINE (CanaryGuard down)", fg="#e74c3c")

    def _paint_cards(self, cards):
        for w in self.ov_cards.winfo_children():
            w.destroy()
        for title, val in cards:
            box = tk.Frame(self.ov_cards, bg="#f4f6f7", bd=1, relief="solid")
            box.pack(side="left", padx=8, ipadx=14, ipady=8)
            tk.Label(box, text=title, bg="#f4f6f7", fg="#5d6d7e", font=("Segoe UI", 9)).pack()
            tk.Label(box, text=val, bg="#f4f6f7", fg="#212f3d", font=("Segoe UI", 16, "bold")).pack()

    def _refresh_events(self):
        def work():
            try:
                return self._get("/api/events").json()
            except Exception:
                return None
        def done(rows):
            if not rows:
                return
            def paint():
                self.ev_tree.delete(*self.ev_tree.get_children())
                for row in rows[:80]:
                    sev = (row.get("severity") or "low").lower()
                    self.ev_tree.insert("", "end", tags=(sev,), values=(
                        row.get("ts") or "",
                        sev,
                        row.get("category") or "",
                        row.get("src_ip") or "local",
                    ))
            self.ui(paint)
        self._worker(work, done)

    def _refresh_monitors(self):
        def work():
            try:
                return self._get("/api/monitors").json()
            except Exception:
                return None
        def done(data):
            if not data:
                return
            mons = data.get("monitors", {})
            def paint():
                self.ov_monitors.delete(*self.ov_monitors.get_children())
                self.mng_tree.delete(*self.mng_tree.get_children())
                for name in sorted(mons):
                    st = mons[name].get("status", "?")
                    label = MONITOR_LABELS.get(name, name)
                    self.ov_monitors.insert("", "end", values=(label, st))
                    self.mng_tree.insert("", "end", iid=name, values=(label, st, "enable / disable"))
            self.ui(paint)
        self._worker(work, done)

    def _refresh_ips(self):
        def work():
            try:
                return self._get("/api/ipblock/blocked").json()
            except Exception:
                return None
        def done(data):
            ips = (data or {}).get("blocked", [])
            def paint():
                self.ip_list.delete(0, "end")
                for ip in ips:
                    self.ip_list.insert("end", ip)
            self.ui(paint)
        self._worker(work, done)

    def _toggle_monitor(self, enabled):
        sel = self.mng_tree.selection()
        if not sel:
            return
        name = sel[0]

        def work():
            try:
                r = self._post(f"/api/monitors/{name}", {"enabled": enabled})
                return r.json()
            except Exception as exc:
                return exc
        def done(res):
            if isinstance(res, Exception):
                self._set_action(f"toggle: {res}", ok=False)
            else:
                self._set_action(f"{name} → {'enabled' if enabled else 'disabled'}", ok=bool(res.get("ok")))
            self._refresh_monitors()
        self._worker(work, done)


def main():
    root = tk.Tk()
    root.withdraw()
    GuardApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
