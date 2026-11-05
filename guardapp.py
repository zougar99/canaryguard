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
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
ICON_PNG = os.path.join(ROOT_DIR, "assets", "icon.png")
ICON_ICO = os.path.join(ROOT_DIR, "assets", "icon.ico")
LOGO_PNG = os.path.join(ROOT_DIR, "assets", "logo.png")
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


def _count_map(value):
    """Normalize {"k": n} or [["k", n], ...] into a plain dict."""
    if isinstance(value, dict):
        return value
    try:
        return {str(k): v for k, v in value}
    except Exception:
        return {}


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
        self._icon_img = None
        self._set_icon(self.root)
        self._build_splash()
        self._try_connect()

    # ---------- plumbing ----------

    def _set_icon(self, win):
        """Apply the CanaryGuard icon to the window and all toplevels."""
        if os.path.exists(ICON_PNG):
            try:
                if Image is not None and ImageTk is not None:
                    self._icon_img = ImageTk.PhotoImage(Image.open(ICON_PNG))
                else:
                    self._icon_img = tk.PhotoImage(file=ICON_PNG)
                win.iconphoto(True, self._icon_img)
                return
            except Exception:
                pass
        if os.path.exists(ICON_ICO):
            try:
                win.iconbitmap(default=ICON_ICO)
            except Exception:
                pass

    def _logo_image(self, size):
        """Small transparent logo for headers, or None when Pillow is absent."""
        if Image is None or ImageTk is None or not os.path.exists(LOGO_PNG):
            return None
        try:
            img = Image.open(LOGO_PNG).convert("RGBA")
            img = img.resize((size, size), Image.LANCZOS)
            return ImageTk.PhotoImage(img)
        except Exception:
            return None

    def ui(self, fn, *args):
        """Run fn on the Tk thread."""
        self.root.after(0, lambda: self._safe(fn, *args))

    def _safe(self, fn, *args):
        try:
            fn(*args)
        except Exception:
            # Never let a UI callback die silently: keep a traceback on disk.
            try:
                import datetime
                import traceback

                os.makedirs(UI_DIR, exist_ok=True)
                with open(os.path.join(UI_DIR, "guardapp.err.log"), "a", encoding="utf-8") as fh:
                    fh.write(f"--- {datetime.datetime.now():%Y-%m-%d %H:%M:%S} {getattr(fn, '__name__', fn)}\n")
                    traceback.print_exc(file=fh)
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
        logo = self._logo_image(52)
        if logo is not None:
            lbl = tk.Label(frm, image=logo)
            lbl.image = logo
            lbl.pack()
        tk.Label(frm, text="CanaryGuard Desktop",
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
        logo = self._logo_image(44)
        if logo is not None:
            lbl = tk.Label(frm, image=logo)
            lbl.image = logo
            lbl.grid(row=0, column=0, columnspan=2, pady=(0, 6))
        tk.Label(frm, text="CanaryGuard Desktop", font=("Segoe UI", 14, "bold")).grid(row=1, column=0, columnspan=2, pady=(0, 10))
        tk.Label(frm, text="username:").grid(row=2, column=0, sticky="e", pady=3)
        u = tk.Entry(frm, width=26)
        u.grid(row=2, column=1, pady=3)
        tk.Label(frm, text="password:").grid(row=3, column=0, sticky="e", pady=3)
        p = tk.Entry(frm, width=26, show="*")
        p.grid(row=3, column=1, pady=3)
        saved_u, saved_p = load_creds()
        u.insert(0, saved_u or "admin")
        p.insert(0, saved_p)
        self._login_status = tk.Label(frm, text="", fg="#666")
        self._login_status.grid(row=5, column=0, columnspan=2, pady=(8, 0))
        b = tk.Button(frm, text="Sign in", width=20, command=lambda: self._do_login(u.get(), p.get()))
        b.grid(row=4, column=0, columnspan=2, pady=(10, 2))

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

    # ---------- main window (redesigned control panel) ----------

    def _build_main(self):
        self.root.deiconify()
        self.root.title("CanaryGuard — Control Panel")
        self.root.minsize(980, 640)
        self.root.configure(bg="#0b0f16")
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("CG.Treeview", background="#121a24", fieldbackground="#121a24",
                        foreground="#e6edf3", rowheight=24, borderwidth=0)
        style.configure("CG.Treeview.Heading", background="#16202c", foreground="#8896a8",
                        font=("Segoe UI", 9, "bold"), relief="flat")
        style.map("CG.Treeview", background=[("selected", "#1f3347")])
        style.configure("CG.TNotebook", background="#0b0f16", borderwidth=0)
        style.configure("CG.TNotebook.Tab", background="#121a24", foreground="#8896a8",
                        padding=(14, 8), font=("Segoe UI", 9))
        style.map("CG.TNotebook.Tab",
                  background=[("selected", "#16202c")],
                  foreground=[("selected", "#e6edf3")])

        bar = tk.Frame(self.root, bg="#0e141d", height=52)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        logo = self._logo_image(28)
        if logo is not None:
            lbl = tk.Label(bar, image=logo, bg="#0e141d")
            lbl.image = logo
            lbl.pack(side="left", padx=(14, 8), pady=10)
        tk.Label(bar, text="CanaryGuard", bg="#0e141d", fg="#e6edf3",
                 font=("Segoe UI", 12, "bold")).pack(side="left")
        tk.Label(bar, text="  ·  Control Panel", bg="#0e141d", fg="#8896a8",
                 font=("Segoe UI", 10)).pack(side="left")
        tk.Button(bar, text="Open dashboard", bg="#16202c", fg="#e6edf3",
                  activebackground="#1f3347", relief="flat", bd=0, padx=10, pady=4,
                  command=self._open_dashboard).pack(side="right", padx=(4, 14), pady=10)
        self.status_lbl = tk.Label(bar, text="connecting…", bg="#0e141d", fg="#8896a8",
                                   font=("Segoe UI", 9))
        self.status_lbl.pack(side="right", padx=8)

        ctl = tk.Frame(self.root, bg="#121a24", pady=10)
        ctl.pack(fill="x")
        self.mode_badge = tk.Label(ctl, text="  MODE  ", bg="#16202c", fg="#8896a8",
                                   font=("Segoe UI", 10, "bold"), padx=10, pady=6)
        self.mode_badge.pack(side="left", padx=(14, 10))
        for text, cmd, bg, fg in (
            ("Sleep", self._ctl_pause, "#1f3347", "#e6edf3"),
            ("Resume", self._ctl_resume, "#143d2b", "#8ce99a"),
            ("Restart", self._ctl_restart, "#16202c", "#e6edf3"),
            ("Stop", self._ctl_stop, "#3d1a1a", "#ff9c96"),
        ):
            tk.Button(ctl, text=text, command=cmd, bg=bg, fg=fg,
                      activebackground="#22303f", activeforeground=fg,
                      relief="flat", bd=0, padx=12, pady=6,
                      font=("Segoe UI", 9, "bold")).pack(side="left", padx=4)
        self.ctl_msg = tk.Label(ctl, text="", bg="#121a24", fg="#8896a8",
                                font=("Segoe UI", 9))
        self.ctl_msg.pack(side="left", padx=12)

        nb = ttk.Notebook(self.root, style="CG.TNotebook")
        nb.pack(fill="both", expand=True, padx=10, pady=(8, 10))
        self.nb = nb
        self._tab_dashboard(nb)
        self._tab_events(nb)
        self._tab_actions(nb)
        self._tab_manage(nb)
        self._tab_blocklist(nb)
        self._poll()

    def _card(self, parent, title, value="–", accent="#2dd4bf"):
        box = tk.Frame(parent, bg="#121a24", highlightbackground="#22303f",
                       highlightthickness=1, padx=14, pady=12)
        tk.Label(box, text=title.upper(), bg="#121a24", fg="#8896a8",
                 font=("Segoe UI", 8, "bold"), anchor="w").pack(fill="x")
        v = tk.Label(box, text=str(value), bg="#121a24", fg=accent,
                     font=("Segoe UI", 22, "bold"), anchor="w")
        v.pack(fill="x", pady=(2, 0))
        box._val = v
        return box

    def _tab_dashboard(self, nb):
        f = tk.Frame(nb, bg="#0b0f16")
        nb.add(f, text="  Dashboard  ")
        krow = tk.Frame(f, bg="#0b0f16")
        krow.pack(fill="x", padx=10, pady=(10, 6))
        self.kpi = {}
        for key, title, accent in [
            ("events", "Events", "#e6edf3"),
            ("crit", "Critical 24h", "#f85149"),
            ("creds", "Credentials", "#d29922"),
            ("mon", "Monitors", "#3fb950"),
            ("up", "Uptime", "#38bdf8"),
            ("blk", "Blocked IPs", "#2dd4bf"),
        ]:
            c = self._card(krow, title, "–", accent)
            c.pack(side="left", fill="x", expand=True, padx=4)
            self.kpi[key] = c
        body = tk.Frame(f, bg="#0b0f16")
        body.pack(fill="both", expand=True, padx=10, pady=(4, 10))
        left = tk.Frame(body, bg="#121a24", highlightbackground="#22303f",
                        highlightthickness=1)
        left.pack(side="left", fill="both", expand=True, padx=(0, 6))
        tk.Label(left, text="  MONITORS", bg="#121a24", fg="#8896a8",
                 font=("Segoe UI", 8, "bold"), anchor="w").pack(fill="x", pady=(10, 4))
        self.ov_monitors = ttk.Treeview(left, columns=("name", "state"), show="headings",
                                         height=14, style="CG.Treeview")
        self.ov_monitors.heading("name", text="Monitor")
        self.ov_monitors.heading("state", text="State")
        self.ov_monitors.column("name", width=240)
        self.ov_monitors.column("state", width=110, anchor="center")
        self.ov_monitors.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.ov_monitors.tag_configure("running", foreground="#3fb950")
        self.ov_monitors.tag_configure("stopped", foreground="#f85149")
        right = tk.Frame(body, bg="#121a24", highlightbackground="#22303f",
                         highlightthickness=1)
        right.pack(side="left", fill="both", expand=True, padx=(6, 0))
        tk.Label(right, text="  RECENT EVENTS", bg="#121a24", fg="#8896a8",
                 font=("Segoe UI", 8, "bold"), anchor="w").pack(fill="x", pady=(10, 4))
        self.mini_feed = ttk.Treeview(right, columns=("time", "sev", "cat", "src"),
                                       show="headings", height=14, style="CG.Treeview")
        for cid, txt, w in (("time", "Time", 135), ("sev", "Severity", 80),
                            ("cat", "Category", 165), ("src", "Source", 150)):
            self.mini_feed.heading(cid, text=txt)
            self.mini_feed.column(cid, width=w)
        self.mini_feed.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        for s, c in (("critical", "#f85149"), ("high", "#f0883e"),
                     ("medium", "#d29922"), ("low", "#8896a8")):
            self.mini_feed.tag_configure(s, foreground=c)

    def _tab_events(self, nb):
        f = tk.Frame(nb, bg="#0b0f16")
        nb.add(f, text="  Events  ")
        hdr = tk.Frame(f, bg="#0b0f16")
        hdr.pack(fill="x", padx=10, pady=(10, 4))
        tk.Label(hdr, text="Latest events", bg="#0b0f16", fg="#8896a8").pack(side="left")
        tk.Button(hdr, text="Refresh", bg="#16202c", fg="#e6edf3",
                  relief="flat", bd=0, padx=10, pady=3,
                  command=lambda: self._worker(self._refresh_events)).pack(side="right")
        box = tk.Frame(f, bg="#121a24", highlightbackground="#22303f", highlightthickness=1)
        box.pack(fill="both", expand=True, padx=10, pady=(4, 10))
        cols = ("time", "sev", "cat", "src")
        self.ev_tree = ttk.Treeview(box, columns=cols, show="headings",
                                    style="CG.Treeview")
        for cid, txt, w in (("time", "Time", 170), ("sev", "Severity", 90),
                            ("cat", "Category", 220), ("src", "Source", 280)):
            self.ev_tree.heading(cid, text=txt)
            self.ev_tree.column(cid, width=w)
        ysb = ttk.Scrollbar(box, orient="vertical", command=self.ev_tree.yview)
        self.ev_tree.configure(yscrollcommand=ysb.set)
        self.ev_tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=8)
        ysb.pack(side="left", fill="y", pady=8)
        for s, c in (("critical", "#f85149"), ("high", "#f0883e"),
                     ("medium", "#d29922"), ("low", "#8896a8")):
            self.ev_tree.tag_configure(s, foreground=c)

    def _tab_actions(self, nb):
        f = tk.Frame(nb, bg="#0b0f16")
        nb.add(f, text="  Actions  ")
        wrap = tk.Frame(f, bg="#0b0f16")
        wrap.pack(fill="both", expand=True, padx=12, pady=12)

        def grp(title):
            g = tk.Frame(wrap, bg="#121a24", highlightbackground="#22303f",
                        highlightthickness=1)
            g.pack(fill="x", pady=(0, 10))
            tk.Label(g, text="  " + title.upper(), bg="#121a24", fg="#8896a8",
                     font=("Segoe UI", 8, "bold"), anchor="w").pack(fill="x", pady=(10, 6))
            row = tk.Frame(g, bg="#121a24")
            row.pack(fill="x", padx=10, pady=(0, 12))
            return row

        def abtn(p, text, cmd, danger=False):
            bg, fg = ("#3d1a1a", "#ff9c96") if danger else ("#16202c", "#e6edf3")
            tk.Button(p, text=text, command=cmd, bg=bg, fg=fg,
                      activebackground="#22303f", relief="flat", bd=0,
                      padx=12, pady=6).pack(side="left", padx=4)

        r = grp("PC control")
        abtn(r, "Lock PC", self._do_lock)
        abtn(r, "Panic", self._do_panic, danger=True)
        abtn(r, "Screenshot", self._do_shot)
        r = grp("Alerts")
        abtn(r, "Test alert", self._do_test)
        abtn(r, "Digest now", self._do_digest)
        tk.Label(r, text="  cat:", bg="#121a24", fg="#8896a8").pack(side="left", padx=(14, 4))
        self.mute_entry = tk.Entry(r, width=16, bg="#0b0f16", fg="#e6edf3",
                                   insertbackground="#e6edf3", relief="flat",
                                   highlightbackground="#22303f", highlightthickness=1)
        self.mute_entry.insert(0, "proc:start")
        self.mute_entry.pack(side="left", padx=4, ipady=4)
        abtn(r, "Mute", self._do_mute)
        abtn(r, "Unmute", self._do_unmute)
        abtn(r, "Unmute all", self._do_unmute_all)
        self.action_status = tk.Label(wrap, text="", bg="#0b0f16", fg="#8896a8",
                                      anchor="w")
        self.action_status.pack(fill="x", pady=(4, 0))

    def _tab_manage(self, nb):
        f = tk.Frame(nb, bg="#0b0f16")
        nb.add(f, text="  Monitors  ")
        box = tk.Frame(f, bg="#121a24", highlightbackground="#22303f",
                       highlightthickness=1)
        box.pack(fill="both", expand=True, padx=10, pady=10)
        top = tk.Frame(box, bg="#121a24")
        top.pack(fill="x", padx=10, pady=(10, 4))
        tk.Label(top, text="Enable / pause monitors (saved)",
                 bg="#121a24", fg="#8896a8").pack(side="left")
        tk.Button(top, text="Refresh", bg="#16202c", fg="#e6edf3",
                  relief="flat", bd=0, padx=10, pady=3,
                  command=lambda: self._worker(self._refresh_monitors)).pack(side="right", padx=3)
        tk.Button(top, text="Pause", bg="#16202c", fg="#e6edf3",
                  relief="flat", bd=0, padx=10, pady=3,
                  command=lambda: self._toggle_monitor(False)).pack(side="right", padx=3)
        tk.Button(top, text="Start", bg="#143d2b", fg="#8ce99a",
                  relief="flat", bd=0, padx=10, pady=3,
                  command=lambda: self._toggle_monitor(True)).pack(side="right", padx=3)
        self.mon_tree = ttk.Treeview(box, columns=("name", "state"), show="headings",
                                     style="CG.Treeview")
        self.mon_tree.heading("name", text="Monitor")
        self.mon_tree.heading("state", text="State")
        self.mon_tree.column("name", width=360)
        self.mon_tree.column("state", width=160, anchor="center")
        self.mon_tree.pack(fill="both", expand=True, padx=10, pady=(4, 10))
        self.mon_tree.tag_configure("running", foreground="#3fb950")
        self.mon_tree.tag_configure("stopped", foreground="#f85149")

    def _tab_blocklist(self, nb):
        f = tk.Frame(nb, bg="#0b0f16")
        nb.add(f, text="  Blocklist  ")
        box = tk.Frame(f, bg="#121a24", highlightbackground="#22303f",
                       highlightthickness=1)
        box.pack(fill="both", expand=True, padx=10, pady=10)
        top = tk.Frame(box, bg="#121a24")
        top.pack(fill="x", padx=10, pady=(10, 6))
        tk.Label(top, text="IP:", bg="#121a24", fg="#8896a8").pack(side="left")
        self.block_ip = tk.Entry(top, width=20, bg="#0b0f16", fg="#e6edf3",
                                 insertbackground="#e6edf3", relief="flat",
                                 highlightbackground="#22303f", highlightthickness=1)
        self.block_ip.pack(side="left", padx=6, ipady=4)
        for txt, cmd, bg, fg in (
            ("Block", self._do_block_ip, "#3d1a1a", "#ff9c96"),
            ("Unblock", self._do_unblock_ip, "#143d2b", "#8ce99a"),
            ("Refresh", self._refresh_ips, "#16202c", "#e6edf3"),
        ):
            tk.Button(top, text=txt, command=cmd, bg=bg, fg=fg,
                      relief="flat", bd=0, padx=10, pady=4).pack(side="left", padx=3)
        self.block_tree = ttk.Treeview(box, columns=("ip",), show="headings",
                                       height=18, style="CG.Treeview")
        self.block_tree.heading("ip", text="Blocked IP")
        self.block_tree.column("ip", width=420)
        self.block_tree.pack(fill="both", expand=True, padx=10, pady=(4, 10))

    def _set_action(self, txt, ok=True):
        fg = "#3fb950" if ok else "#f85149"
        for name in ("action_status", "ctl_msg"):
            try:
                getattr(self, name).config(text=txt, fg=fg)
            except Exception:
                pass

    def _control(self, action, label):
        self._set_action(f"{label}...")

        def work():
            self._post(f"/api/control/{action}", {"reason": "guardapp"})

        def done(res):
            if isinstance(res, Exception):
                self._set_action(f"{label} failed: {res}", ok=False)
                return
            self._set_action(f"{label} requested")
            self.root.after(1500, lambda: self._worker(self._refresh_overview))

        self._worker(work, done)

    def _ctl_pause(self):
        self._control("pause", "Sleep")

    def _ctl_resume(self):
        self._control("resume", "Resume")

    def _ctl_restart(self):
        self._control("restart", "Restart")

    def _ctl_stop(self):
        if not messagebox.askyesno(
            "Stop CanaryGuard",
            "Stop the whole service?\n\nDashboard will go offline. "
            "Use Telegram /start or this app to bring it back."):
            return
        self._control("stop", "Stop")

    def _act(self, path, name):
        self._set_action(f"{name}...")

        def work():
            self._post(path)

        def done(res):
            ok = not isinstance(res, Exception)
            self._set_action(f"{name} OK" if ok else f"{name} failed: {res}", ok=ok)

        self._worker(work, done)

    def _do_lock(self):
        self._act("/api/lock", "Lock")

    def _do_panic(self):
        self._act("/api/panic", "Panic lock")

    def _do_test(self):
        self._act("/api/test_alert", "Test alert")

    def _do_digest(self):
        self._act("/api/digest", "Digest")

    def _do_mute(self):
        cat = self.mute_entry.get().strip()
        if not cat:
            return
        self._worker(lambda: self._post("/api/mute", {"category": cat}),
                     lambda r: self._set_action(
                         f"muted {cat}" if not isinstance(r, Exception) else f"mute failed: {r}",
                         ok=not isinstance(r, Exception)))

    def _do_unmute(self):
        cat = self.mute_entry.get().strip()
        if not cat:
            return
        self._worker(lambda: self._post("/api/unmute", {"category": cat}),
                     lambda r: self._set_action(
                         f"unmuted {cat}" if not isinstance(r, Exception) else f"unmute failed: {r}",
                         ok=not isinstance(r, Exception)))

    def _do_unmute_all(self):
        self._worker(lambda: self._post("/api/unmute", {"all": True}),
                     lambda r: self._set_action(
                         "unmuted all" if not isinstance(r, Exception) else f"unmute failed: {r}",
                         ok=not isinstance(r, Exception)))

    def _do_block_ip(self):
        ip = self.block_ip.get().strip()
        if not ip:
            return

        def done(r):
            ok = not isinstance(r, Exception)
            self._set_action(f"blocked {ip}" if ok else f"block failed: {r}", ok=ok)
            self._worker(self._refresh_ips)
            self._worker(self._refresh_overview)

        self._worker(lambda: self._post("/api/ipblock/block", {"ip": ip}), done)

    def _do_unblock_ip(self):
        ip = self.block_ip.get().strip()
        if not ip:
            return

        def done(r):
            ok = not isinstance(r, Exception)
            self._set_action(f"unblocked {ip}" if ok else f"unblock failed: {r}", ok=ok)
            self._worker(self._refresh_ips)
            self._worker(self._refresh_overview)

        self._worker(lambda: self._post("/api/ipblock/remove", {"ip": ip}), done)

    def _do_shot(self):
        self._set_action("capturing screenshot...")

        def work():
            return self._get("/api/screenshot", timeout=15).content

        def done(res):
            if isinstance(res, Exception):
                self._set_action(f"screenshot failed: {res}", ok=False)
                return
            if Image is None:
                p = os.path.join(UI_DIR, "screenshot.jpg")
                with open(p, "wb") as fh:
                    fh.write(res)
                self._set_action(f"saved: {p}")
                return
            try:
                img = Image.open(io.BytesIO(res))
                top = tk.Toplevel(self.root)
                top.title("Screenshot")
                top.configure(bg="#0b0f16")
                w, h = img.size
                scale = min(900 / max(w, 1), 600 / max(h, 1), 1.0)
                prev = img.resize((int(w * scale), int(h * scale)), Image.LANCZOS)
                tkimg = ImageTk.PhotoImage(prev)
                lbl = tk.Label(top, image=tkimg, bg="#0b0f16")
                lbl.image = tkimg
                lbl.pack()
                self._set_action("screenshot OK")
            except Exception as exc:
                self._set_action(f"display failed: {exc}", ok=False)

        self._worker(work, done)

    def _open_dashboard(self):
        try:
            import webbrowser
            webbrowser.open(BASE_URL + "/")
        except Exception:
            pass

    def _poll(self):
        self._worker(self._refresh_overview)
        self.root.after(6000, self._poll)

    def _refresh_overview(self):
        try:
            d = self._get("/api/overview").json()
        except Exception as exc:
            self.ui(self._paint_offline, exc)
            return
        self.ui(self._paint_overview, d)
        self.ui(self._paint_events, d.get("events", []))

    def _refresh_stats(self):
        self._refresh_overview()

    def _refresh_events(self):
        try:
            self.ui(self._paint_events, self._get("/api/events").json())
        except Exception:
            pass

    def _refresh_monitors(self):
        try:
            self.ui(self._paint_monitors,
                    self._get("/api/monitors").json().get("monitors", {}))
        except Exception:
            pass

    def _refresh_ips(self):
        try:
            self.ui(self._paint_ips,
                    self._get("/api/ipblock/blocked").json().get("blocked", []))
        except Exception:
            pass

    def _paint_offline(self, exc):
        self.status_lbl.config(text=f"dashboard offline: {exc}", fg="#f85149")
        try:
            self.mode_badge.config(text="  OFFLINE  ", bg="#3d1a1a", fg="#ff9c96")
        except Exception:
            pass

    def _paint_overview(self, d):
        ctl = d.get("control") or {}
        st = d.get("stats") or {}
        mode = str(ctl.get("mode", "?")).lower()
        colors = {"running": ("#143d2b", "#8ce99a"), "paused": ("#3d3314", "#e9c46a"),
                  "stopped": ("#3d1a1a", "#ff9c96"), "starting": ("#14263d", "#8bd6ff"),
                  "restarting": ("#14263d", "#8bd6ff")}
        bg, fg = colors.get(mode, ("#16202c", "#8896a8"))
        self.mode_badge.config(text=f"  {mode.upper()}  ", bg=bg, fg=fg)
        up = ctl.get("uptime_seconds")
        up_txt = "–"
        if up is not None:
            s = int(up)
            h, m = divmod(s, 3600)
            d2, h = divmod(h, 24)
            up_txt = f"{d2}d {h}h" if d2 else (f"{h}h {m}m" if h else f"{m}m")
        self.status_lbl.config(
            text=f"{mode} · {ctl.get('monitors_running',0)}/{ctl.get('monitors_total',0)} monitors · {up_txt}",
            fg="#8896a8")
        sev = _count_map(st.get("severities") or [])
        crit = sev.get("critical", 0) + sev.get("high", 0)
        vals = {"events": f"{st.get('total',0):,}", "crit": f"{crit:,}",
                "creds": f"{st.get('creds',0):,}",
                "mon": f"{ctl.get('monitors_running',0)}/{ctl.get('monitors_total',0)}",
                "up": up_txt, "blk": f"{len(d.get('blocked') or []):,}"}
        for k, v in vals.items():
            if hasattr(self, "kpi") and k in self.kpi:
                self.kpi[k]._val.config(text=v)
        self._paint_monitors(d.get("monitors") or {})
        self._paint_ips(d.get("blocked") or [])

    def _paint_status(self, online):
        pass

    def _paint_cards(self, cards):
        pass

    def _paint_monitors(self, mons):
        for tv in (getattr(self, "ov_monitors", None), getattr(self, "mon_tree", None)):
            if tv is None:
                continue
            for i in tv.get_children():
                tv.delete(i)
            for name, info in sorted(mons.items()):
                st = info.get("status", "?") if isinstance(info, dict) else str(info)
                tv.insert("", "end", values=(name, st),
                          tags=("running" if st == "running" else "stopped",))

    def _paint_events(self, rows):
        for tv in (getattr(self, "ev_tree", None), getattr(self, "mini_feed", None)):
            if tv is None:
                continue
            for i in tv.get_children():
                tv.delete(i)
            src = rows[:120] if tv is getattr(self, "ev_tree", None) else rows[:18]
            for e in src:
                sev = str(e.get("severity", "low")).lower()
                srcv = e.get("src_ip") or e.get("ip") or "-"
                tv.insert("", "end",
                          values=(e.get("ts", ""), sev, e.get("category", "?"), srcv),
                          tags=(sev if sev in ("critical", "high", "medium", "low") else "low",))

    def _paint_ips(self, ips):
        tv = getattr(self, "block_tree", None)
        if tv is None:
            return
        for i in tv.get_children():
            tv.delete(i)
        for ip in ips:
            tv.insert("", "end", values=(ip,))

    def _toggle_monitor(self, enabled):
        tv = getattr(self, "mon_tree", None)
        if tv is None:
            return
        sel = tv.selection()
        if not sel:
            self._set_action("pick a monitor first", ok=False)
            return
        name = tv.item(sel[0], "values")[0]

        def done(r):
            ok = not isinstance(r, Exception)
            self._set_action(
                f"{name} {'started' if enabled else 'paused'}" if ok else f"toggle failed: {r}",
                ok=ok)
            self._worker(self._refresh_monitors)
            self._worker(self._refresh_overview)

        self._worker(lambda: self._post(f"/api/monitors/{name}", {"enabled": enabled}),
                    done)


def main():
    try:
        if os.name == "nt":
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "CanaryGuard.Desktop")
    except Exception:
        pass
    root = tk.Tk()
    try:
        root.withdraw()
    except Exception:
        pass
    GuardApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
