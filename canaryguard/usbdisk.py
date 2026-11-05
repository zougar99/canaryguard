import os
import threading
import time
from datetime import datetime

from .config import get_store

try:
    import psutil
except ImportError:
    psutil = None


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _volume_label(mountpoint):
    try:
        import ctypes
        name = ctypes.create_unicode_buffer(261)
        fs = ctypes.create_unicode_buffer(261)
        ok = ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(mountpoint), name, 261, None, None, None, fs, 261
        )
        if ok:
            return name.value or ""
    except Exception:
        pass
    return ""


def _set_usb_write_protect(enable):
    """Global USB write-protection via registry (needs admin; applies to
    newly plugged sticks). Returns True on success."""
    try:
        import winreg
        key_path = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
        key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0,
                                 winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
        with key:
            winreg.SetValueEx(key, "WriteProtect", 0, winreg.REG_DWORD, 1 if enable else 0)
        return True
    except PermissionError:
        return False
    except Exception:
        return False


def _usb_device_info():
    """Return USB disk devices (model + serial) via WMI/CIM, best-effort."""
    try:
        import subprocess
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_DiskDrive | Where-Object {$_.InterfaceType -eq 'USB'} | "
             "ForEach-Object { \"$($_.Model) | SN=$($_.SerialNumber)\" }"],
            capture_output=True, text=True, timeout=10,
        )
        return [l.strip() for l in out.stdout.splitlines() if l.strip()]
    except Exception:
        return []


class USBDiskMonitor:
    """Watch drives and folders: connections, Explorer opens, file activity,
    and programs executed from them.

    - Any drive letter that appears AFTER startup (USB stick, external disk,
      mounted volume) triggers a CONNECTED alert and gets a live filesystem
      watcher for created/modified/deleted files.
    - Every Explorer folder navigation is tracked, so opening a folder on
      C:, H: or a USB stick fires an alert (cooldown per path).
    - Programs launched from non-system drives (or configured extra folders)
      are reported as EXECUTED.
    """

    def __init__(self, config, alerts=None, logger=None, panic=None):
        self.config = config
        self.logger = logger or print
        self.store = get_store(config)
        self.alerts = alerts
        self.poll = float(config.get("usb_monitor", "poll_seconds", default=3))
        self.cooldown = int(config.get("usb_monitor", "cooldown_seconds", default=30))
        self.notify_connect = config.get("usb_monitor", "notify_connect", default=True)
        self.notify_files = config.get("usb_monitor", "notify_files", default=True)
        self.notify_open = config.get("usb_monitor", "notify_explorer_open", default=True)
        self.notify_exec = config.get("usb_monitor", "notify_exec", default=True)
        self.extra_folders = [
            os.path.normpath(p) + os.sep
            for p in config.get("usb_monitor", "extra_folders", default=[])
        ]
        self.watch_drives = [
            d.replace("\\", "").replace("/", "").upper()
            for d in config.get("usb_monitor", "watch_drives", default=[])
        ]
        self.block_writes = config.get("usb_monitor", "block_unknown_writes", default=False)
        self.panic = panic  # PanicManager or None
        self._stop = threading.Event()
        self._thread = None
        self._known = set()
        self._observers = {}
        self._open_cd = {}
        self._exec_seen = set()
        self._shell = None
        self._shell_failed = False
        self._exec_roots = []

    # ---------- helpers ----------

    def _within(self, table, key):
        now = time.monotonic()
        last = table.get(key)
        if last is not None and now - last < self.cooldown:
            return True
        table[key] = now
        return False

    def _alert(self, category, severity, title, lines):
        if not self.alerts:
            return
        now = _now()
        event = {"src_host": "local", "src_port": -1, "dst_port": -1, "local_time": now, "ts": now}
        self.alerts.send(event, category, severity, "\n".join([title] + lines))

    # ---------- drives ----------

    def _partitions(self):
        parts = {}
        for p in psutil.disk_partitions(all=True):
            mp = p.mountpoint
            if len(mp) >= 2 and mp[1] == ":":
                parts[mp] = p
        return parts

    def _attach_watcher(self, mountpoint):
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            root = self

            class Handler(FileSystemEventHandler):
                def on_any_event(self, event):
                    root._fs_event(mountpoint, event)

            obs = Observer()
            obs.schedule(Handler(), mountpoint, recursive=True)
            obs.daemon = True
            obs.start()
            self._observers[mountpoint] = obs
            self.logger(f"[usb] watching {mountpoint}")
        except Exception as exc:
            self.logger(f"[usb] watcher failed for {mountpoint}: {exc}")

    def _on_connected(self, mp, part):
        removable = "removable" in (getattr(part, "opts", "") or "").lower()
        fstype = getattr(part, "fstype", "") or "?"
        label = _volume_label(mp)
        kind = "removable" if removable else "drive"
        desc = f"{label} ({fstype}, {kind})" if label else f"({fstype}, {kind})"
        details = f"{mp} {desc}"
        devices = _usb_device_info() if removable else []
        if devices:
            details += " | " + "; ".join(devices[:3])
        self.store.insert_usb_event("connected", mp, details)
        self.logger(f"[usb] DRIVE CONNECTED: {details}")
        if self.panic:
            self.panic.usb_connected(mp)
        blocked = False
        if removable and self.block_writes:
            blocked = _set_usb_write_protect(True)
            if blocked:
                self.logger(f"[usb] WRITE-PROTECT enabled for USB media")
        if self.notify_connect and not self._within(self._open_cd, f"conn:{mp}"):
            icon = "\U0001f50c" if removable else "\U0001f4bf"
            lines = [f"drive: {mp}", f"label: {label or '-'}", f"type: {fstype} {kind}",
                     f"time: {_now()}"]
            for dev in devices[:2]:
                lines.append(f"device: {dev}")
            if blocked:
                lines.append("\u26d4 write-protect ON (USB writes blocked)")
            self._alert("usb:connect", "high" if removable else "medium",
                        f"{icon} {'USB' if removable else 'DRIVE'} CONNECTED", lines)
        self._attach_watcher(mp)
        self._exec_roots.append(os.path.normpath(mp) + os.sep)

    def _on_removed(self, mp):
        details = f"{mp} disconnected"
        self.store.insert_usb_event("disconnected", mp, details)
        self.logger(f"[usb] DRIVE REMOVED: {mp}")
        if self.panic:
            self.panic.usb_removed(mp)
        obs = self._observers.pop(mp, None)
        if obs:
            obs.stop()
        self._exec_roots = [r for r in self._exec_roots if not r.startswith(mp)]
        if self.notify_connect and not self._within(self._open_cd, f"disc:{mp}"):
            self._alert("usb:connect", "medium", f"\U0001f6aa DRIVE DISCONNECTED",
                        [f"drive: {mp}", f"time: {_now()}"])

    def _fs_event(self, mountpoint, event):
        etype = getattr(event, "event_type", "")
        path = getattr(event, "dest_path", "") or getattr(event, "src_path", "")
        if not path or etype in ("opened", "closed_no_write"):
            return
        self.store.insert_usb_event("file", mountpoint, f"{etype}: {path}")
        self.logger(f"[usb] FILE {etype} on {mountpoint}: {path}")
        if not self.notify_files:
            return
        if self._within(self._open_cd, f"fs:{etype}:{path}"):
            return
        icons = {"created": "\U0001f4dd", "deleted": "\U0001f5d1\ufe0f", "modified": "\u270f\ufe0f", "moved": "\U0001f4c2"}
        _fallback = "\U0001f4c4"
        self._alert("usb:file", "medium",
                    f"{icons.get(etype, _fallback)} FILE {etype.upper()} on {mountpoint}",
                    [f"path: {path}", f"time: {_now()}"])

    # ---------- explorer windows ----------

    def _check_explorer_windows(self):
        if self._shell_failed:
            return
        try:
            import pythoncom
            import win32com.client
            if self._shell is None:
                pythoncom.CoInitialize()
                self._shell = win32com.client.Dispatch("Shell.Application")
            for win in list(self._shell.Windows()):
                url = ""
                try:
                    url = win.LocationURL or ""
                except Exception:
                    continue
                if not url.lower().startswith("file:///"):
                    continue
                path = url[len("file:///"):].replace("/", "\\")
                drive2 = path[:2].upper() if len(path) >= 2 and path[1] == ":" else ""
                # filter: only watched drives + dynamically attached (new/USB) drives
                if self.watch_drives:
                    on_dynamic = any(drive2 == mp[:2].upper() for mp in list(self._observers))
                    if drive2 not in self.watch_drives and not on_dynamic:
                        continue
                full_drive = drive2 + "\\" if drive2 else "?"
                if self._within(self._open_cd, f"open:{path.lower()}"):
                    continue
                details = f"opened: {path}"
                self.store.insert_usb_event("opened", full_drive, details)
                self.logger(f"[usb] FOLDER OPENED: {path}")
                if self.notify_open:
                    self._alert("usb:open", "medium", f"\U0001f4c2 FOLDER OPENED",
                                [f"path: {path}", f"time: {_now()}"])
        except Exception as exc:
            self._shell_failed = True
            self.logger(f"[usb] explorer tracking unavailable: {exc}")

    # ---------- executions ----------

    def _check_executions(self):
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                info = proc.info
                pid = info["pid"]
                exe = (info["exe"] or "").lower()
                if not exe or pid in self._exec_seen:
                    continue
                hit_root = next((r for r in self._exec_roots if exe.startswith(r.lower())), None)
                if not hit_root:
                    continue
                self._exec_seen.add(pid)
                name = info["name"] or os.path.basename(exe)
                details = f"executed: {name} from {exe}"
                self.store.insert_usb_event("executed", hit_root[:2], details)
                self.logger(f"[usb] EXECUTED FROM DRIVE: {name} ({exe})")
                if self.notify_exec and not self._within(self._open_cd, f"exec:{exe}"):
                    self._alert("usb:exec", "critical", f"\u26a1 PROGRAM RUN FROM EXTERNAL DRIVE",
                                [f"app: {name}", f"path: {exe}", f"time: {_now()}"])
            except Exception:
                continue

    # ---------- loop ----------

    def _loop(self):
        while not self._stop.is_set():
            try:
                parts = self._partitions()
                new = set(parts) - self._known
                gone = self._known - set(parts)
                for mp in sorted(new):
                    self._on_connected(mp, parts[mp])
                for mp in sorted(gone):
                    self._on_removed(mp)
                self._known = set(parts)
                self._check_explorer_windows()
                self._check_executions()
            except Exception as exc:
                self.logger(f"[usb] error: {exc}")
            self._stop.wait(self.poll)

    def start(self):
        if psutil is None:
            self.logger("[usb] psutil missing - drive monitor disabled")
            return
        self._known = set(self._partitions())   # silent baseline
        self._exec_roots = list(self.extra_folders)
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.logger(f"[usb] monitoring drives (baseline: {len(self._known)}), extra={self.extra_folders or 'none'}")

    def stop(self):
        self._stop.set()
        for obs in self._observers.values():
            try:
                obs.stop()
            except Exception:
                pass