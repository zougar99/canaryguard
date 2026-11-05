"""Runtime control for the CanaryGuard stack.

One place that knows how to start, stop, pause, resume and restart the main
service, and where the current mode is stored on disk. Used by the dashboard,
the desktop app and the always-on Telegram supervisor (cgctl.py).

Files
-----
runtime_state.json : {"mode": ..., "since": ..., "reason": ..., "pid": ...}
tamper.stopped     : present while the user asked for a full stop, so the
                     watchdog must NOT revive the service.
"""

import json
import os
import socket
import subprocess
import sys
from datetime import datetime

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_FILE = os.path.join(BASE, "runtime_state.json")
STOP_FLAG = os.path.join(BASE, "tamper.stopped")
TASK_NAME = "CanaryGuard"
PORT = 8080

VALID_MODES = ("starting", "running", "paused", "stopping", "stopped", "restarting")


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _hidden_kwargs():
    """Keep helper processes from flashing a console window."""
    if sys.platform.startswith("win"):
        return {"creationflags": 0x08000000}  # CREATE_NO_WINDOW
    return {}


# ---------------------------------------------------------------- state file

def read_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {"mode": "unknown", "since": None, "reason": ""}


def write_state(mode, reason="", extra=None):
    data = {"mode": mode, "since": _now(), "reason": reason or "", "pid": os.getpid()}
    if extra:
        data.update(extra)
    try:
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        os.replace(tmp, STATE_FILE)
    except Exception:
        pass
    return data


def set_stop_flag(on, reason=""):
    try:
        if on:
            with open(STOP_FLAG, "w", encoding="utf-8") as fh:
                fh.write(f"{_now()} {reason}\n")
        elif os.path.exists(STOP_FLAG):
            os.remove(STOP_FLAG)
    except Exception:
        pass


def stop_flag_set():
    return os.path.exists(STOP_FLAG)


# ---------------------------------------------------------------- probes

def port_open(port=PORT, host="127.0.0.1", timeout=1.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((host, port)) == 0
    finally:
        sock.close()


def find_main_pids():
    """PIDs of running main.py instances (never the supervisor)."""
    pids = []
    try:
        import psutil
    except ImportError:
        return pids
    for proc in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = " ".join(proc.info.get("cmdline") or [])
            if "main.py" in cmd and "canaryguard" in cmd.lower() and "cgctl" not in cmd:
                pids.append(proc.info["pid"])
        except Exception:
            continue
    return pids


def is_running():
    return bool(find_main_pids()) or port_open()


def uptime_seconds():
    st = read_state()
    since = st.get("since")
    if not since:
        return None
    try:
        started = datetime.strptime(since, "%Y-%m-%d %H:%M:%S")
        return max(0, int((datetime.now() - started).total_seconds()))
    except Exception:
        return None


def status():
    st = read_state()
    pids = find_main_pids()
    return {
        "mode": st.get("mode", "unknown"),
        "since": st.get("since"),
        "reason": st.get("reason", ""),
        "state_pid": st.get("pid"),
        "dashboard": port_open(),
        "pids": pids,
        "running": bool(pids) or port_open(),
        "stopped_flag": stop_flag_set(),
        "uptime_seconds": uptime_seconds(),
    }


# ---------------------------------------------------------------- actions

def start_stack(reason="start requested"):
    """Start the service through its scheduled task (works when stopped)."""
    set_stop_flag(False, reason)
    write_state("starting", reason)
    try:
        subprocess.run(["schtasks", "/run", "/tn", TASK_NAME],
                       capture_output=True, timeout=25, **_hidden_kwargs())
        return True, "start requested"
    except Exception as exc:
        write_state("stopped", f"start failed: {exc}")
        return False, str(exc)


def _post(path, payload=None, timeout=5):
    try:
        import requests

        return requests.post(f"http://127.0.0.1:{PORT}{path}", json=payload or {},
                             timeout=timeout)
    except Exception:
        return None


def stop_stack(reason="stop requested", wait=10):
    """Graceful API stop, then a hard kill as a fallback."""
    set_stop_flag(True, reason)
    write_state("stopping", reason)
    _post("/api/control/stop", {"reason": reason}, timeout=4)
    deadline = datetime.now().timestamp() + wait
    while datetime.now().timestamp() < deadline:
        if not port_open(timeout=0.5):
            break
        import time as _t

        _t.sleep(0.5)
    killed = 0
    for pid in find_main_pids():
        try:
            import psutil

            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
            killed += 1
        except Exception:
            continue
    write_state("stopped", reason, {"killed": killed})
    return True, f"stopped (killed={killed})"


def pause_stack(reason="pause requested"):
    set_stop_flag(False, reason)
    resp = _post("/api/control/pause", {"reason": reason})
    if resp is not None and resp.ok:
        return True, "paused"
    return False, "dashboard unreachable"


def resume_stack(reason="resume requested"):
    set_stop_flag(False, reason)
    resp = _post("/api/control/resume", {"reason": reason})
    if resp is not None and resp.ok:
        return True, "resumed"
    return False, "dashboard unreachable"


def restart_stack(reason="restart requested"):
    set_stop_flag(False, reason)
    write_state("restarting", reason)
    resp = _post("/api/control/restart", {"reason": reason}, timeout=4)
    if resp is not None and resp.ok:
        return True, "restarting"
    # dashboard was down: just start it
    return start_stack(reason)


def human_uptime(seconds):
    if seconds is None:
        return "?"
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d {hours}h {minutes}m"
    return f"{hours}h {minutes}m"
