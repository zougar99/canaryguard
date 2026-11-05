"""Shared Windows helpers.

Every external command we spawn should go through ``run`` / ``popen`` so it
never pops up a console window. ``CREATE_NO_WINDOW`` (0x08000000) is honoured
on Windows; on other platforms the flags are ignored.
"""
import os
import subprocess

NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW
DETACHED = 0x00000008   # DETACHED_PROCESS
NEW_GROUP = 0x00000200  # CREATE_NEW_PROCESS_GROUP

IS_WINDOWS = os.name == "nt"


def hidden_kwargs():
    return {"creationflags": NO_WINDOW} if IS_WINDOWS else {}


def run(*args, **kwargs):
    if IS_WINDOWS:
        kwargs.setdefault("creationflags", NO_WINDOW)
    return subprocess.run(*args, **kwargs)


def popen(*args, **kwargs):
    if IS_WINDOWS:
        kwargs.setdefault("creationflags", NO_WINDOW)
    return subprocess.Popen(*args, **kwargs)


def detach(*args, **kwargs):
    if IS_WINDOWS and args:
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | NO_WINDOW | DETACHED | NEW_GROUP
    return subprocess.Popen(*args, **kwargs)
