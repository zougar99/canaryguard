import json
import os
import threading

from .logstore import LogStore, get_logstore


class Config:
    _lock = threading.Lock()
    _instance = None

    @classmethod
    def load(cls, path=None):
        with cls._lock:
            if cls._instance is not None:
                return cls._instance
            path = path or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json")
            if not os.path.exists(path):
                raise FileNotFoundError(f"Config not found: {path}")
            with open(path, "r", encoding="utf-8") as fh:
                cls._instance = cls(json.load(fh), path)
            return cls._instance

    def __init__(self, data, path):
        self.data = data
        self.path = path
        self._base_dir = os.path.dirname(os.path.abspath(path))

    def get(self, *keys, default=None):
        node = self.data
        for key in keys:
            if not isinstance(node, dict) or key not in node:
                return default
            node = node[key]
        return node

    def section(self, *keys):
        value = self.get(*keys, default={})
        return value if isinstance(value, dict) else {}


def get_store(config: Config) -> LogStore:
    db_file = config.get("opencanary", "db_file")
    return get_logstore(db_file)