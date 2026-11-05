import os

from canaryguard.ingest import Ingestor


class _Logger:
    def __call__(self, *args):
        pass


def _ingestor(log_file, offset, ino):
    ing = Ingestor.__new__(Ingestor)
    ing.logger = _Logger()
    ing.log_file = log_file
    ing._offset = offset
    ing._ino = ino
    return ing


def test_truncated_log_resets_offset(tmp_path):
    log = tmp_path / "opencanary.log"
    log.write_text("short\n", encoding="utf-8")
    ing = _ingestor(str(log), offset=10_000_000, ino=None)
    ing._maybe_reset_for_rotation(str(log))
    assert ing._offset is None


def test_inode_change_resets_offset(tmp_path):
    log = tmp_path / "opencanary.log"
    log.write_text("some content here\n", encoding="utf-8")
    st = os.stat(str(log))
    ing = _ingestor(str(log), offset=10, ino=(st.st_ino or 0) + 999999)
    ing._maybe_reset_for_rotation(str(log))
    assert ing._offset is None


def test_stable_file_keeps_offset(tmp_path):
    log = tmp_path / "opencanary.log"
    payload = "x" * 5000 + "\n"
    log.write_text(payload, encoding="utf-8")
    st = os.stat(str(log))
    ing = _ingestor(str(log), offset=100, ino=st.st_ino)
    ing._maybe_reset_for_rotation(str(log))
    assert ing._offset == 100
