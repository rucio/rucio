from pathlib import Path


def test_set_replica_unavailable_uses_for_update_lock():
    src = (
        Path(__file__).resolve().parents[1]
        / "lib"
        / "rucio"
        / "core"
        / "rule_grouping.py"
    ).read_text(encoding="utf-8")
    idx = src.index("def __set_replica_unavailable")
    body = src[idx : idx + 650]
    assert "with_for_update()" in body
    assert "populate_existing=True" in body
    assert "locked_replica.lock_cnt -= 1" in body
