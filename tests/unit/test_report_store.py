import os
import time

import pytest

from backend.exceptions import ReportNotFound
from backend.schemas import Finding, Report, Severity, build_summary
from backend.storage.report_store import ReportStore


def _report(target: str, *severities: Severity) -> Report:
    findings = [Finding(title="t", severity=s) for s in severities]
    return Report(target=target, findings=findings, summary=build_summary(findings))


def test_roundtrip_listing_and_delete(tmp_path):
    store = ReportStore(tmp_path)
    first = _report("one", Severity.HIGH)
    store.save(first)
    time.sleep(0.01)
    second = _report("two")
    store.save(second)
    os.utime(tmp_path / f"{first.report_id}.json", (1, 1))

    loaded = store.load(first.report_id)
    assert loaded.summary.high == 1 and loaded.target == "one"
    assert [m.target for m in store.list()] == ["two", "one"]
    assert [m.target for m in store.list(limit=1)] == ["two"]
    assert store.count() == 2

    store.delete(first.report_id)
    with pytest.raises(ReportNotFound):
        store.load(first.report_id)
    assert [m.target for m in store.list()] == ["two"]
    assert not list(tmp_path.glob(".rpt_*"))


@pytest.mark.parametrize("bad_id", ["", "../etc/passwd", "rpt_XYZ", "rpt_0123456789ab/../x"])
def test_invalid_ids_never_touch_the_filesystem(tmp_path, bad_id):
    with pytest.raises(ReportNotFound):
        ReportStore(tmp_path).load(bad_id)


def test_corrupt_files_are_skipped(tmp_path):
    store = ReportStore(tmp_path)
    store.save(_report("ok"))
    (tmp_path / "rpt_0123456789ab.json").write_text("{not json", encoding="utf-8")
    assert [m.target for m in store.list()] == ["ok"]
