import json

from clefcve.labeler import is_done, load_labels, save_label


def test_save_and_clear_label(tmp_path):
    path = tmp_path / "labels.json"
    save_label("CVE-2026-0001", {"security_impact": "y", "desc_clarity": 3}, path)
    save_label("CVE-2026-0002", {"security_impact": "n"}, path)
    labels = load_labels(path)
    assert is_done(labels["CVE-2026-0001"]) and not is_done(labels["CVE-2026-0002"])
    assert "labeled_at" in labels["CVE-2026-0001"]
    save_label("CVE-2026-0001", {}, path)  # empty label clears
    assert set(json.loads(path.read_text())) == {"CVE-2026-0002"}
    assert not list(tmp_path.glob("*.tmp"))  # atomic write leaves no temp files
