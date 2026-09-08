"""Sanity-check the loader API against the shipped data/ directory."""

from cticonnect import (
    list_tasks, list_categories, load_task, load_all, get_manifest,
)


TASK_COUNTS = {
    "rcm": 290, "wim": 308, "atd": 261, "esd": 280,
    "ata": 160, "vca": 219,
    "csc": 111, "tap": 135, "mla": 95,
}


def test_categories():
    assert list_categories() == [
        "entity_linking", "entity_attribution", "multi_doc_synthesis"
    ]


def test_task_counts():
    for task, expected in TASK_COUNTS.items():
        assert len(load_task(task)) == expected, task


def test_total_count_is_1859():
    assert sum(len(load_task(t)) for t in TASK_COUNTS) == 1859


def test_manifest_consistency():
    manifest = get_manifest()
    assert manifest["total_count"] == 1859
    all_data = load_all()
    for task, info in manifest["tasks"].items():
        assert info["count"] == len(all_data[task])


def test_qa_record_fields():
    qa = load_task("rcm")[0]
    assert qa.id.startswith("rcm-")
    assert qa.task == "rcm"
    assert qa.category == "entity_linking"
    assert qa.eval_type == "single_id_match"
    assert qa.question
    assert qa.answer
    assert qa.ground_truth.target_id.startswith("CWE-")


def test_el_question_no_id_leak():
    """EL questions must never contain CVE/CWE/CAPEC/T-IDs."""
    import re
    leak_re = re.compile(r"CVE-\d{4}-\d+|CWE-\d+|CAPEC-\d+|\bT\d{4}(?:\.\d+)?\b")
    for task in ["rcm", "wim", "atd", "esd"]:
        for qa in load_task(task):
            assert not leak_re.search(qa.question), (
                f"ID leak in {qa.id}: {qa.question[:200]}"
            )
