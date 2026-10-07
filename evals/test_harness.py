"""The quality-bar gate (SPEC §12), now across every bundled target: the oracle must confirm
every genuine IDOR and reject every planted trap — zero false positives, zero misses."""
from evals.harness import run


def test_quality_bar_perfect_across_targets():
    m = run(write=False)["metrics"]
    assert m["confusion"]["FP"] == 0, "a trap was wrongly confirmed"
    assert m["confusion"]["FN"] == 0, "a real IDOR was missed"
    assert m["precision"] == 1.0 and m["recall"] == 1.0


def test_every_target_scored_with_both_classes():
    pt = run(write=False)["per_target"]
    assert set(pt) == {"saas", "clinic"}
    for name, tm in pt.items():
        assert tm["confusion"]["TP"] > 0 and tm["confusion"]["TN"] > 0, f"{name} missing a class"
