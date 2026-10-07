"""The quality-bar gate (SPEC §12): on the eval set the oracle must confirm every genuine IDOR
and reject every planted trap — i.e. zero false positives, zero misses."""
from evals.harness import run


def test_quality_bar_perfect_on_benchmark():
    m = run(write=False)["metrics"]
    assert m["confusion"]["FP"] == 0, "a trap was wrongly confirmed"
    assert m["confusion"]["FN"] == 0, "a real IDOR was missed"
    assert m["precision"] == 1.0 and m["recall"] == 1.0


def test_benchmark_has_both_classes():
    c = run(write=False)["metrics"]["confusion"]
    assert c["TP"] > 0 and c["TN"] > 0, "benchmark must contain real IDORs and traps"
