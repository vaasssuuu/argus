"""Classify — hand the attempt to the deterministic oracle for the verdict, then advance.

The node is a thin wrapper: all judgement lives in the oracle. It records the finding and the
reason (confirmed or false-positive) in the trace, then moves the cursor to the next candidate.
"""
from agent.oracle.differential import classify as oracle_classify


def classify(state, *, manifest):
    finding = oracle_classify(state["current_attempt"], manifest)
    state["trace"].step("classify", f"{finding.verdict}: {finding.reason}",
                        finding_id=finding.id, checks=finding.checks)
    return {"findings": state["findings"] + [finding], "cursor": state["cursor"] + 1}
