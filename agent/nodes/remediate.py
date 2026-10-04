"""Remediate — for CONFIRMED findings only, the LLM writes a fix suggestion (suggestion-only;
no code changes, no auto-PR — D7). False positives need no fix."""
from agent.schemas.finding import CONFIRMED

SYS = ("You are a security engineer. In 1-2 sentences, suggest how to fix the given broken-access-"
       "control (IDOR) issue. Be concrete and generic (an ownership check); no code, no preamble.")


def remediate(state, *, llm):
    fixed = 0
    for f in state["findings"]:
        if f.verdict == CONFIRMED:
            f.remediation = llm.chat(SYS, f"Endpoint {f.endpoint}: {f.reason}").strip()
            fixed += 1
    state["trace"].step("remediate", f"fix suggestions for {fixed} confirmed finding(s)")
    return {}
