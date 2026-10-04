"""The validation loop as a LangGraph state machine (D6) — a single agent driving an explicit
graph of steps, NOT a swarm.

    recon → candidates → (poc → execute → classify)*  → remediate → END

The starred middle is a loop over candidates: after each verdict, the conditional edge sends us
back to synthesise the next PoC, or on to remediation once the candidates are exhausted.
"""
from functools import partial

from langgraph.graph import END, START, StateGraph

from agent.nodes.candidates import candidates
from agent.nodes.classify import classify
from agent.nodes.execute import execute
from agent.nodes.poc_synthesis import poc_synthesis
from agent.nodes.recon import recon
from agent.nodes.remediate import remediate
from agent.state import ScanState


def _next(state):
    return "poc" if state["cursor"] < len(state["candidates"]) else "remediate"


def build_graph(llm, runner, manifest):
    g = StateGraph(ScanState)
    g.add_node("recon", partial(recon, runner=runner))
    g.add_node("candidates", partial(candidates, llm=llm))
    g.add_node("poc", partial(poc_synthesis, llm=llm))
    g.add_node("execute", partial(execute, runner=runner))
    g.add_node("classify", partial(classify, manifest=manifest))
    g.add_node("remediate", partial(remediate, llm=llm))

    g.add_edge(START, "recon")
    g.add_edge("recon", "candidates")
    g.add_conditional_edges("candidates", _next, {"poc": "poc", "remediate": "remediate"})
    g.add_edge("poc", "execute")
    g.add_edge("execute", "classify")
    g.add_conditional_edges("classify", _next, {"poc": "poc", "remediate": "remediate"})
    g.add_edge("remediate", END)
    return g.compile()
