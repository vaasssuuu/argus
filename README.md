# Argus

**An autonomous agent that finds one class of vulnerability — IDOR / broken access control — and *proves* each finding by generating and executing a real exploit in an isolated sandbox.** It returns a verdict with evidence: *exploit confirmed*, or *false positive rejected*.

The proof loop is the product. Argus doesn't flag "possible" issues and leave you to sort through them — it tries the attack, and shows you what happened.

---

## The idea: prove it, don't guess

Most scanners produce a long list of *maybes*. Real issues get buried under false alarms, and a human has to manually confirm each one.

Argus takes the opposite bet on a single, narrow problem and goes deep:

1. It finds candidate access-control issues.
2. It generates a concrete proof-of-concept exploit.
3. It runs that exploit against an authorized target **inside a sandbox that can reach only that target**.
4. It returns a verdict **with the evidence that justifies it**:
   - ✅ **Confirmed** — here is the exact request/response showing one user holding another user's private data.
   - ❌ **Rejected (false positive)** — the access control held; here's the `403`. Not a bug.

That second outcome — confidently, verifiably saying *"this is not a vulnerability"* — is the signature behavior, and the hard part almost nothing does well.

## The bug it hunts: IDOR / broken access control

IDOR (Insecure Direct Object Reference) is when an app lets you reach **someone else's** object just by changing an identifier in the request — e.g. opening `/api/invoices/124` when only `/api/invoices/123` is yours, because the handler forgot to check *"does this belong to the caller?"* It is one of the most common and most serious bugs in fast-built apps, precisely because that ownership check is so easy to omit.

## Benchmark result

Argus ships with a deliberately-vulnerable target that contains **real holes** and **decoys** (endpoints that take an object id and *look* exploitable but are correctly authorized). On that benchmark:

| | Confirmed | Rejected |
|---|---|---|
| **Real IDORs (6)** | 6 ✅ | 0 |
| **Decoys / traps (6)** | 0 | 6 ✅ |

**Precision 1.00 · Recall 1.00 · Zero false positives.** For each confirmed finding, Argus also drafts a remediation suggestion.

> Honest caveat: this is a controlled target with a known answer key — on purpose. That's how you plant decoys and get a real precision number. Crucially, the oracle decides from *behavior alone* (did the attacker actually receive the victim's data?); the answer key is used only to **score** the run, never during detection.

## How it works

```
 CLI ─▶ Agent (single LangGraph state machine) ─▶ Runner (Docker, egress-locked) ─▶ Target (bundled vuln app)
            │                                           ▲
            ├── LLM (provider-agnostic) ────────────────┘   proposes candidates + PoCs
            └── Oracle (deterministic) ── verdict + evidence ─▶ Trace (JSON)
```

The loop, as explicit steps: **recon → candidates → PoC synthesis → execute → classify (oracle) → remediate**.

Three design choices carry the whole thing:

- **The LLM proposes; a deterministic oracle disposes.** The model may hypothesize candidates and write exploits, but it *never* renders the verdict — a plain, deterministic function does, from evidence. The AI never grades its own homework.
- **One agent, one tight loop — not a swarm.** LangGraph models the loop as an explicit state machine of steps, which stays legible and matches the single-family scope.
- **The guardrail lives in the network, not a prompt.** Exploits run in a Docker container on an `--internal` network (no gateway to the internet). By construction, the sandbox can reach the authorized target and nothing else — and a self-check proves the internet is unreachable from inside.

## Quickstart

Requires [uv](https://docs.astral.sh/uv/). Docker is needed only for the full sandboxed run.

```bash
uv sync                                 # create the env (Python 3.11+)

uv run pytest                           # the test suite (no Docker, no API key)
uv run python -m evals.harness          # the scorecard: precision/recall + confusion matrix

# Full end-to-end run (needs Docker running + an LLM key, see below):
cp .env.example .env                     # then put your key in .env
uv run python -m cli.argus scan          # builds the sandbox, runs the loop, writes traces/run-*.json
```

The LLM is provider-agnostic (any OpenAI-compatible API). The default is DeepSeek — set `DEEPSEEK_API_KEY` in `.env` (see `.env.example`). The scorecard and tests need **no** key and **no** Docker.

## Project layout

```
target/   the deliberately-vulnerable Flask app + its ground-truth manifest (the answer key)
agent/    the loop: schemas, LLM client, the 6 nodes, the LangGraph graph, and the oracle
runner/   the Docker sandbox + the network-level egress guardrail
cli/      `argus scan`
evals/    the scorecard (precision/recall + confusion matrix)
traces/   captured run evidence (JSON)
```

## Scope — narrow on purpose

Argus is deliberately **one vulnerability family, done deeply**. These are explicit non-goals, not missing features:

- ❌ Other vulnerability families (until the IDOR loop is genuinely solid and measured).
- ❌ A "graph of agents" swarm — one agent, one orchestrated loop.
- ❌ Pointing the tool at arbitrary live targets — it attacks **only** the bundled/authorized target. This is a hard legal + safety guardrail, enforced at the network layer.

## Roadmap

- [x] Vulnerable target + ground-truth manifest
- [x] The validation loop (recon → … → oracle), CLI, end-to-end
- [x] Docker sandbox + egress guardrail
- [x] Eval harness (precision/recall + confusion matrix)
- [ ] Replay dashboard (web UI that replays a captured run)
- [ ] CI (run the scan on push, publish the evidence artifact)

## Contributing

Contributions are welcome — please read **[CONTRIBUTING.md](CONTRIBUTING.md)** first, especially the scope section (it's what keeps the project focused). Good first areas: harder target endpoints and decoys, more eval cases, the dashboard, and new object-reference patterns for recon to discover.

## License

Intended: **MIT** — a `LICENSE` file will be added. Until then, all rights reserved by the author.
