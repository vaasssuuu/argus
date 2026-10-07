# Contributing to Argus

Thanks for your interest! Argus has a sharp, deliberate scope, so the most useful thing you can
read before writing any code is the **Scope** section below — it's what keeps the project from
turning into a shallow everything-scanner.

## The philosophy (please internalize this)

Argus proves findings; it does not guess. The whole value is the **validation loop**: generate a
real exploit, run it in isolation, and decide *confirmed vs. false positive* with evidence, via a
**deterministic oracle** — never by asking the LLM to grade itself. **Depth on validation beats
breadth on vulnerability types.** A change that trades oracle rigor for more surface area is the
wrong change here.

## Dev setup

Requires [uv](https://docs.astral.sh/uv/) and Python 3.11+. Docker is needed only for the full
sandboxed run.

```bash
uv sync
uv run pytest                  # must stay green
uv run python -m evals.harness # the scorecard must stay at precision 1.00 / recall 1.00
```

No API key or Docker is required for the tests or the scorecard. The live `cli.argus scan` run
needs Docker running and an LLM key in `.env` (see `.env.example`).

## What makes a good PR

- **Tests + the eval stay green.** Non-trivial logic ships with a check. New target behavior or
  oracle logic ships with a test that fails if the logic breaks.
- **Small, boring, focused.** Prefer the shortest change that works; reuse what's there; reach for
  the standard library before a new dependency. Match the style of the surrounding code.
- **One concern per PR**, with a clear description of the problem and the approach.
- **New dependencies need a reason** in the PR description.

## Scope — what will and won't be accepted

**Welcome:**
- Harder target endpoints and trickier **decoys/traps** (UUID or nested ids, GraphQL, pagination
  or search-based leaks, object references in request bodies).
- More **eval cases** → a richer precision/recall number and confusion matrix.
- New **object-reference patterns** for the recon step to discover.
- The **replay dashboard** (see the roadmap in the README).
- Docs, examples, and a second sandbox/runner backend behind the existing abstraction.

**Will be declined (not personal — it's the thesis):**
- ❌ Adding a **second vulnerability family** before the IDOR loop's precision/recall bar is met.
- ❌ Any ability to point the tool at **arbitrary, non-authorized targets** — Argus attacks only
  the bundled target, and that guardrail is enforced in the network layer by design.
- ❌ Turning the single agent into a **swarm of agents**.
- ❌ Complexity that doesn't serve the proof loop or the demo.

If you're unsure whether an idea fits, **open a Discussion first** — that's cheaper than a PR that
has to be turned down.

## How to contribute, step by step

1. **Found a bug or have a focused improvement?** Open an **Issue** (look for `good-first-issue` /
   `help-wanted` labels). **Have an idea or a scope question?** Open a **Discussion**.
2. Fork the repo and create a branch.
3. Make the change; add/adjust tests; run `uv run pytest` and `uv run python -m evals.harness`.
4. Open a PR describing the problem and your approach. CI must pass.

By contributing, you agree your contributions are licensed under the project's license (intended
MIT; a `LICENSE` file will be added).
