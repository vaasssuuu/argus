# Where to contribute

The core of Argus is solid: the validation loop, the deterministic oracle, the sandbox, the
benchmark, and a `pip`-installable CLI all work. That leaves a lot of good, self-contained
places to help without needing to understand the whole system first.

Please skim **[CONTRIBUTING.md](CONTRIBUTING.md)** before starting, especially the scope section
(it is what keeps the project focused). To claim something, open an issue or a short Discussion
so we do not duplicate work.

Difficulty: 🟢 good first issue · 🟡 medium · 🔴 ambitious.

## Targets and benchmark
- 🟢 Add more **decoys** (traps) to the bundled targets so precision is tested harder.
- 🟡 Add IDOR surfaces Argus does not cover yet: **UUID ids**, **nested routes**
  (`/users/{a}/orders/{b}`), **object references in request bodies**, pagination or search leaks.
- 🟡 Add a **third bundled target** in a different domain to widen the benchmark.
- 🟢 Grow the **eval set** with more principal pairs and edge cases.

## Recon (the biggest open area)
- 🔴 **Autonomous recon on unknown apps.** Today the bring-your-own-target flow needs a spec.
  Infer object endpoints and ownership from an **OpenAPI file**, or by crawling the app from an
  authenticated session. This is the highest-impact feature on the list.

## Oracle
- 🟡 A **similarity-based differential** so the manifest-free oracle can catch leaks whose
  responses embed the requester's identity (today it requires an exact match, on purpose).
- 🟡 Handle **non-JSON** and partial-content responses in the content check.

## Runner and sandbox
- 🟡 A second **sandbox backend** behind the existing abstraction (for example a microVM option),
  chosen at runtime.
- 🟢 Friendlier errors when **Docker is not running** or an image is missing.

## Dashboard
- 🟡 A **target switcher** so the replay can show the clinic run as well as the saas run.
- 🟢 **Filters** on the findings (confirmed only, by endpoint, by principal).
- 🟢 A **copy-as-curl** button on each piece of evidence.

## CLI and developer experience
- 🟡 Accept an **OpenAPI spec** directly for `--target` instead of the custom spec format.
- 🟡 **SARIF output** so findings drop into IDEs and CI dashboards.
- 🟢 A `--json` flag that prints findings as machine-readable output.

## CI and packaging
- 🟢 A **GitHub Actions** workflow that runs `argus eval` on every push (no Docker, no key) as a
  green gate, with a status badge.

## Docs and examples
- 🟢 A short tutorial: **"write your first target spec and scan your own app."**
- 🟢 Example specs for common frameworks (Flask, Express, FastAPI, Rails).

---

Out of scope (so nobody spends effort that cannot be merged): other vulnerability families, a
hosted "scan any URL" service, and turning the single agent into a swarm. See CONTRIBUTING.md for
the why.
