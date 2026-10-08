"use client";

import { useEffect, useRef, useState } from "react";
import type { Report, Trace } from "@/lib/trace";
import { clean, isConfirmed, phaseOf } from "@/lib/trace";
import Backdrop from "./Backdrop";
import FindingCard from "./FindingCard";

const STEP_MS = 85;
const REPO = "https://github.com/vaasssuuu/argus";
const INSTALL = "pip install argus-idor\nargus scan --provider <provider>\nargus eval";

export default function Replay({ trace, report }: { trace: Trace; report: Report }) {
  const total = trace.steps.length;
  const [shown, setShown] = useState(0);
  const [playing, setPlaying] = useState(true);
  const [copied, setCopied] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!playing || shown >= total) return;
    const t = setTimeout(() => setShown((n) => n + 1), STEP_MS);
    return () => clearTimeout(t);
  }, [playing, shown, total]);

  useEffect(() => {
    if (shown >= total) setPlaying(false);
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: "smooth" });
  }, [shown, total]);

  const confirmed = trace.findings.filter(isConfirmed);
  const rejected = trace.findings.filter((f) => !isConfirmed(f));
  const pct = (x: number) => `${Math.round(x * 100)}%`;
  const done = shown >= total;
  const restart = () => { setShown(0); setPlaying(true); };
  const copyInstall = () => {
    navigator.clipboard?.writeText(INSTALL).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <>
      <Backdrop />

      <div className="topbar">
        <div className="brand"><span className="mark" />ARGUS</div>
        <div className="nav">
          <div className="meta"><span>run <b>{trace.run_id}</b></span></div>
          <a className="btn-contribute" href={REPO}>★ Contribute</a>
        </div>
      </div>

      <main className="wrap">
        <header className="hero">
          <div className="eyebrow">autonomous IDOR / broken-access-control validation</div>
          <h1>Is your app one guessed ID<br /><span className="accent">away from a breach?</span></h1>
          <p className="lede">
            Change one number in a URL and you could be reading another user&apos;s data. That&apos;s
            IDOR, and it hides in almost every fast-built app. Argus is an autonomous agent that
            hunts it and proves each finding with a real exploit, run in an isolated sandbox. No
            maybes: confirmed with evidence, or rejected.
          </p>

          <div className="install">
            <div className="install-bar">
              <span className="tag">install &amp; run</span>
              <button className="copy" onClick={copyInstall}>{copied ? "copied ✓" : "copy"}</button>
            </div>
            <pre>
<span className="prompt">$</span> pip install argus-idor{"\n"}
<span className="prompt">$</span> argus scan --provider &lt;provider&gt;   <span className="cmt"># gemini, deepseek, or openai</span>{"\n"}
<span className="prompt">$</span> argus eval                          <span className="cmt"># the benchmark · no key</span>
            </pre>
          </div>
          <p className="lede" style={{ marginTop: 16, fontSize: 15 }}>
            Works with DeepSeek, OpenAI, or Gemini (free flash tier). Runs locally against a
            target you authorize, in a sandbox that can reach nothing else.
          </p>

          <div className="stats">
            <div className="stat"><div className="n good">{pct(report.metrics.precision)}</div><div className="k">Precision</div></div>
            <div className="stat"><div className="n good">{pct(report.metrics.recall)}</div><div className="k">Recall</div></div>
            <div className="stat"><div className="n">{report.metrics.n_cases}</div><div className="k">Cases tested</div></div>
            <div className="stat"><div className="n">{report.metrics.confusion.FP}</div><div className="k">False positives</div></div>
          </div>

          {report.per_target && (
            <p className="benchline">
              Benchmarked across {Object.keys(report.per_target).length} target apps:{" "}
              {Object.entries(report.per_target).map(([name, m]) => `${name} (${m.n_cases})`).join(" · ")}
              . {report.metrics.confusion.TP} real IDORs confirmed, {report.metrics.confusion.TN} decoys rejected,{" "}
              {report.metrics.confusion.FP} false positives.
            </p>
          )}
        </header>

        <section>
          <div className="sec-head">
            <h2>Watch it work</h2><span className="rule" />
            <span className="count">{shown}/{total} steps</span>
          </div>

          <div className="replay">
            <div className="replay-bar">
              <span className={`dot ${done ? "" : "live"}`} />
              <span className="title">{done ? "replay complete" : "replaying a captured run…"}</span>
              <span className="spacer" />
              <button className="ctrl" onClick={() => setPlaying((p) => !p)} disabled={done}>
                {playing && !done ? "pause" : "play"}
              </button>
              <button className="ctrl" onClick={restart}>↻ replay</button>
            </div>
            <div className="progress"><i style={{ width: `${(shown / total) * 100}%` }} /></div>
            <div className="log" ref={logRef}>
              {trace.steps.slice(0, shown).map((s, i) => {
                const ok = s.node === "classify" && s.summary.startsWith("confirmed");
                const no = s.node === "classify" && s.summary.startsWith("false_positive");
                return (
                  <div className="log-row" key={i}>
                    <span className={`phase ${ok ? "verdict-ok" : no ? "verdict-no" : ""}`}>{phaseOf(s.node)}</span>
                    <span className="msg">{clean(s.summary)}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </section>

        <section>
          <div className="sec-head">
            <h2>Confirmed exploits</h2><span className="rule" />
            <span className="count">{confirmed.length} in this run · with proof</span>
          </div>
          <div className="grid">{confirmed.map((f) => <FindingCard key={f.id} f={f} />)}</div>
        </section>

        <section>
          <div className="sec-head">
            <h2>Rejected · false positives</h2><span className="rule" />
            <span className="count">{rejected.length} in this run · access held</span>
          </div>
          <div className="grid">{rejected.map((f) => <FindingCard key={f.id} f={f} />)}</div>
        </section>

        <footer>
          <span>Genuine captured evidence · replayed deterministically · no mocks.</span>
          <a href={REPO}>github.com/vaasssuuu/argus →</a>
        </footer>
        <div className="footcredit">
          Built by <span className="who">Vatsalya Soni</span>, CS undergrad. Argus is open source,{" "}
          <a href={REPO}>now by you too</a>.
          <span className="sub">prove it, don&apos;t guess.</span>
        </div>
      </main>
    </>
  );
}
