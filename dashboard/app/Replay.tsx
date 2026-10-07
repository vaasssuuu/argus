"use client";

import { useEffect, useRef, useState } from "react";
import type { Report, Trace } from "@/lib/trace";
import { clean, isConfirmed, phaseOf } from "@/lib/trace";
import FindingCard from "./FindingCard";

const STEP_MS = 85;

export default function Replay({ trace, report }: { trace: Trace; report: Report }) {
  const total = trace.steps.length;
  const [shown, setShown] = useState(0);
  const [playing, setPlaying] = useState(true);
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

  return (
    <>
      <div className="topbar">
        <div className="brand"><span className="mark" />ARGUS</div>
        <div className="meta">
          <span>run <b>{trace.run_id}</b></span>
          <span>{trace.target}</span>
        </div>
      </div>

      <main className="wrap">
        <header className="hero">
          <div className="eyebrow">IDOR / Broken Access Control · autonomous validation</div>
          <h1>Prove it.<br /><span className="accent">Don&apos;t guess.</span></h1>
          <p className="lede">
            Argus finds access-control vulnerabilities and proves each one by generating and
            executing a real exploit in an isolated sandbox, then returns a verdict with
            evidence: confirmed, or false&nbsp;positive rejected.
          </p>

          <div className="stats">
            <div className="stat"><div className="n good">{confirmed.length}</div><div className="k">Confirmed</div></div>
            <div className="stat"><div className="n cool">{rejected.length}</div><div className="k">Rejected</div></div>
            <div className="stat"><div className="n good">{pct(report.metrics.precision)}</div><div className="k">Precision</div></div>
            <div className="stat"><div className="n">{report.metrics.confusion.FP}</div><div className="k">False positives</div></div>
          </div>
        </header>

        <section>
          <div className="sec-head">
            <h2>The run</h2><span className="rule" />
            <span className="count">{shown}/{total} steps</span>
          </div>

          <div className="replay">
            <div className="replay-bar">
              <span className={`dot ${done ? "" : "live"}`} />
              <span className="title">{done ? "replay complete" : "replaying captured run…"}</span>
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
                    <span className={`phase ${ok ? "verdict-ok" : no ? "verdict-no" : ""}`}>
                      {phaseOf(s.node)}
                    </span>
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
            <span className="count">{confirmed.length} with proof</span>
          </div>
          <div className="grid">
            {confirmed.map((f) => <FindingCard key={f.id} f={f} />)}
          </div>
        </section>

        <section>
          <div className="sec-head">
            <h2>Rejected — false positives</h2><span className="rule" />
            <span className="count">{rejected.length} access held</span>
          </div>
          <div className="grid">
            {rejected.map((f) => <FindingCard key={f.id} f={f} />)}
          </div>
        </section>

        <footer>
          <span>Genuine captured evidence · replayed deterministically · no mocks.</span>
          <a href="https://github.com/vaasssuuu/argus">github.com/vaasssuuu/argus →</a>
        </footer>
      </main>
    </>
  );
}
