import type { Finding } from "@/lib/trace";
import { clean, isConfirmed, leakedSecret } from "@/lib/trace";

function ResponseBody({ f }: { f: Finding }) {
  const text = f.response.body_excerpt.trim();
  const secret = leakedSecret(f);
  const ok = isConfirmed(f);
  const status = (
    <span style={{ color: ok ? "var(--confirm)" : "var(--reject)", fontWeight: 600 }}>
      HTTP {f.response.status}
    </span>
  );
  if (ok && secret && text.includes(secret)) {
    const i = text.indexOf(secret);
    return (
      <pre>{status}{"\n"}{text.slice(0, i)}<span className="secret">{secret}</span>{text.slice(i + secret.length)}</pre>
    );
  }
  return <pre>{status}{"\n"}{text}</pre>;
}

export default function FindingCard({ f }: { f: Finding }) {
  const ok = isConfirmed(f);
  const verdict = ok ? "confirmed" : "rejected";
  const reason = clean(f.reason);

  return (
    <article className={`card ${verdict}`}>
      <div className="card-top">
        <div>
          <div className="endpoint">{f.endpoint}</div>
          <div className="flow">{f.attacker} <span className="arrow">→</span> {f.victim}</div>
        </div>
        <div style={{ textAlign: "right" }}>
          <span className={`verdict ${verdict}`}>
            {ok ? "✓ confirmed" : "✕ rejected"}
          </span>
          <div className={`status ${ok ? "s2" : "s4"}`} style={{ marginTop: 10 }}>
            {f.response.status}
          </div>
        </div>
      </div>

      <p className="reason">
        {reason.startsWith(f.attacker) ? (
          <><span className="mark">{f.attacker}</span>{reason.slice(f.attacker.length)}</>
        ) : (
          reason
        )}
      </p>

      <details className="expander">
        <summary><span className="chev">›</span> evidence</summary>
        <div className="evidence">
          <div className="ev-block">
            <div className="ev-label">exploit request</div>
            <pre>{f.request.method} {f.request.path}{"\n"}Authorization: Bearer &lt;redacted&gt;</pre>
          </div>
          <div className="ev-block">
            <div className="ev-label">response{ok ? " · victim data leaked" : " · access control held"}</div>
            <ResponseBody f={f} />
          </div>

          {ok && f.checks.length > 0 && (
            <div className="checks">
              {f.checks.map((c) => <span className="chk" key={c}>{c}</span>)}
            </div>
          )}

          {ok && f.remediation && (
            <div className="fix"><b>Fix:</b> {clean(f.remediation)}</div>
          )}
        </div>
      </details>
    </article>
  );
}
