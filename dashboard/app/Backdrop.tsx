"use client";

// Atmosphere: faint IDOR probes drifting upward behind the hero — the tool quietly
// enumerating ids. Deterministic positions (index-based) so SSR and client markup match.

const PROBES = [
  ["GET /api/invoices/1024", "200", "leaked"],
  ["GET /api/records/5002", "403", "held"],
  ["GET /api/orders/3002", "403", "held"],
  ["GET /api/documents/9001", "200", "leaked"],
  ["GET /api/messages/6002", "403", "held"],
  ["GET /api/labs/9003", "200", "leaked"],
  ["GET /api/billing/4002", "403", "held"],
  ["GET /api/prescriptions/7002", "200", "leaked"],
  ["GET /api/users/42/profile", "403", "held"],
  ["GET /api/invoices/1025", "200", "leaked"],
  ["GET /api/records/5003", "200", "leaked"],
  ["GET /api/settings/5021", "403", "held"],
  ["GET /api/labs/9002", "403", "held"],
  ["GET /api/documents/9004", "200", "leaked"],
  ["GET /api/orders/3005", "403", "held"],
  ["GET /api/prescriptions/7001", "200", "leaked"],
];

export default function Backdrop() {
  return (
    <div className="backdrop" aria-hidden>
      {PROBES.map(([req, code, verdict], i) => {
        const leaked = verdict === "leaked";
        const left = (i * 61) % 92;           // spread across width, deterministic
        const dur = 16 + (i % 6) * 3.5;        // 16s..33.5s
        const delay = -((i * 2.3) % dur);      // staggered, already in-flight on load
        return (
          <span
            key={i}
            className="probe"
            style={{ left: `${left}%`, animationDuration: `${dur}s`, animationDelay: `${delay}s` }}
          >
            {req} <span className="arrow">{"->"}</span>{" "}
            <span className={leaked ? "leak" : "held"}>{code} {verdict}</span>
          </span>
        );
      })}
    </div>
  );
}
