import traceJson from "../public/traces/run-9d06965c.json";
import reportJson from "../public/report.json";
import type { Report, Trace } from "@/lib/trace";
import Replay from "./Replay";

const trace = traceJson as unknown as Trace;
const report = reportJson as unknown as Report;

export default function Page() {
  return <Replay trace={trace} report={report} />;
}
