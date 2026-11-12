// ============================================================
// OTLC Guardian - inbound-file check 8: Windows Defender
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// The file as it sits on disk is scanned once by Windows Defender,
// after the walk:
//
//   MpCmdRun.exe -Scan -ScanType 3 -File <path> -DisableRemediation
//
// A custom scan of the one file with the local signatures. Nothing
// is fetched (no signature update is asked for) and nothing is
// removed or quarantined by this scan: Guardian reports, the daemon
// decides.
//
//   - exit 0: no threat, the check passes;
//   - exit 2 with no failure reported: a threat, the file blocks;
//   - exit 2 is also how MpCmdRun reports that the scan failed
//     ("CmdTool: Failed with hr = 0x80004005" when Defender is turned
//     off because another antivirus is the active one). A failed scan
//     holds: as unavailable when Defender's service is not running,
//     else as an error with the code;
//   - Defender missing, timing out or failing in any other way holds:
//     a scan that did not happen is never clean;
//   - off Windows the check does not run, which holds as well.
//
// The daemon starts the CLI with only PATH and SystemRoot in the
// environment, so MpCmdRun.exe is looked for under %ProgramFiles%
// when that is set and under C:\Program Files otherwise.
// ============================================================

import { spawnSync } from "child_process";
import path from "path";

const DEFAULT_PROGRAM_FILES = "C:\\Program Files";
const DEFAULT_SYSTEM_ROOT = "C:\\Windows";
const SERVICE = "WinDefend";
const SERVICE_RUNNING = 4;
const SERVICE_TIMEOUT_MS = 5_000;
const DETAIL_MAX = 200;
// "Threat                  : Virus:DOS/EICAR_Test_File"
const THREAT_LINE = /^\s*Threat\s*:\s*(.+?)\s*$/gm;
const FAILURE_CODE = /0x[0-9A-Fa-f]{8}/;
const SCAN_FAILED = /Failed with hr|\[Failed\]/i;
// "        STATE              : 4  RUNNING": the number, which does not change with the display language.
const SERVICE_STATE = /\bSTATE\s*:\s*(\d+)/;

/**
 * @typedef {object} DefenderResult
 * @property {"clean"|"threat"|"unavailable"|"error"} status
 * @property {string} detail
 */

/**
 * Builds the runner that scans one file with MpCmdRun.exe. `env` and
 * `spawn` are injectable for tests.
 *
 * @param {{ env?: Record<string, string|undefined>, spawn?: typeof spawnSync }} [options]
 * @returns {(filePath: string, timeoutMs: number) => DefenderResult}
 */
export function defenderRunner({ env = process.env, spawn = spawnSync } = {}) {
  const exe = path.win32.join(env.ProgramFiles || DEFAULT_PROGRAM_FILES, "Windows Defender", "MpCmdRun.exe");
  return (filePath, timeoutMs) => {
    const run = spawn(exe, ["-Scan", "-ScanType", "3", "-File", filePath, "-DisableRemediation"], {
      encoding: "utf8",
      timeout: timeoutMs,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    if (run.error) {
      if (run.error.code === "ENOENT") return { status: "unavailable", detail: `${exe} was not found` };
      if (run.error.code === "ETIMEDOUT") return { status: "error", detail: `the scan did not finish in ${Math.round(timeoutMs / 1000)} s` };
      return { status: "error", detail: `MpCmdRun.exe could not be started (${run.error.code ?? run.error.message})` };
    }
    if (run.status === 0) return { status: "clean", detail: "no threat found" };
    const output = `${run.stdout ?? ""}\n${run.stderr ?? ""}`;
    if (run.status === 2 && !SCAN_FAILED.test(output)) {
      const names = [...new Set([...output.matchAll(THREAT_LINE)].map((m) => m[1]))];
      return { status: "threat", detail: names.length ? names.join(", ") : "a threat (Defender's output did not name it)" };
    }
    if (run.status === null) return { status: "error", detail: `the scan was stopped by ${run.signal ?? "a signal"}` };
    if (!serviceRunning(env, spawn)) {
      return { status: "unavailable", detail: `the Windows Defender service (${SERVICE}) is not running; another antivirus may be the active one` };
    }
    const code = FAILURE_CODE.exec(output)?.[0];
    return { status: "error", detail: `MpCmdRun.exe exit code ${run.status}${code ? ` (${code})` : ""}` };
  };
}

/**
 * Whether Defender's service is running, asked only after a scan
 * failed, to say why. A query that itself fails says nothing, so the
 * scan's own failure stands.
 */
function serviceRunning(env, spawn) {
  const sc = path.win32.join(env.SystemRoot || DEFAULT_SYSTEM_ROOT, "System32", "sc.exe");
  const query = spawn(sc, ["query", SERVICE], { encoding: "utf8", timeout: SERVICE_TIMEOUT_MS, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  if (query.error || query.status !== 0) return true;
  const state = SERVICE_STATE.exec(String(query.stdout ?? ""))?.[1];
  return state === undefined || Number(state) === SERVICE_RUNNING;
}

const clip = (text) => {
  const flat = String(text ?? "").replace(/\s+/g, " ").trim();
  return flat.length > DETAIL_MAX ? `${flat.slice(0, DETAIL_MAX)}...` : flat;
};

/**
 * Check 8. Called once, on the top-level file.
 * @param {import("../index.js").Inspection} ctx
 * @param {string} filePath
 * @param {import("../index.js").Node} node
 */
export function checkDefender(ctx, filePath, node) {
  const timeoutMs = ctx.budget.remainingMs();
  if (timeoutMs <= 0) {
    ctx.report("defender", "hold", "defender-error", "no time was left for the Defender scan; the file was not scanned", node);
    return;
  }
  const run = ctx.options.defender ?? defenderRunner();
  const result = run(path.resolve(filePath), timeoutMs);
  switch (result?.status) {
    case "clean":
      return;
    case "threat":
      ctx.report("defender", "block", "defender-threat", `Windows Defender found ${clip(result.detail)}`, node);
      return;
    case "unavailable":
      ctx.report("defender", "hold", "defender-unavailable", `Windows Defender is not available: ${clip(result.detail)}; the file was not scanned`, node);
      return;
    case "error":
      ctx.report("defender", "hold", "defender-error", `the Defender scan failed: ${clip(result.detail)}; the file was not scanned`, node);
      return;
    default:
      ctx.report("defender", "hold", "defender-error", "the Defender scan gave no answer Guardian knows; the file was not scanned", node);
  }
}
