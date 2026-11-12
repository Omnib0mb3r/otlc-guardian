// ============================================================
// OTLC Guardian - inbound-file check 8: antivirus
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// The file as it sits on disk is scanned once, after the walk, by
// whichever antivirus engine protects this machine. Guardian changes
// no antivirus setting, fetches nothing and removes nothing: it
// reports, the daemon decides.
//
// Engines, in order:
//
//   1. Windows Defender, when its service (WinDefend) is running:
//        MpCmdRun.exe -Scan -ScanType 3 -File <path> -DisableRemediation
//      Exit 0 is clean. Exit 2 with no failure reported is a threat.
//      Exit 2 is also how MpCmdRun reports a scan that failed
//      ("CmdTool: Failed with hr = ..."), which holds.
//
//   2. Otherwise the antivirus registered as this machine's AMSI
//      provider (Antimalware Scan Interface; a third-party antivirus
//      that replaces Defender registers one). A Windows PowerShell
//      child runs engines/amsi.ps1, a plain script file: it calls
//      AmsiInitialize, AmsiOpenSession, AmsiScanBuffer over the
//      file's bytes, AmsiCloseSession and AmsiUninitialize. A file
//      larger than one buffer goes through in chunks that overlap.
//      AMSI_RESULT_DETECTED (32768 or more) blocks; clean is
//      AMSI_RESULT_CLEAN (0) or NOT_DETECTED (1) only;
//      blocked-by-administrator results and every other value hold.
//
//      AMSI sees only the bytes it is handed and does not unpack an
//      archive. So every archive entry Guardian read (each file.inner
//      entry) goes to the child on standard input and is scanned as a
//      buffer of its own, under its inner path, in the same session.
//      A detection in an entry blocks with that entry's path.
//      MpCmdRun unpacks archives itself and gets the file only.
//
//      A provider whose product is switched off answers "clean" to
//      everything. So the product behind the provider must be listed
//      as enabled by Windows Security Center (root/SecurityCenter2,
//      AntiVirusProduct, productState bit 0x1000); otherwise the
//      check holds as antivirus-disabled.
//
//   3. Neither: the check holds. A scan that did not happen is never
//      clean. Off Windows the check does not run, which holds too.
//
// The daemon starts the CLI with only PATH and SystemRoot in the
// environment, so programs are found from %ProgramFiles% and
// %SystemRoot% when set and from C:\Program Files and C:\Windows
// otherwise, and the AMSI child is given a temp folder to compile in.
// The file's path and name reach the child in environment variables
// and the entries' paths on standard input, never in its command
// line: a name is untrusted. The command line is the same for every
// file and holds no script text.
// ============================================================

import { spawnSync } from "child_process";
import os from "os";
import path from "path";
import { fileURLToPath } from "url";

const DEFAULT_PROGRAM_FILES = "C:\\Program Files";
const DEFAULT_SYSTEM_ROOT = "C:\\Windows";
const SERVICE = "WinDefend";
const SERVICE_STATE_RUNNING = 4;
const SERVICE_TIMEOUT_MS = 5_000;
const DETAIL_MAX = 200;
// "Threat                  : Virus:DOS/EICAR_Test_File"
const THREAT_LINE = /^\s*Threat\s*:\s*(.+?)\s*$/gm;
const FAILURE_CODE = /0x[0-9A-Fa-f]{8}/;
const SCAN_FAILED = /Failed with hr|\[Failed\]/i;
// "        STATE              : 4  RUNNING": the number, which does not change with the display language.
const SERVICE_STATE = /\bSTATE\s*:\s*(\d+)/;

const DEFENDER_ENGINE = "Windows Defender (MpCmdRun)";

// AMSI_RESULT values (amsi.h).
const AMSI_CLEAN = 0;
const AMSI_NOT_DETECTED = 1;
const AMSI_BLOCKED_BY_ADMIN_START = 0x4000;
const AMSI_BLOCKED_BY_ADMIN_END = 0x4FFF;
const AMSI_DETECTED = 0x8000;

/** One AmsiScanBuffer call takes this many bytes. */
export const AMSI_CHUNK_BYTES = 16 * 1024 * 1024;
/** Each chunk starts with this many bytes of the one before, so nothing is cut in two unseen. */
export const AMSI_OVERLAP_BYTES = 64 * 1024;
/** The AMSI child's script. Its header says what it reads and prints. */
export const AMSI_SCRIPT = fileURLToPath(new URL("../engines/amsi.ps1", import.meta.url));

// Windows Security Center, AntiVirusProduct.productState: this bit is
// set while the product is switched on.
const PRODUCT_ENABLED = 0x1000;
// Windows Defender as Security Center lists it, and its AMSI provider DLL.
const DEFENDER_PRODUCT_PATH = /^windowsdefender:/i;
const DEFENDER_PROVIDER = "mpoav.dll";
// "C:", "Program Files", "<vendor>": a provider and a product that
// share at least this much of their path belong together.
const VENDOR_DEPTH = 3;

const SPAWN = { encoding: "utf8", windowsHide: true, stdio: ["ignore", "pipe", "pipe"] };

/**
 * @typedef {object} AntivirusResult
 * @property {string|null} engine what scanned, or null when nothing could
 * @property {"clean"|"threat"|"unavailable"|"disabled"|"error"} status of the file itself
 * @property {string} detail
 * @property {{ path: string, status: "threat"|"error", detail: string }[]} [findings]
 *   archive entries that are not clean, by inner path
 */

/**
 * @typedef {object} Entry an archive entry Guardian read
 * @property {string} path its inner path
 * @property {Buffer} data its bytes
 */

const hresult = (hr) => `0x${(Number(hr) >>> 0).toString(16).toUpperCase().padStart(8, "0")}`;

/**
 * Builds the runner that scans one file with this machine's antivirus.
 * `env` and `spawn` are injectable for tests.
 *
 * @param {{ env?: Record<string, string|undefined>, spawn?: typeof spawnSync }} [options]
 * @returns {(filePath: string, timeoutMs: number, contentName: string, entries?: Entry[]) => AntivirusResult}
 */
export function systemAntivirus({ env = process.env, spawn = spawnSync } = {}) {
  const systemRoot = env.SystemRoot || DEFAULT_SYSTEM_ROOT;
  return (filePath, timeoutMs, contentName, entries = []) => {
    const deadline = Date.now() + timeoutMs;
    const left = () => Math.max(1, deadline - Date.now());
    if (defenderRunning(systemRoot, spawn, Math.min(SERVICE_TIMEOUT_MS, left()))) {
      return { engine: DEFENDER_ENGINE, ...scanWithDefender(env, spawn, filePath, left()) };
    }
    const amsi = scanWithAmsi(env, systemRoot, spawn, filePath, contentName, entries, left());
    if (amsi.status === "unavailable") {
      return { engine: null, status: "unavailable", detail: `the Windows Defender service (${SERVICE}) is not running, and ${amsi.detail}` };
    }
    return amsi;
  };
}

/** Whether Defender's service is running. A query that fails or cannot be read says it is not. */
function defenderRunning(systemRoot, spawn, timeoutMs) {
  const query = spawn(path.win32.join(systemRoot, "System32", "sc.exe"), ["query", SERVICE], { ...SPAWN, timeout: timeoutMs });
  if (query.error || query.status !== 0) return false;
  return Number(SERVICE_STATE.exec(String(query.stdout ?? ""))?.[1]) === SERVICE_STATE_RUNNING;
}

function scanWithDefender(env, spawn, filePath, timeoutMs) {
  const exe = path.win32.join(env.ProgramFiles || DEFAULT_PROGRAM_FILES, "Windows Defender", "MpCmdRun.exe");
  const run = spawn(exe, ["-Scan", "-ScanType", "3", "-File", filePath, "-DisableRemediation"], { ...SPAWN, timeout: timeoutMs });
  if (run.error) {
    if (run.error.code === "ENOENT") return { status: "unavailable", detail: `${exe} was not found` };
    if (run.error.code === "ETIMEDOUT") return { status: "error", detail: `the scan did not finish in ${Math.round(timeoutMs / 1000)} s` };
    return { status: "error", detail: `MpCmdRun.exe could not be started (${run.error.code ?? run.error.message})` };
  }
  if (run.status === 0) return { status: "clean", detail: "no threat found" };
  const output = `${run.stdout ?? ""}\n${run.stderr ?? ""}`;
  if (run.status === 2 && !SCAN_FAILED.test(output)) {
    const names = [...new Set([...output.matchAll(THREAT_LINE)].map((m) => m[1]))];
    return { status: "threat", detail: names.length ? names.join(", ") : "a threat (the output did not name it)" };
  }
  if (run.status === null) return { status: "error", detail: `the scan was stopped by ${run.signal ?? "a signal"}` };
  const code = FAILURE_CODE.exec(output)?.[0];
  return { status: "error", detail: `MpCmdRun.exe exit code ${run.status}${code ? ` (${code})` : ""}` };
}

/**
 * The archive entries as the AMSI child reads them from standard
 * input: for each, the length of its path (4 bytes, little endian),
 * the path in UTF-8, the length of its data (8 bytes) and the data.
 * @param {Entry[]} entries
 * @returns {Buffer}
 */
export function encodeEntries(entries) {
  const frames = [];
  for (const { path: innerPath, data } of entries) {
    const name = Buffer.from(innerPath, "utf8");
    const head = Buffer.alloc(4 + name.length + 8);
    head.writeUInt32LE(name.length, 0);
    name.copy(head, 4);
    head.writeBigUInt64LE(BigInt(data.length), 4 + name.length);
    frames.push(head, data);
  }
  return Buffer.concat(frames);
}

/** The folders a Windows path runs through, lower case, without a \\?\ prefix. */
const folders = (file) => path.win32.dirname(String(file).replace(/^\\\\\?\\/, "")).toLowerCase().split("\\").filter(Boolean);

/** Whether a provider DLL belongs to a Security Center product. */
function sameProduct(provider, product) {
  const paths = Array.isArray(product?.paths) ? product.paths.map(String) : [];
  if (path.win32.basename(provider).toLowerCase() === DEFENDER_PROVIDER) return paths.some((p) => DEFENDER_PRODUCT_PATH.test(p));
  const dll = folders(provider);
  return paths.some((p) => {
    const exe = folders(p);
    let shared = 0;
    while (shared < dll.length && shared < exe.length && dll[shared] === exe[shared]) shared++;
    return shared >= VENDOR_DEPTH;
  });
}

/**
 * What Security Center says about the products behind the providers.
 * @returns {{ enabled: string[] } | { why: string }} the enabled products' names, or why none is
 */
function providerState(providers, products) {
  const own = products.filter((product) => providers.some((provider) => sameProduct(provider, product)));
  const enabled = own.filter((product) => Number.isInteger(product.state) && (product.state & PRODUCT_ENABLED) !== 0);
  if (enabled.length) return { enabled: enabled.map((product) => String(product.name)) };
  if (own.length === 0) return { why: "Windows Security Center lists no antivirus product for it" };
  const states = own.map((product) => `${product.name} (product state 0x${(Number(product.state) >>> 0).toString(16).toUpperCase().padStart(6, "0")})`);
  return { why: `Windows Security Center reports ${states.join(", ")} switched off` };
}

function amsiVerdict(result) {
  if (!Number.isInteger(result)) return { status: "error", detail: "the scan gave no AMSI result" };
  if (result >= AMSI_DETECTED) return { status: "threat", detail: `flagged as malware (AMSI result ${result})` };
  if (result === AMSI_CLEAN || result === AMSI_NOT_DETECTED) return { status: "clean", detail: "no threat found" };
  if (result >= AMSI_BLOCKED_BY_ADMIN_START && result <= AMSI_BLOCKED_BY_ADMIN_END) {
    return { status: "error", detail: `blocked by an administrator policy (AMSI result ${result})` };
  }
  return { status: "error", detail: `AMSI result ${result}, which Guardian does not know` };
}

function scanWithAmsi(env, systemRoot, spawn, filePath, contentName, entries, timeoutMs) {
  const exe = path.win32.join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const temp = env.TEMP || env.TMP || os.tmpdir();
  const run = spawn(exe, ["-NoProfile", "-NonInteractive", "-NoLogo", "-ExecutionPolicy", "Bypass", "-File", AMSI_SCRIPT], {
    ...SPAWN,
    stdio: ["pipe", "pipe", "pipe"],
    input: encodeEntries(entries),
    timeout: timeoutMs,
    env: {
      ...env,
      SystemRoot: systemRoot,
      TEMP: temp,
      TMP: temp,
      GUARDIAN_AMSI_FILE: filePath,
      GUARDIAN_AMSI_NAME: contentName,
      GUARDIAN_AMSI_CHUNK: String(AMSI_CHUNK_BYTES),
      GUARDIAN_AMSI_OVERLAP: String(AMSI_OVERLAP_BYTES),
    },
  });
  const unknown = "AMSI";
  if (run.error) {
    if (run.error.code === "ENOENT") return { engine: null, status: "unavailable", detail: `Windows PowerShell (${exe}) was not found, so no AMSI provider could be asked` };
    if (run.error.code === "ETIMEDOUT") return { engine: unknown, status: "error", detail: `the scan did not finish in ${Math.round(timeoutMs / 1000)} s` };
    return { engine: unknown, status: "error", detail: `the AMSI scan could not be started (${run.error.code ?? run.error.message})` };
  }
  if (run.status === null) return { engine: unknown, status: "error", detail: `the scan was stopped by ${run.signal ?? "a signal"}` };

  let out = null;
  const last = String(run.stdout ?? "").trim().split(/\r?\n/).pop();
  try {
    out = JSON.parse(last);
  } catch {
    // Not the script's JSON line: reported below with what the child wrote.
    out = null;
  }
  if (run.status !== 0 || out === null || typeof out !== "object" || !Array.isArray(out.providers)) {
    const said = String(run.stderr ?? "").trim() || last || "no output";
    return { engine: unknown, status: "error", detail: `the AMSI scan gave no result (exit code ${run.status}: ${said})` };
  }
  if (out.providers.length === 0) return { engine: null, status: "unavailable", detail: "no AMSI provider is registered" };

  const providers = out.providers.map(String);
  const named = `AMSI provider ${providers.map((p) => path.win32.basename(p)).join(", ")}`;
  if (out.productsError) return { engine: named, status: "error", detail: `Windows Security Center could not be read (${out.productsError})` };
  const state = providerState(providers, Array.isArray(out.products) ? out.products : []);
  if (!state.enabled) return { engine: null, status: "disabled", detail: `the ${named} cannot be relied on: ${state.why}` };

  const engine = `${named} (${state.enabled.join(", ")})`;
  if (out.error) return { engine, status: "error", detail: String(out.error) };
  if (out.init !== 0) return { engine, status: "error", detail: `AmsiInitialize failed (${hresult(out.init)})` };
  if (out.session !== 0) return { engine, status: "error", detail: `AmsiOpenSession failed (${hresult(out.session)})` };
  if (out.entries !== entries.length) {
    return { engine, status: "error", detail: `${out.entries} of ${entries.length} archive entries were scanned` };
  }
  const findings = [];
  const stray = { engine, status: "error", detail: "the scan named an archive entry Guardian did not send" };
  const known = (index) => Number.isInteger(index) && index >= 0 && index < entries.length;
  for (const { index, result } of Array.isArray(out.flagged) ? out.flagged : []) {
    if (!known(index)) return stray;
    findings.push({ path: entries[index].path, ...amsiVerdict(result) });
  }
  for (const { index, hr } of Array.isArray(out.entryErrors) ? out.entryErrors : []) {
    if (!known(index)) return stray;
    findings.push({ path: entries[index].path, status: "error", detail: `AmsiScanBuffer failed (${hresult(hr)})` });
  }
  const own = out.hr !== 0 ? { status: "error", detail: `AmsiScanBuffer failed (${hresult(out.hr)})` } : amsiVerdict(out.result);
  return { engine, ...own, findings: findings.filter((finding) => finding.status !== "clean") };
}

const clip = (text) => {
  const flat = String(text ?? "").replace(/\s+/g, " ").trim();
  return flat.length > DETAIL_MAX ? `${flat.slice(0, DETAIL_MAX)}...` : flat;
};

/**
 * Check 8. Called once, on the top-level file, with the archive
 * entries the walk read.
 * @param {import("../index.js").Inspection} ctx
 * @param {string} filePath
 * @param {import("../index.js").Node} node
 */
export function checkAntivirus(ctx, filePath, node) {
  const timeoutMs = ctx.budget.remainingMs();
  if (timeoutMs <= 0) {
    ctx.report("antivirus", "hold", "antivirus-error", "no time was left for the antivirus scan; the file was not scanned", node);
    return;
  }
  const run = ctx.options.antivirus ?? systemAntivirus();
  const result = run(path.resolve(filePath), timeoutMs, path.basename(filePath), ctx.entries);
  const engine = typeof result?.engine === "string" && result.engine ? result.engine : null;
  const by = engine ?? "the antivirus";
  switch (result?.status) {
    case "clean":
      ctx.antivirusEngine = engine;
      break;
    case "threat":
      ctx.antivirusEngine = engine;
      ctx.report("antivirus", "block", "antivirus-threat", `${by} found ${clip(result.detail)}`, node);
      break;
    case "unavailable":
      ctx.report("antivirus", "hold", "antivirus-unavailable", `no antivirus engine could scan the file: ${clip(result.detail)}`, node);
      return;
    case "disabled":
      ctx.report("antivirus", "hold", "antivirus-disabled", `${clip(result.detail)}; the file was not scanned`, node);
      return;
    case "error":
      ctx.antivirusEngine = engine;
      ctx.report("antivirus", "hold", "antivirus-error", `the scan by ${by} failed: ${clip(result.detail)}; the file was not scanned`, node);
      break;
    default:
      ctx.report("antivirus", "hold", "antivirus-error", "the antivirus scan gave no answer Guardian knows; the file was not scanned", node);
      return;
  }
  // Archive entries the engine was handed one by one.
  for (const finding of Array.isArray(result.findings) ? result.findings : []) {
    const where = { path: String(finding?.path) };
    if (finding?.status === "threat") {
      ctx.report("antivirus", "block", "antivirus-threat", `${by} found ${clip(finding.detail)}`, where);
    } else {
      ctx.report("antivirus", "hold", "antivirus-error", `the scan by ${by} failed: ${clip(finding?.detail)}; the entry was not scanned`, where);
    }
  }
}
