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
//      child calls AmsiInitialize, AmsiOpenSession, AmsiScanBuffer
//      over the file's bytes, AmsiCloseSession and AmsiUninitialize.
//      A file larger than one buffer goes through in chunks that
//      overlap, in one session. Before the file, the child hands the
//      provider the antivirus industry's harmless test string: a
//      provider that does not flag it is not scanning (its product is
//      switched off, or it only takes scripts), and with no engine
//      the file is not clean. AMSI_RESULT_DETECTED (32768 or more)
//      blocks; clean is AMSI_RESULT_CLEAN (0) or NOT_DETECTED (1)
//      only; blocked-by-administrator results and every other value
//      hold.
//
//   3. Neither: the check holds. A scan that did not happen is never
//      clean. Off Windows the check does not run, which holds too.
//
// The daemon starts the CLI with only PATH and SystemRoot in the
// environment, so programs are found from %ProgramFiles% and
// %SystemRoot% when set and from C:\Program Files and C:\Windows
// otherwise, and the AMSI child is given a temp folder to compile in.
// The file's path and name reach the child in environment variables,
// never in its command text: a file name is untrusted.
// ============================================================

import { spawnSync } from "child_process";
import os from "os";
import path from "path";

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

/** One AmsiScanBuffer call takes this many bytes of the file. */
export const AMSI_CHUNK_BYTES = 16 * 1024 * 1024;
/** Each chunk starts this many bytes before the last one ended, so nothing is cut in two unseen. */
export const AMSI_OVERLAP_BYTES = 64 * 1024;

const SPAWN = { encoding: "utf8", windowsHide: true, stdio: ["ignore", "pipe", "pipe"] };

// The AMSI child. It prints one line of JSON and decides nothing:
//   providers   file names of the registered provider DLLs
//   init        HRESULT of AmsiInitialize
//   selftest    AMSI_RESULT for the antivirus test string, selftestHr its HRESULT
//   result      highest AMSI_RESULT over the file's chunks, hr the first failing HRESULT
//   chunks      AmsiScanBuffer calls made on the file
//   error       a .NET or PowerShell failure (the file could not be opened, Add-Type failed)
// The test string is put together at run time so no file holds it whole.
const AMSI_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
$out = @{ providers = @(); init = $null; selftest = $null; selftestHr = $null; result = $null; hr = 0; chunks = 0; error = $null }
try {
  $ids = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName })
  foreach ($id in $ids) {
    $dll = (Get-ItemProperty ('HKLM:\SOFTWARE\Classes\CLSID\' + $id + '\InprocServer32') -ErrorAction SilentlyContinue).'(default)'
    if ($dll) { $out.providers += [IO.Path]::GetFileName($dll.Trim('"')) } else { $out.providers += $id }
  }
  if ($out.providers.Count -gt 0) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class GuardianAmsi {
  [DllImport("amsi.dll", CharSet = CharSet.Unicode)] public static extern int AmsiInitialize(string appName, out IntPtr context);
  [DllImport("amsi.dll")] public static extern int AmsiOpenSession(IntPtr context, out IntPtr session);
  [DllImport("amsi.dll", CharSet = CharSet.Unicode)] public static extern int AmsiScanBuffer(IntPtr context, byte[] buffer, uint length, string contentName, IntPtr session, out int result);
  [DllImport("amsi.dll")] public static extern void AmsiCloseSession(IntPtr context, IntPtr session);
  [DllImport("amsi.dll")] public static extern void AmsiUninitialize(IntPtr context);
}
"@
    $context = [IntPtr]::Zero
    $out.init = [GuardianAmsi]::AmsiInitialize('OTLC Guardian inbound-check', [ref]$context)
    if ($out.init -eq 0) {
      try {
        $session = [IntPtr]::Zero
        $out.selftestHr = [GuardianAmsi]::AmsiOpenSession($context, [ref]$session)
        if ($out.selftestHr -eq 0) {
          try {
            $probe = [Text.Encoding]::ASCII.GetBytes('X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR' + '-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
            $verdict = 0
            $out.selftestHr = [GuardianAmsi]::AmsiScanBuffer($context, $probe, [uint32]$probe.Length, 'guardian-selftest.txt', $session, [ref]$verdict)
            if ($out.selftestHr -eq 0) { $out.selftest = $verdict }
          } finally { [GuardianAmsi]::AmsiCloseSession($context, $session) }
        }
        if ($out.selftestHr -eq 0 -and $out.selftest -ge 32768) {
          $chunk = [int]$env:GUARDIAN_AMSI_CHUNK
          $overlap = [int]$env:GUARDIAN_AMSI_OVERLAP
          $stream = [IO.File]::Open($env:GUARDIAN_AMSI_FILE, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
          try {
            $length = $stream.Length
            $out.result = 0
            $session = [IntPtr]::Zero
            $out.hr = [GuardianAmsi]::AmsiOpenSession($context, [ref]$session)
            if ($out.hr -eq 0) {
              try {
                $buffer = New-Object byte[] ([int][Math]::Min([long]$chunk, [Math]::Max([long]1, $length)))
                $position = [long]0
                while ($position -lt $length) {
                  $null = $stream.Seek($position, [IO.SeekOrigin]::Begin)
                  $filled = 0
                  while ($filled -lt $buffer.Length) {
                    $read = $stream.Read($buffer, $filled, $buffer.Length - $filled)
                    if ($read -le 0) { break }
                    $filled += $read
                  }
                  if ($filled -le 0) { break }
                  $verdict = 0
                  $out.hr = [GuardianAmsi]::AmsiScanBuffer($context, $buffer, [uint32]$filled, $env:GUARDIAN_AMSI_NAME, $session, [ref]$verdict)
                  $out.chunks += 1
                  if ($out.hr -ne 0) { break }
                  if ($verdict -gt $out.result) { $out.result = $verdict }
                  if ($verdict -ge 32768) { break }
                  if ($position + $filled -ge $length) { break }
                  $position += $filled - $overlap
                }
              } finally { [GuardianAmsi]::AmsiCloseSession($context, $session) }
            }
          } finally { $stream.Dispose() }
        }
      } finally { [GuardianAmsi]::AmsiUninitialize($context) }
    }
  }
} catch {
  $out.error = $_.Exception.Message
}
[Console]::Out.WriteLine(($out | ConvertTo-Json -Compress))
`;
const AMSI_COMMAND = Buffer.from(AMSI_SCRIPT, "utf16le").toString("base64");

/**
 * @typedef {object} AntivirusResult
 * @property {string|null} engine what scanned, or null when nothing could
 * @property {"clean"|"threat"|"unavailable"|"error"} status
 * @property {string} detail
 */

const hresult = (hr) => `0x${(Number(hr) >>> 0).toString(16).toUpperCase().padStart(8, "0")}`;

/**
 * Builds the runner that scans one file with this machine's antivirus.
 * `env` and `spawn` are injectable for tests.
 *
 * @param {{ env?: Record<string, string|undefined>, spawn?: typeof spawnSync }} [options]
 * @returns {(filePath: string, timeoutMs: number, contentName: string) => AntivirusResult}
 */
export function systemAntivirus({ env = process.env, spawn = spawnSync } = {}) {
  const systemRoot = env.SystemRoot || DEFAULT_SYSTEM_ROOT;
  return (filePath, timeoutMs, contentName) => {
    const deadline = Date.now() + timeoutMs;
    const left = () => Math.max(1, deadline - Date.now());
    if (defenderRunning(systemRoot, spawn, Math.min(SERVICE_TIMEOUT_MS, left()))) {
      return { engine: DEFENDER_ENGINE, ...scanWithDefender(env, spawn, filePath, left()) };
    }
    const amsi = scanWithAmsi(env, systemRoot, spawn, filePath, contentName, left());
    if (amsi.engine === null) {
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

function scanWithAmsi(env, systemRoot, spawn, filePath, contentName, timeoutMs) {
  const exe = path.win32.join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const temp = env.TEMP || env.TMP || os.tmpdir();
  const run = spawn(exe, ["-NoProfile", "-NonInteractive", "-NoLogo", "-EncodedCommand", AMSI_COMMAND], {
    ...SPAWN,
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

  const engine = `AMSI provider ${out.providers.join(", ")}`;
  if (out.error) return { engine, status: "error", detail: String(out.error) };
  if (out.init !== 0) return { engine, status: "error", detail: `AmsiInitialize failed (${hresult(out.init)})` };
  if (out.selftestHr !== 0) return { engine, status: "error", detail: `the provider's self-test call failed (${hresult(out.selftestHr)})` };
  if (!Number.isInteger(out.selftest) || out.selftest < AMSI_DETECTED) {
    return { engine: null, status: "unavailable", detail: `the ${engine} did not flag the antivirus test string, so it is not scanning files` };
  }
  if (out.hr !== 0) return { engine, status: "error", detail: `AmsiScanBuffer failed (${hresult(out.hr)})` };
  const result = out.result;
  if (!Number.isInteger(result)) return { engine, status: "error", detail: "the scan gave no AMSI result" };
  if (result >= AMSI_DETECTED) return { status: "threat", engine, detail: `flagged as malware (AMSI result ${result})` };
  if (result === AMSI_CLEAN || result === AMSI_NOT_DETECTED) return { engine, status: "clean", detail: "no threat found" };
  if (result >= AMSI_BLOCKED_BY_ADMIN_START && result <= AMSI_BLOCKED_BY_ADMIN_END) {
    return { engine, status: "error", detail: `blocked by an administrator policy (AMSI result ${result})` };
  }
  return { engine, status: "error", detail: `AMSI result ${result}, which Guardian does not know` };
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
export function checkAntivirus(ctx, filePath, node) {
  const timeoutMs = ctx.budget.remainingMs();
  if (timeoutMs <= 0) {
    ctx.report("antivirus", "hold", "antivirus-error", "no time was left for the antivirus scan; the file was not scanned", node);
    return;
  }
  const run = ctx.options.antivirus ?? systemAntivirus();
  const result = run(path.resolve(filePath), timeoutMs, path.basename(filePath));
  const engine = typeof result?.engine === "string" && result.engine ? result.engine : null;
  const by = engine ?? "the antivirus";
  switch (result?.status) {
    case "clean":
      ctx.antivirusEngine = engine;
      return;
    case "threat":
      ctx.antivirusEngine = engine;
      ctx.report("antivirus", "block", "antivirus-threat", `${by} found ${clip(result.detail)}`, node);
      return;
    case "unavailable":
      ctx.report("antivirus", "hold", "antivirus-unavailable", `no antivirus engine could scan the file: ${clip(result.detail)}`, node);
      return;
    case "error":
      ctx.antivirusEngine = engine;
      ctx.report("antivirus", "hold", "antivirus-error", `the scan by ${by} failed: ${clip(result.detail)}; the file was not scanned`, node);
      return;
    default:
      ctx.report("antivirus", "hold", "antivirus-error", "the antivirus scan gave no answer Guardian knows; the file was not scanned", node);
  }
}
