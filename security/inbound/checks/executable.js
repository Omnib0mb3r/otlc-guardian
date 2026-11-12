// ============================================================
// OTLC Guardian - inbound-file check 2: executables and scripts
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// A program or a script blocks, at the top level or inside any
// archive or document. Two ways in, both judged:
//
//   - the bytes are a program format (PE, ELF, Mach-O, MSI, LNK,
//     a Java class or archive, an Android or Windows app package,
//     WebAssembly, compiled help, a #! script);
//   - the name (on disk or as sent) ends in an extension Windows or
//     a shell runs as a program or script, whatever the bytes are:
//     a .ps1 or .js is text, and it still runs on a double-click.
//
// Not run on a mail body (contract v1): a body is never executed.
// ============================================================

import { FAMILY, extOf } from "./type.js";

/** Extensions that run as a program or script when opened. */
export const EXECUTABLE_EXTENSIONS = new Set([
  // Windows programs, installers, shortcuts and system files
  "exe", "dll", "scr", "com", "pif", "cpl", "ocx", "sys", "drv", "msi", "msp", "mst",
  "lnk", "url", "scf", "settingcontent-ms", "appref-ms", "application", "xbap", "gadget",
  "appx", "appxbundle", "msix", "msixbundle", "msc", "chm", "reg",
  // Scripts run by Windows Script Host, PowerShell and the command shell
  "bat", "cmd", "ps1", "psm1", "psd1", "ps1xml", "psc1", "vbs", "vbe", "js", "jse",
  "wsf", "wsh", "wsc", "hta", "sct",
  // Java, Android and Unix shells
  "jar", "class", "apk", "dex", "sh", "bash", "zsh", "csh", "ksh", "command",
]);

const DESCRIPTION = {
  pe: "a Windows program (PE)",
  "dos-exe": "a DOS program (MZ)",
  elf: "a Linux program (ELF)",
  macho: "a macOS program (Mach-O)",
  "java-class": "a Java class",
  lnk: "a Windows shortcut (LNK)",
  "shebang-script": "a script (#! line)",
  wasm: "a WebAssembly module",
  dex: "Android bytecode (dex)",
  chm: "compiled HTML help (runs script)",
  msi: "a Windows installer (MSI)",
  jar: "a Java archive (jar)",
  apk: "an Android app (apk)",
  appx: "a Windows app package (appx/msix)",
};

/**
 * Check 2.
 * @param {import("../index.js").Inspection} ctx
 * @param {import("../index.js").Node} node
 */
export function checkExecutable(ctx, node) {
  if (FAMILY[node.type] === "executable") {
    ctx.report("executable", "block", "executable",
      `${node.part || node.name} is ${DESCRIPTION[node.type] ?? node.type} (${node.type})`, node);
  }
  const names = [{ name: node.name, label: "name" }];
  if (node.top && ctx.meta.original_name) names.push({ name: ctx.meta.original_name, label: "original name" });
  for (const { name, label } of names) {
    const ext = extOf(name);
    if (EXECUTABLE_EXTENSIONS.has(ext)) {
      ctx.report("executable", "block", "executable-name", `${label} ends in .${ext}, which runs as a program or script`, node);
    }
  }
}
