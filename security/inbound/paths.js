// ============================================================
// OTLC Guardian - inbound-file check: inner paths
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// An archive entry's inner path is its name in the archive. Entries
// of a nested archive are joined to their container's path with
// "!/" (the jar URL convention), so "plc.zip!/main.L5K" is main.L5K
// inside plc.zip inside the checked file. A name with "/" in it is a
// folder inside one archive; "!/" always marks a new archive level.
// ============================================================

/**
 * @param {{ path?: string }} parent
 * @param {string} name entry name inside the parent archive
 * @returns {string}
 */
export function innerPath(parent, name) {
  return parent.path === undefined ? name : `${parent.path}!/${name}`;
}

/**
 * Why an entry name could write outside the folder it is extracted
 * to, or null. Both separators count: Windows extractors honour "\".
 *
 * @param {string} name
 * @returns {string|null}
 */
export function pathProblem(name) {
  if (name.includes("\0")) return "holds a NUL character";
  const n = name.replace(/\\/g, "/");
  if (n.startsWith("/")) return "is an absolute path";
  if (/^[A-Za-z]:/.test(n)) return "starts with a drive letter";
  if (n.split("/").includes("..")) return "climbs out of its folder (..)";
  if (n.includes(":")) return "holds a colon (an alternate data stream or a device name)";
  return null;
}
