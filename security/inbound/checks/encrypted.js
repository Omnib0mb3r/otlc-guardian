// ============================================================
// OTLC Guardian - inbound-file check 6: encryption
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// Content Guardian cannot read without a password holds. It is never
// guessed at and no password is ever tried: an encrypted archive can
// carry anything, and what is not read is not judged.
//
// The readers record what they found locked on the node they read:
//   - node.encryptedEntries: zip entries with the encryption flag
//     (bit 0), strong encryption (bit 6) or WinZip AES (method 99);
//   - node.encryptedParts: { what } for a whole document or part
//     that is encrypted (an Office file, a PDF), added by those readers.
// ============================================================

const LISTED = 5;

/**
 * Check 6.
 * @param {import("../index.js").Inspection} ctx
 * @param {import("../index.js").Node} node
 */
export function checkEncrypted(ctx, node) {
  const entries = node.encryptedEntries ?? [];
  if (entries.length > 0) {
    const kinds = new Set(entries.map((e) => (e.method === 99 ? "AES" : e.flags & 0x0040 ? "strong encryption" : "ZipCrypto")));
    const names = entries.slice(0, LISTED).map((e) => `"${e.name}"`).join(", ");
    const more = entries.length > LISTED ? ` and ${entries.length - LISTED} more` : "";
    ctx.report("encrypted", "hold", "encrypted",
      `${entries.length} encrypted entr${entries.length === 1 ? "y" : "ies"} (${[...kinds].join(", ")}): ${names}${more}; not read`, node);
  }
  for (const { what } of node.encryptedParts ?? []) {
    ctx.report("encrypted", "hold", "encrypted", `${what} is encrypted; its content was not read`, node);
  }
}
