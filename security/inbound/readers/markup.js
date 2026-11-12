// ============================================================
// OTLC Guardian - inbound-file check: markup helpers
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================

const XML_NAMED = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };

/**
 * Decodes the five XML entities and numeric character references.
 * Other named entities are left as written.
 * @param {string} text
 * @returns {string}
 */
export function decodeXmlEntities(text) {
  return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (whole, ref) => {
    if (ref[0] === "#") {
      const code = ref[1] === "x" || ref[1] === "X" ? parseInt(ref.slice(2), 16) : parseInt(ref.slice(1), 10);
      return Number.isInteger(code) && code >= 0 && code <= 0x10FFFF ? String.fromCodePoint(code) : whole;
    }
    return XML_NAMED[ref.toLowerCase()] ?? whole;
  });
}
