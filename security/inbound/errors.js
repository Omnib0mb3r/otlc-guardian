// ============================================================
// OTLC Guardian - inbound-file check: error types
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================

/** The caller asked for something the check cannot do (no file, bad meta). Exit 2. */
export class UsageError extends Error {
  constructor(message) {
    super(message);
    this.name = "UsageError";
  }
}

/**
 * The bytes do not follow their format (a truncated zip, a compound
 * file whose sector chain loops). The check that met it holds the
 * file: a file that cannot be read cannot be judged.
 */
export class FormatError extends Error {
  constructor(message) {
    super(message);
    this.name = "FormatError";
  }
}
