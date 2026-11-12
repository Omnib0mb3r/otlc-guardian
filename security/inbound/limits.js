// ============================================================
// OTLC Guardian - inbound-file check: limits
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// One Budget per checked file. Every reader asks it before it
// does work that grows with the input, so a hostile file can cost
// at most the limits below. All reading happens in memory; the
// budget is what keeps that safe.
//
// Contract v1 (DevNeural docs/spec/LEX-MAILBOX.md section 6):
// 60 s per file, 200 MB input, 1 GB uncompressed across an
// archive tree, depth 3. Two guards are Guardian's own: an entry
// count and the size below which the ratio rule does not apply.
// ============================================================

import zlib from "zlib";
import { constants as bufferConstants } from "buffer";

export const DEFAULT_LIMITS = Object.freeze({
  timeMs:            60_000,
  inputBytes:        200 * 1024 * 1024,
  totalUncompressed: 1024 * 1024 * 1024,
  depth:             3,
  // An archive tree with more entries than this is not walked to the end.
  entries:           10_000,
  // An entry that expands more than `ratio` times its stored size is a
  // bomb, once it is at least `ratioFloor` bytes. Below the floor a
  // ratio says nothing: 2 KB of spaces stores in 20 bytes.
  ratio:             100,
  ratioFloor:        1024 * 1024,
});

/**
 * A limit was reached. `severity` is the verdict it forces: a time,
 * size, depth or entry limit holds; an uncompressed total over the
 * limit is a decompression bomb and blocks (plan check 5).
 */
export class LimitError extends Error {
  constructor(code, detail, severity = "hold") {
    super(detail);
    this.name = "LimitError";
    this.code = code;
    this.severity = severity;
  }
}

export class Budget {
  /**
   * @param {Partial<typeof DEFAULT_LIMITS>} [limits]
   * @param {() => number} [now] clock, injectable for tests
   */
  constructor(limits = {}, now = Date.now) {
    this.limits = { ...DEFAULT_LIMITS, ...limits };
    this.now = now;
    this.deadline = now() + this.limits.timeMs;
    this.uncompressed = 0;
    this.entries = 0;
  }

  /** Throws when the time limit has passed. Readers call it in their loops. */
  tick() {
    if (this.now() > this.deadline) {
      throw new LimitError("limit-time", `check stopped at the ${this.limits.timeMs / 1000} s limit`);
    }
  }

  remainingMs() {
    return Math.max(0, this.deadline - this.now());
  }

  remainingBytes() {
    return Math.max(0, this.limits.totalUncompressed - this.uncompressed);
  }

  /** Counts bytes produced by decompression against the 1 GB total. */
  spend(bytes) {
    this.uncompressed += bytes;
    if (this.uncompressed > this.limits.totalUncompressed) throw this.bombTotal();
  }

  /** Counts one archive entry against the entry limit. */
  countEntry() {
    if (++this.entries > this.limits.entries) {
      throw new LimitError("limit-entries", `more than ${this.limits.entries} archive entries`);
    }
  }

  bombTotal() {
    return new LimitError(
      "archive-bomb-total",
      `more than ${this.limits.totalUncompressed} bytes uncompressed across the file`,
      "block",
    );
  }
}

const INFLATERS = {
  raw:  zlib.inflateRawSync,
  zlib: zlib.inflateSync,
  gzip: zlib.gunzipSync,
};

/**
 * Decompresses in memory without ever producing more than the budget
 * allows. zlib stops at `maxOutputLength` and throws, so a bomb never
 * reaches its full size. `tolerant` accepts a stream cut short (PDF
 * writers often leave the zlib checksum off).
 *
 * @param {"raw"|"zlib"|"gzip"} kind
 * @param {Buffer} data
 * @param {Budget} budget
 * @param {{ tolerant?: boolean }} [options]
 * @returns {Buffer}
 */
export function inflateLimited(kind, data, budget, { tolerant = false } = {}) {
  budget.tick();
  const room = budget.remainingBytes();
  if (room === 0) throw budget.bombTotal();
  const maxOutputLength = Math.min(room + 1, bufferConstants.MAX_LENGTH);
  const options = { maxOutputLength };
  if (tolerant) options.finishFlush = zlib.constants.Z_SYNC_FLUSH;
  let out;
  try {
    out = INFLATERS[kind](data, options);
  } catch (error) {
    if (error?.code === "ERR_BUFFER_TOO_LARGE" || error instanceof RangeError) throw budget.bombTotal();
    throw error;
  }
  budget.spend(out.length);
  return out;
}
