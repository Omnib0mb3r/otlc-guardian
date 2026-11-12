// ============================================================
// OTLC Guardian - inbound-file check: markup reader
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// Pulls the text out of XML, HTML and SVG for the prompt-injection
// check, the way a reader (human or AI) would meet it, and finds the
// active content an HTML or SVG file carries.
//
// XML: text nodes, CDATA, comments and attribute values. Tag names
// are not text, so <User> cannot read as a chat delimiter.
//
// HTML and SVG: visible text; hidden text (comments, display:none,
// visibility:hidden, opacity:0, font-size:0, mso-hide:all, the
// hidden attribute, text the same colour as its background); and
// the alt, title, aria-label and placeholder attributes. Inline tags
// (<b>, <span>, <a>) do not break a sentence; block tags do.
// Active content: <script>, event handlers, <form>, <iframe>,
// <frame>, <object>, <embed>, <applet>, and javascript:, vbscript:
// or data: URLs, also in a style url() or a meta refresh.
//
// Both tokenizers walk the text once with indexOf and sticky
// matches, so the cost is linear in the input.
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
    if (ref[0] === "#") return numericEntity(ref) ?? whole;
    return XML_NAMED[ref.toLowerCase()] ?? whole;
  });
}

function numericEntity(ref) {
  const code = ref[1] === "x" || ref[1] === "X" ? parseInt(ref.slice(2), 16) : parseInt(ref.slice(1), 10);
  return Number.isInteger(code) && code >= 0 && code <= 0x10FFFF ? String.fromCodePoint(code) : null;
}

// The named entities mail and web pages use. One that is not listed
// stays as written, which a reader would also show.
const HTML_NAMED = {
  ...XML_NAMED,
  nbsp: "\u00A0", zwnj: "\u200C", zwj: "\u200D", shy: "\u00AD", lrm: "\u200E", rlm: "\u200F",
  ensp: "\u2002", emsp: "\u2003", thinsp: "\u2009", copy: "\u00A9", reg: "\u00AE", trade: "\u2122",
  hellip: "\u2026", ndash: "\u2013", mdash: "\u2014", lsquo: "\u2018", rsquo: "\u2019",
  ldquo: "\u201C", rdquo: "\u201D", bull: "\u2022", middot: "\u00B7", laquo: "\u00AB",
  raquo: "\u00BB", euro: "\u20AC", pound: "\u00A3", deg: "\u00B0", times: "\u00D7",
};

/** @param {string} text */
export function decodeHtmlEntities(text) {
  return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z][a-z0-9]*);/gi, (whole, ref) => {
    if (ref[0] === "#") return numericEntity(ref) ?? whole;
    return HTML_NAMED[ref] ?? HTML_NAMED[ref.toLowerCase()] ?? whole;
  });
}

// ---------------------------------------------------------------------------
// TAGS
// ---------------------------------------------------------------------------

const NAME = /[A-Za-z_:][\w:.-]*/y;
const ATTR_NAME = /[^\s"'>/=]+/y;
const SPACE = /[\s/]*/y;

/**
 * Reads the tag that starts at `start` (just past "<" or "</").
 * @returns {{ name: string, attrs: Array<[string, string]>, end: number, selfClosing: boolean } | null}
 */
function readTag(src, start, decode) {
  NAME.lastIndex = start;
  const m = NAME.exec(src);
  if (!m) return null;
  const attrs = [];
  let p = NAME.lastIndex;
  for (;;) {
    SPACE.lastIndex = p;
    SPACE.exec(src);
    p = SPACE.lastIndex;
    if (p >= src.length) return { name: m[0], attrs, end: src.length, selfClosing: false };
    if (src[p] === ">") return { name: m[0], attrs, end: p + 1, selfClosing: src[p - 1] === "/" };
    ATTR_NAME.lastIndex = p;
    const an = ATTR_NAME.exec(src);
    if (!an) { p++; continue; }
    p = ATTR_NAME.lastIndex;
    while (p < src.length && /\s/.test(src[p])) p++;
    let value = "";
    if (src[p] === "=") {
      p++;
      while (p < src.length && /\s/.test(src[p])) p++;
      const q = src[p];
      if (q === '"' || q === "'") {
        const close = src.indexOf(q, p + 1);
        const stop = close < 0 ? src.length : close;
        value = src.slice(p + 1, stop);
        p = stop + 1;
      } else {
        const s = p;
        while (p < src.length && !/[\s>]/.test(src[p])) p++;
        value = src.slice(s, p);
      }
    }
    attrs.push([an[0], decode(value)]);
  }
}

const localName = (name) => name.slice(name.lastIndexOf(":") + 1).toLowerCase();

// ---------------------------------------------------------------------------
// XML
// ---------------------------------------------------------------------------

/**
 * The text of an XML document.
 *
 * @param {string} src
 * @param {object} [options]
 * @param {Set<string>} [options.blocks] local names whose tags end a
 *   line. Given for Office parts, where a word is split across runs
 *   (<w:t>ign</w:t><w:t>ore</w:t>) and only paragraphs, cells and the
 *   like separate words. Without it every tag separates.
 * @param {Set<string>|"all"} [options.attributes] attribute local names
 *   whose values are read; "all" (the default) reads every value.
 * @param {() => void} [options.tick] called as the walk goes, for the time limit
 * @returns {{ text: string, attributes: string, comments: string }}
 */
export function xmlText(src, { blocks, attributes = "all", tick = () => {} } = {}) {
  let text = "";
  const attrs = [];
  const comments = [];
  let p = 0;
  let steps = 0;
  const boundary = (name) => {
    if (!blocks || blocks.has(localName(name))) text += "\n";
  };
  while (p < src.length) {
    if ((++steps & 0x3FF) === 0) tick();
    const lt = src.indexOf("<", p);
    if (lt < 0) { text += decodeXmlEntities(src.slice(p)); break; }
    if (lt > p) text += decodeXmlEntities(src.slice(p, lt));
    if (src.startsWith("<!--", lt)) {
      const end = src.indexOf("-->", lt + 4);
      comments.push(src.slice(lt + 4, end < 0 ? src.length : end));
      p = end < 0 ? src.length : end + 3;
    } else if (src.startsWith("<![CDATA[", lt)) {
      const end = src.indexOf("]]>", lt + 9);
      text += src.slice(lt + 9, end < 0 ? src.length : end);
      p = end < 0 ? src.length : end + 3;
    } else if (src[lt + 1] === "?" || src[lt + 1] === "!") {
      const end = src.indexOf(">", lt + 2);
      p = end < 0 ? src.length : end + 1;
    } else {
      const closing = src[lt + 1] === "/";
      const tag = readTag(src, lt + (closing ? 2 : 1), decodeXmlEntities);
      if (!tag) { text += "<"; p = lt + 1; continue; }
      boundary(tag.name);
      for (const [name, value] of tag.attrs) {
        if (/^xmlns(?::|$)/i.test(name)) continue;
        if (attributes === "all" || attributes.has(localName(name))) attrs.push(value);
      }
      p = tag.end;
    }
  }
  return { text, attributes: attrs.join("\n"), comments: comments.join("\n") };
}

// ---------------------------------------------------------------------------
// HTML AND SVG
// ---------------------------------------------------------------------------

const VOID = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"]);
// Content up to the matching end tag is not markup.
const RAW = new Set(["script", "style", "textarea", "title", "xmp", "noembed", "noframes"]);
// Text elements whose raw content is still text a reader sees.
const RAW_TEXT = new Set(["textarea", "title", "xmp"]);
// Tags that sit inside a sentence. Every other tag separates words.
const INLINE = new Set([
  "a", "abbr", "b", "bdi", "bdo", "big", "cite", "code", "data", "dfn", "em", "font", "i", "kbd",
  "label", "mark", "q", "s", "samp", "small", "span", "strike", "strong", "sub", "sup", "time",
  "tt", "u", "var", "wbr", "ins", "del", "nobr", "tspan",
]);
const ACTIVE_ELEMENTS = new Map([
  ["script", "a <script> element"], ["form", "a <form>"], ["iframe", "an <iframe>"], ["frame", "a <frame>"],
  ["frameset", "a <frameset>"], ["object", "an <object>"], ["embed", "an <embed>"], ["applet", "an <applet>"],
]);
const TEXT_ATTRIBUTES = new Set(["alt", "title", "aria-label", "aria-description", "placeholder"]);
const URL_ATTRIBUTES = new Set([
  "href", "src", "action", "formaction", "data", "background", "poster", "lowsrc", "dynsrc",
  "cite", "longdesc", "codebase", "xlink:href", "srcset",
]);
// SVG animation can set an href to a script URL.
const ANIMATION_VALUES = new Set(["values", "to", "from", "by"]);
const DANGEROUS_SCHEME = /^(javascript|vbscript|data):/;

/** A URL as a browser reads its scheme: whitespace and control characters inside it are dropped. */
function schemeOf(url) {
  // eslint-disable-next-line no-control-regex -- browsers strip these from a URL scheme
  const m = DANGEROUS_SCHEME.exec(url.replace(/[\x00-\x20\x7F-\x9F]/g, "").toLowerCase());
  return m ? m[1] : null;
}

function styleDeclarations(style) {
  const out = {};
  for (const decl of style.split(";")) {
    const colon = decl.indexOf(":");
    if (colon < 0) continue;
    out[decl.slice(0, colon).trim().toLowerCase()] = decl.slice(colon + 1).trim().toLowerCase();
  }
  return out;
}

const NAMED_COLOURS = { white: "#ffffff", black: "#000000", red: "#ff0000", transparent: null };

function colour(value) {
  if (!value) return null;
  const v = value.replace(/!important/g, "").trim().toLowerCase();
  if (v in NAMED_COLOURS) return NAMED_COLOURS[v];
  let m = /^#([0-9a-f]{3})$/.exec(v);
  if (m) return `#${[...m[1]].map((c) => c + c).join("")}`;
  m = /^#([0-9a-f]{6})$/.exec(v);
  if (m) return `#${m[1]}`;
  m = /^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/.exec(v);
  if (m) return `#${[m[1], m[2], m[3]].map((n) => Math.min(255, Number(n)).toString(16).padStart(2, "0")).join("")}`;
  return null;
}

/** The first colour in a `background` shorthand. */
function backgroundColour(value) {
  if (!value) return null;
  for (const token of value.split(/\s+(?![^(]*\))/)) {
    const c = colour(token);
    if (c) return c;
  }
  return null;
}

const isZero = (v) => v !== undefined && /^0*\.?0*(?:px|pt|em|rem|%)?$/.test(v.replace(/!important/, "").trim());

/** Why an element's own attributes hide it, or null. */
function hiddenBy(attrs, decl) {
  if (attrs.has("hidden")) return "the hidden attribute";
  if (decl.display?.startsWith("none")) return "display:none";
  if (decl.visibility?.startsWith("hidden") || decl.visibility?.startsWith("collapse")) return "visibility:hidden";
  if (isZero(decl.opacity)) return "opacity:0";
  if (isZero(decl["font-size"])) return "font-size:0";
  if (decl["mso-hide"]?.startsWith("all")) return "mso-hide:all";
  if ((isZero(decl["max-height"]) || isZero(decl.height)) && decl.overflow?.startsWith("hidden")) return "zero height";
  return null;
}

/**
 * Reads an HTML or SVG document.
 *
 * @param {string} src
 * @param {{ tick?: () => void }} [options]
 * @returns {{ visible: string, hidden: string, comments: string, attributes: string, active: string[] }}
 */
export function readMarkup(src, { tick = () => {} } = {}) {
  let visible = "";
  let hidden = "";
  const comments = [];
  const attributes = [];
  const active = new Set();
  /** @type {Array<{ name: string, hidden: boolean, color: string|null, bg: string|null }>} */
  const stack = [];
  const top = () => stack[stack.length - 1];

  const addText = (t) => {
    const el = top();
    const isHidden = el?.hidden || (el?.color && el.color === el.bg);
    if (isHidden) hidden += t;
    else visible += t;
  };
  const separate = () => { visible += "\n"; hidden += "\n"; };

  const scanStyle = (css) => {
    // A quoted URL may hold ")": url('javascript:alert(1)').
    for (const m of css.matchAll(/url\(\s*(?:'([^']*)'|"([^"]*)"|([^)]*))/gi)) {
      const scheme = schemeOf(decodeHtmlEntities(m[1] ?? m[2] ?? m[3]));
      if (scheme) active.add(`a ${scheme}: URL in a style`);
    }
    if (/expression\s*\(/i.test(css)) active.add("a CSS expression()");
  };

  const openTag = (tag) => {
    const name = tag.name.toLowerCase();
    const local = localName(name);
    const attrs = new Map(tag.attrs.map(([k, v]) => [k.toLowerCase(), v]));
    if (ACTIVE_ELEMENTS.has(local)) active.add(ACTIVE_ELEMENTS.get(local));
    for (const [key, value] of attrs) {
      if (/^on[a-z]+$/.test(key)) active.add(`an event handler (${key} on <${local}>)`);
      else if (URL_ATTRIBUTES.has(key) || (ANIMATION_VALUES.has(key) && /^(?:set|animate)/.test(local))) {
        const scheme = schemeOf(value);
        if (scheme) active.add(`a ${scheme}: URL (${key} on <${local}>)`);
      } else if (TEXT_ATTRIBUTES.has(key) && value.trim()) attributes.push(value);
    }
    if (local === "meta" && /refresh/i.test(attrs.get("http-equiv") ?? "")) {
      const url = /url\s*=\s*['"]?(.*)$/i.exec(attrs.get("content") ?? "")?.[1] ?? "";
      const scheme = schemeOf(url);
      if (scheme) active.add(`a ${scheme}: URL in a meta refresh`);
    }
    if (attrs.has("style")) scanStyle(attrs.get("style"));

    if (!INLINE.has(local)) separate();
    if (VOID.has(local) || tag.selfClosing) return;
    const decl = styleDeclarations(attrs.get("style") ?? "");
    const parent = top();
    const color = colour(decl.color) ?? colour(attrs.get("color")) ?? parent?.color ?? null;
    const bg = colour(decl["background-color"]) ?? backgroundColour(decl.background) ??
      colour(attrs.get("bgcolor")) ?? parent?.bg ?? null;
    stack.push({ name: local, hidden: Boolean(parent?.hidden || hiddenBy(attrs, decl)), color, bg });
  };

  const closeTag = (name) => {
    const local = localName(name.toLowerCase());
    if (!INLINE.has(local)) separate();
    for (let i = stack.length - 1; i >= 0; i--) {
      if (stack[i].name === local) {
        stack.length = i;
        return;
      }
    }
  };

  let p = 0;
  let steps = 0;
  while (p < src.length) {
    if ((++steps & 0x3FF) === 0) tick();
    const lt = src.indexOf("<", p);
    if (lt < 0) { addText(decodeHtmlEntities(src.slice(p))); break; }
    if (lt > p) addText(decodeHtmlEntities(src.slice(p, lt)));
    if (src.startsWith("<!--", lt)) {
      const end = src.indexOf("-->", lt + 4);
      // Conditional comments hold markup for Outlook; their tags are not text.
      comments.push(decodeHtmlEntities(src.slice(lt + 4, end < 0 ? src.length : end).replace(/<[^<>]*>/g, " ")));
      p = end < 0 ? src.length : end + 3;
      continue;
    }
    if (src.startsWith("<![CDATA[", lt)) {
      const end = src.indexOf("]]>", lt + 9);
      addText(src.slice(lt + 9, end < 0 ? src.length : end));
      p = end < 0 ? src.length : end + 3;
      continue;
    }
    if (src[lt + 1] === "!" || src[lt + 1] === "?") {
      const end = src.indexOf(">", lt + 2);
      p = end < 0 ? src.length : end + 1;
      continue;
    }
    const closing = src[lt + 1] === "/";
    const tag = readTag(src, lt + (closing ? 2 : 1), decodeHtmlEntities);
    if (!tag) { addText("<"); p = lt + 1; continue; }
    p = tag.end;
    if (closing) { closeTag(tag.name); continue; }
    openTag(tag);
    const local = localName(tag.name);
    if (RAW.has(local) && !tag.selfClosing) {
      const endRe = new RegExp(`</${local}(?=[\\s>/])`, "gi");
      endRe.lastIndex = p;
      const m = endRe.exec(src);
      const body = src.slice(p, m ? m.index : src.length);
      if (RAW_TEXT.has(local)) addText(decodeHtmlEntities(body));
      else if (local === "style") scanStyle(body);
      if (!m) break;
      const gt = src.indexOf(">", m.index);
      p = gt < 0 ? src.length : gt + 1;
      closeTag(local);
    }
  }
  return { visible, hidden, comments: comments.join("\n"), attributes: attributes.join("\n"), active: [...active] };
}
