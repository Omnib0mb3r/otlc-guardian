/**
 * ============================================================
 * OTLC GUARDIAN - inbound-check test fixtures
 * // tests · onthelevelconcepts.com
 * Version: 1.5.0
 * ============================================================
 *
 * Builders for the files tests/inbound.test.js judges. Every file
 * here is Guardian-made, written byte by byte from the format
 * specifications: no customer, employer or third-party file is in
 * this repository (it is public). Hostile samples are inert: a
 * macro project with no code, a PDF script that only calls
 * app.alert, an executable header with no program behind it.
 *
 * Built in memory. The test writes them to an OS temp folder only.
 * ============================================================
 */

import zlib from "zlib";

const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const u32be = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };

// ---------------------------------------------------------------------------
// EXECUTABLES (headers only, no program)
// ---------------------------------------------------------------------------

/** An MZ header whose e_lfanew points at a PE signature. Not runnable. */
export function pe() {
  const b = Buffer.alloc(0x80);
  b.write("MZ", 0, "latin1");
  b.writeUInt32LE(0x40, 0x3C);
  b.write("PE\0\0", 0x40, "latin1");
  return b;
}

export const elf = () => Buffer.concat([Buffer.from([0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0]), Buffer.alloc(56)]);
export const lnk = () => Buffer.concat([Buffer.from([0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0x00]), Buffer.alloc(68)]);
export const javaClass = () => Buffer.from([0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x41, 0, 0]);

// ---------------------------------------------------------------------------
// IMAGES
// ---------------------------------------------------------------------------

function pngChunk(type, data) {
  const head = Buffer.from(type, "latin1");
  return Buffer.concat([u32be(data.length), head, data, u32be(zlib.crc32(Buffer.concat([head, data])))]);
}

/**
 * A 1x1 grey PNG. `text` adds tEXt chunks ({ keyword: value }),
 * `ztext` adds compressed zTXt chunks, `itext` compressed iTXt chunks.
 */
export function png({ text = {}, ztext = {}, itext = {} } = {}) {
  const ihdr = Buffer.concat([u32be(1), u32be(1), Buffer.from([8, 0, 0, 0, 0])]);
  const idat = zlib.deflateSync(Buffer.from([0, 0x80]));
  const chunks = [pngChunk("IHDR", ihdr)];
  for (const [k, v] of Object.entries(text)) chunks.push(pngChunk("tEXt", Buffer.from(`${k}\0${v}`, "latin1")));
  for (const [k, v] of Object.entries(ztext)) {
    chunks.push(pngChunk("zTXt", Buffer.concat([Buffer.from(`${k}\0\0`, "latin1"), zlib.deflateSync(Buffer.from(v, "latin1"))])));
  }
  for (const [k, v] of Object.entries(itext)) {
    // keyword, compressed (1), deflate (0), language tag, translated keyword, UTF-8 text
    chunks.push(pngChunk("iTXt", Buffer.concat([Buffer.from(`${k}\0\x01\0en\0\0`, "latin1"), zlib.deflateSync(Buffer.from(v, "utf8"))])));
  }
  chunks.push(pngChunk("IDAT", idat), pngChunk("IEND", Buffer.alloc(0)));
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), ...chunks]);
}

function jpegSegment(marker, data) {
  const len = Buffer.alloc(2);
  len.writeUInt16BE(data.length + 2);
  return Buffer.concat([Buffer.from([0xFF, marker]), len, data]);
}

/**
 * JPEG segment structure (SOI, optional COM, EXIF and XMP, SOS, EOI).
 * The scan data is a stub: enough for a reader of the format, not a
 * picture. tests/fixtures/inbound/clean.jpg is a real one.
 */
export function jpeg({ comment, exifText, xmp } = {}) {
  const parts = [Buffer.from([0xFF, 0xD8])];
  parts.push(jpegSegment(0xE0, Buffer.from("JFIF\0\x01\x01\0\0\x01\0\x01\0\0", "latin1")));
  if (comment) parts.push(jpegSegment(0xFE, Buffer.from(comment, "latin1")));
  if (exifText) {
    // A TIFF header with one ImageDescription (0x010E) ASCII entry.
    const text = Buffer.from(`${exifText}\0`, "latin1");
    const ifd = Buffer.concat([u16(1), u16(0x010E), u16(2), u32(text.length), u32(26), u32(0)]);
    const tiff = Buffer.concat([Buffer.from("II*\0", "latin1"), u32(8), ifd, text]);
    parts.push(jpegSegment(0xE1, Buffer.concat([Buffer.from("Exif\0\0", "latin1"), tiff])));
  }
  if (xmp) parts.push(jpegSegment(0xE1, Buffer.from(`http://ns.adobe.com/xap/1.0/\0${xmp}`, "utf8")));
  parts.push(jpegSegment(0xDA, Buffer.from([1, 1, 0, 0, 0x3F, 0])), Buffer.from([0x12, 0x34]), Buffer.from([0xFF, 0xD9]));
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// ARCHIVES
// ---------------------------------------------------------------------------

/**
 * A zip written to APPNOTE 6.3.10. Each entry: { name, data, method
 * (8 deflate, default; 0 stored; any other number is written as is),
 * symlink, encrypted (flag bit 0), aes (method 99 with its 0x9901
 * field), localName (a different name in the local header), crc
 * (overrides the real one) }.
 */
export function zip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const e of entries) {
    const data = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data ?? "", "utf8");
    const method = e.aes ? 99 : (e.method ?? 8);
    const stored = method === 8 ? zlib.deflateRawSync(data) : data;
    const flags = (e.encrypted ? 0x0001 : 0) | 0x0800;
    const crc = e.crc ?? zlib.crc32(data);
    const name = Buffer.from(e.name, "utf8");
    const localName = Buffer.from(e.localName ?? e.name, "utf8");
    const extra = e.aes ? Buffer.concat([u16(0x9901), u16(7), u16(2), Buffer.from("AE"), Buffer.from([3]), u16(8)]) : Buffer.alloc(0);
    const local = Buffer.concat([
      u32(0x04034b50), u16(20), u16(flags), u16(method), u16(0), u16(0x21),
      u32(crc), u32(stored.length), u32(data.length), u16(localName.length), u16(extra.length), localName, extra,
    ]);
    const madeBy = e.symlink ? (3 << 8) | 20 : 20;
    const attr = e.symlink ? (0o120777 << 16) >>> 0 : 0;
    centrals.push(Buffer.concat([
      u32(0x02014b50), u16(madeBy), u16(20), u16(flags), u16(method), u16(0), u16(0x21),
      u32(crc), u32(stored.length), u32(data.length), u16(name.length), u16(extra.length), u16(0),
      u16(0), u16(0), u32(attr), u32(offset), name, extra,
    ]));
    locals.push(local, stored);
    offset += local.length + stored.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.concat([
    u32(0x06054b50), u16(0), u16(0), u16(entries.length), u16(entries.length), u32(cd.length), u32(offset), u16(0),
  ]);
  return Buffer.concat([...locals, cd, eocd]);
}

/** A tar (ustar) of { name, data, type ("0" file, "2" symlink, "1" hardlink, "3" device), linkname }. */
export function tar(entries) {
  const blocks = [];
  for (const e of entries) {
    const data = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data ?? "", "utf8");
    const h = Buffer.alloc(512);
    h.write(e.name, 0, 100, "utf8");
    h.write("0000644\0", 100, "latin1");
    h.write("0000000\0", 108, "latin1");
    h.write("0000000\0", 116, "latin1");
    h.write(`${data.length.toString(8).padStart(11, "0")}\0`, 124, "latin1");
    h.write("00000000000\0", 136, "latin1");
    h.write("        ", 148, "latin1");
    h.write(e.type ?? "0", 156, "latin1");
    if (e.linkname) h.write(e.linkname, 157, 100, "utf8");
    h.write("ustar\0" + "00", 257, "latin1");
    let sum = 0;
    for (const b of h) sum += b;
    h.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "latin1");
    blocks.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

/** gzip with the member name stored in the header. */
export function gzip(data, name) {
  const body = zlib.gzipSync(Buffer.isBuffer(data) ? data : Buffer.from(data));
  if (!name) return body;
  // Rebuild the header with FNAME set: same deflate stream and trailer.
  const header = Buffer.from([0x1F, 0x8B, 8, 0x08, 0, 0, 0, 0, 0, 0xFF]);
  return Buffer.concat([header, Buffer.from(`${name}\0`, "latin1"), body.subarray(10)]);
}

// ---------------------------------------------------------------------------
// COMPOUND FILES ([MS-CFB] version 3)
// ---------------------------------------------------------------------------

const FREESECT = 0xFFFFFFFF;
const ENDOFCHAIN = 0xFFFFFFFE;
const FATSECT = 0xFFFFFFFD;
const NOSTREAM = 0xFFFFFFFF;

function guidBytes(text) {
  const h = text.replace(/-/g, "");
  const b = Buffer.from(h, "hex");
  // The first three groups are little-endian on disk.
  return Buffer.concat([Buffer.from(b.subarray(0, 4)).reverse(), Buffer.from(b.subarray(4, 6)).reverse(),
    Buffer.from(b.subarray(6, 8)).reverse(), b.subarray(8, 16)]);
}

/**
 * A version 3 compound file. `tree` is a list of nodes: a stream
 * { name, data } or a storage { name, children, clsid }. Streams under
 * 4096 bytes go in the mini stream, as Office writes them.
 */
export function cfb(tree, { clsid } = {}) {
  const dir = [{ name: "Root Entry", type: 5, clsid, children: tree }];
  const flatten = (nodes) => nodes.map((n) => {
    const index = dir.length;
    const entry = { name: n.name, type: n.children ? 1 : 2, clsid: n.clsid, data: n.data === undefined ? undefined : Buffer.isBuffer(n.data) ? n.data : Buffer.from(n.data, "latin1") };
    dir.push(entry);
    if (n.children) entry.childIdx = flatten(n.children);
    return index;
  });
  dir[0].childIdx = flatten(tree);
  for (const e of dir) {
    e.left = NOSTREAM; e.right = NOSTREAM; e.child = NOSTREAM;
    if (e.childIdx?.length) e.child = e.childIdx[0];
  }
  for (const e of dir) (e.childIdx ?? []).forEach((idx, k, all) => { dir[idx].right = all[k + 1] ?? NOSTREAM; });

  // Mini stream.
  const miniParts = [];
  const miniFat = [];
  for (const e of dir) {
    if (e.type !== 2 || e.data.length >= 4096) continue;
    const count = Math.ceil(e.data.length / 64);
    e.start = count ? miniFat.length : ENDOFCHAIN;
    for (let i = 0; i < count; i++) miniFat.push(i === count - 1 ? ENDOFCHAIN : miniFat.length + 1);
    miniParts.push(Buffer.concat([e.data, Buffer.alloc(count * 64 - e.data.length)]));
  }
  const miniStream = Buffer.concat(miniParts);

  // Regular sectors: mini stream container, big streams, mini FAT, directory, FAT.
  const sectors = [];
  const fat = [];
  const place = (data) => {
    const count = Math.ceil(data.length / 512);
    if (count === 0) return ENDOFCHAIN;
    const start = sectors.length;
    for (let i = 0; i < count; i++) {
      sectors.push(Buffer.concat([data.subarray(i * 512, i * 512 + 512), Buffer.alloc(Math.max(0, 512 - data.subarray(i * 512, i * 512 + 512).length))]));
      fat.push(i === count - 1 ? ENDOFCHAIN : start + i + 1);
    }
    return start;
  };
  dir[0].start = place(miniStream);
  dir[0].size = miniStream.length;
  for (const e of dir) {
    if (e.type === 2) {
      if (e.data.length >= 4096) e.start = place(e.data);
      e.size = e.data.length;
    } else if (e.type === 1) { e.start = 0; e.size = 0; }
  }
  const miniFatBuf = Buffer.concat(miniFat.map(u32));
  const miniFatStart = miniFat.length ? place(miniFatBuf) : ENDOFCHAIN;
  const dirBuf = Buffer.concat(dir.map((e) => {
    const b = Buffer.alloc(128);
    const name = Buffer.from(`${e.name}\0`, "utf16le");
    name.copy(b, 0, 0, Math.min(64, name.length));
    b.writeUInt16LE(Math.min(64, name.length), 64);
    b[66] = e.type;
    b[67] = 1;
    b.writeUInt32LE(e.left, 68); b.writeUInt32LE(e.right, 72); b.writeUInt32LE(e.child, 76);
    if (e.clsid) guidBytes(e.clsid).copy(b, 80);
    b.writeUInt32LE(e.start >>> 0, 116);
    b.writeUInt32LE(e.size ?? 0, 120);
    return b;
  }));
  const dirStart = place(dirBuf);
  let fatCount = 1;
  while (sectors.length + fatCount > fatCount * 128) fatCount++;
  const fatStart = sectors.length;
  for (let i = 0; i < fatCount; i++) fat.push(FATSECT);
  while (fat.length < fatCount * 128) fat.push(FREESECT);
  const fatBuf = Buffer.concat(fat.map(u32));
  for (let i = 0; i < fatCount; i++) sectors.push(fatBuf.subarray(i * 512, i * 512 + 512));

  const header = Buffer.alloc(512);
  Buffer.from([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]).copy(header, 0);
  header.writeUInt16LE(0x3E, 24); header.writeUInt16LE(3, 26); header.writeUInt16LE(0xFFFE, 28);
  header.writeUInt16LE(9, 30); header.writeUInt16LE(6, 32);
  header.writeUInt32LE(fatCount, 44); header.writeUInt32LE(dirStart, 48);
  header.writeUInt32LE(4096, 56); header.writeUInt32LE(miniFatStart >>> 0, 60);
  header.writeUInt32LE(Math.ceil(miniFatBuf.length / 512), 64);
  header.writeUInt32LE(ENDOFCHAIN, 68); header.writeUInt32LE(0, 72);
  for (let i = 0; i < 109; i++) header.writeUInt32LE(i < fatCount ? fatStart + i : FREESECT, 76 + i * 4);
  return Buffer.concat([header, ...sectors]);
}

/** A VBA project with the storages Office writes and no code in it. Inert. */
export const vbaProject = () => cfb([
  { name: "VBA", children: [{ name: "dir", data: Buffer.alloc(16) }, { name: "_VBA_PROJECT", data: Buffer.from([0xCC, 0x61, 0xFF, 0xFF, 0, 0, 0]) }] },
  { name: "PROJECT", data: "ID=\"{00000000-0000-0000-0000-000000000000}\"\r\nName=\"GuardianTest\"\r\n" },
]);

/** An OLE Package (Ole10Native) wrapping `data` as `fileName`. */
export function olePackage(fileName, data) {
  const temp = Buffer.from(`C:\\tmp\\${fileName}\0`, "latin1");
  const native = Buffer.concat([
    u16(2), Buffer.from(`${fileName}\0C:\\tmp\\${fileName}\0`, "latin1"), u32(0x00030000),
    u32(temp.length), temp, u32(data.length), data,
  ]);
  return cfb([{ name: "\u0001Ole10Native", data: Buffer.concat([u32(native.length), native]) }],
    { clsid: "0003000c-0000-0000-c000-000000000046" });
}

/** A BIFF8 Workbook stream: BOF, optional FILEPASS, one BOUNDSHEET per sheet, EOF. */
export function biffWorkbook({ sheets = [{ name: "Sheet1", type: 0 }], encrypted = false } = {}) {
  const rec = (type, data) => Buffer.concat([u16(type), u16(data.length), data]);
  const parts = [rec(0x0809, Buffer.from([0, 6, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))];
  if (encrypted) parts.push(rec(0x002F, Buffer.alloc(6)));
  for (const s of sheets) {
    const name = Buffer.from(s.name, "latin1");
    parts.push(rec(0x0085, Buffer.concat([u32(0), Buffer.from([0, s.type, name.length, 0]), name])));
  }
  parts.push(rec(0x000A, Buffer.alloc(0)));
  return Buffer.concat(parts);
}

/** A WordDocument stream whose FIB says Word, with the encrypted flag when asked. */
export function wordDocumentStream({ encrypted = false } = {}) {
  const b = Buffer.alloc(1024);
  b.writeUInt16LE(0xA5EC, 0);
  b.writeUInt16LE(0x00C1, 2);
  b.writeUInt16LE(encrypted ? 0x0100 : 0, 0x0A);
  b.write("Guardian test document text.", 0x200, "latin1");
  return b;
}

// ---------------------------------------------------------------------------
// OFFICE OPEN XML
// ---------------------------------------------------------------------------

const W_NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"';
const REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";

/**
 * A minimal .docx (or .docm with `vba`). `body` is WordprocessingML
 * inside <w:body>; `rels` adds relationships to document.xml.rels;
 * `settingsRels` to settings.xml.rels; `parts` adds raw parts.
 */
export function docx({ body = "<w:p><w:r><w:t>Line 3 transfer notes.</w:t></w:r></w:p>", rels = "", settingsRels = "", vba = false, parts = [] } = {}) {
  const entries = [
    { name: "[Content_Types].xml", data: '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
      '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
      '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>' },
    { name: "_rels/.rels", data: `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="${REL}/officeDocument" Target="word/document.xml"/></Relationships>` },
    { name: "word/document.xml", data: `<?xml version="1.0"?><w:document ${W_NS}><w:body>${body}</w:body></w:document>` },
    { name: "word/_rels/document.xml.rels", data: `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${rels}</Relationships>` },
  ];
  if (settingsRels) {
    entries.push({ name: "word/settings.xml", data: `<?xml version="1.0"?><w:settings ${W_NS}><w:attachedTemplate r:id="rId1"/></w:settings>` });
    entries.push({ name: "word/_rels/settings.xml.rels", data: `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${settingsRels}</Relationships>` });
  }
  if (vba) entries.push({ name: "word/vbaProject.bin", data: vbaProject() });
  return zip([...entries, ...parts]);
}

/** A minimal .xlsx; `parts` adds raw parts (macro sheets, external links). */
export function xlsx({ sheet = '<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Belt speed</t></is></c></row></sheetData>', vba = false, parts = [] } = {}) {
  const entries = [
    { name: "[Content_Types].xml", data: '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/></Types>' },
    { name: "_rels/.rels", data: `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="${REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>` },
    { name: "xl/workbook.xml", data: '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>' },
    { name: "xl/worksheets/sheet1.xml", data: `<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">${sheet}</worksheet>` },
  ];
  if (vba) entries.push({ name: "xl/vbaProject.bin", data: vbaProject() });
  return zip([...entries, ...parts]);
}

export const REL_TYPES = REL;

// ---------------------------------------------------------------------------
// PDF
// ---------------------------------------------------------------------------

/**
 * A PDF written by hand to ISO 32000. Each object is a string (its
 * body) or a stream { dict, data, flate }. Objects are numbered from 1
 * and an xref table is written. `trailer` adds trailer entries.
 */
export function pdf(objects, { trailer = "" } = {}) {
  const parts = [Buffer.from("%PDF-1.7\n%\xE2\xE3\xCF\xD3\n", "latin1")];
  const offsets = [];
  let length = parts[0].length;
  objects.forEach((o, i) => {
    let body;
    if (typeof o === "string") body = Buffer.from(o, "latin1");
    else {
      const data = o.flate ? zlib.deflateSync(Buffer.isBuffer(o.data) ? o.data : Buffer.from(o.data, "latin1")) : (Buffer.isBuffer(o.data) ? o.data : Buffer.from(o.data, "latin1"));
      const filter = o.flate ? " /Filter /FlateDecode" : "";
      body = Buffer.concat([Buffer.from(`<< ${o.dict} /Length ${data.length}${filter} >>\nstream\n`, "latin1"), data, Buffer.from("\nendstream", "latin1")]);
    }
    const obj = Buffer.concat([Buffer.from(`${i + 1} 0 obj\n`, "latin1"), body, Buffer.from("\nendobj\n", "latin1")]);
    offsets.push(length);
    parts.push(obj);
    length += obj.length;
  });
  const xref = `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.map((o) => `${String(o).padStart(10, "0")} 00000 n \n`).join("")}`;
  parts.push(Buffer.from(`${xref}trailer\n<< /Size ${objects.length + 1} /Root 1 0 R ${trailer}>>\nstartxref\n${length}\n%%EOF\n`, "latin1"));
  return Buffer.concat(parts);
}

/** Catalog, pages and one page whose content stream shows `text`. Objects 1 to 4. */
export function pdfPage(text = "Line 3 transfer notes", { catalogExtra = "" } = {}) {
  return [
    `<< /Type /Catalog /Pages 2 0 R ${catalogExtra}>>`,
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> >>",
    { dict: "", data: `BT /F1 12 Tf 72 720 Td (${text}) Tj ET`, flate: true },
  ];
}

/**
 * A page whose text is shown through a Type0 font with a ToUnicode
 * CMap: each character of `text` gets its own two-byte code, so the
 * content stream holds only hex codes and the words can be read only
 * through the CMap. `tj` shows them as a TJ array with a small
 * kerning number between the codes. Objects 1 to 6.
 */
export function pdfCmapPage(text, { tj = false } = {}) {
  const chars = [...new Set(text)];
  const code = (ch) => (chars.indexOf(ch) + 1).toString(16).padStart(4, "0");
  const hex = [...text].map(code);
  const show = tj ? `[${hex.map((h) => `<${h}>`).join(" -20 ")}] TJ` : `<${hex.join("")}> Tj`;
  const bfchar = chars.map((ch) => `<${code(ch)}> <${ch.charCodeAt(0).toString(16).padStart(4, "0")}>`).join("\n");
  const cmap = "/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n" +
    "1 begincodespacerange <0000> <FFFF> endcodespacerange\n" +
    `${chars.length} beginbfchar\n${bfchar}\nendbfchar\nendcmap CMapName currentdict /CMap defineresource pop end end`;
  return [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
    { dict: "", data: `BT /F1 12 Tf 72 720 Td ${show} ET`, flate: true },
    "<< /Type /Font /Subtype /Type0 /BaseFont /GuardianTest /Encoding /Identity-H /ToUnicode 6 0 R >>",
    { dict: "", data: cmap, flate: true },
  ];
}

/** An object stream holding [num, body] pairs, Flate-compressed. */
export function pdfObjectStream(pairs) {
  let offsets = "";
  let bodies = "";
  for (const [num, body] of pairs) {
    offsets += `${num} ${bodies.length} `;
    bodies += `${body}\n`;
  }
  return { dict: `/Type /ObjStm /N ${pairs.length} /First ${offsets.length}`, data: offsets + bodies, flate: true };
}

// ---------------------------------------------------------------------------
// ANTIVIRUS RUNNERS (mocked; the real one is opt-in)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CAD exchange files
// ---------------------------------------------------------------------------

const FACETS = [
  [[0, 0, -1], [0, 0, 0], [0, 10, 0], [10, 0, 0]],
  [[0, -1, 0], [0, 0, 0], [10, 0, 0], [0, 0, 10]],
  [[-1, 0, 0], [0, 0, 0], [0, 0, 10], [0, 10, 0]],
  [[0.577, 0.577, 0.577], [10, 0, 0], [0, 10, 0], [0, 0, 10]],
];

/** An ASCII STL of one tetrahedron. `name` is free text after "solid". */
export function stlAscii(name = "guardian-fixture") {
  const facets = FACETS.map(([n, ...vertices]) =>
    `  facet normal ${n.join(" ")}\n    outer loop\n${vertices.map((v) => `      vertex ${v.join(" ")}\n`).join("")}    endloop\n  endfacet\n`).join("");
  return Buffer.from(`solid ${name}\n${facets}endsolid ${name}\n`);
}

/** A binary STL of one tetrahedron. `header` is the free text of its 80-byte header. */
export function stlBinary(header = "Guardian-made binary STL") {
  const buf = Buffer.alloc(84 + 50 * FACETS.length);
  buf.write(header.slice(0, 80), 0, "latin1");
  buf.writeUInt32LE(FACETS.length, 80);
  FACETS.forEach((facet, i) => facet.flat().forEach((value, j) => buf.writeFloatLE(value, 84 + 50 * i + 4 * j)));
  return buf;
}

/** A STEP (ISO 10303-21) file holding one point. `description` is free text in its header. */
export function step(description = "Guardian-made STEP file") {
  return Buffer.from([
    "ISO-10303-21;", "HEADER;", `FILE_DESCRIPTION(('${description}'),'2;1');`,
    "FILE_NAME('fixture.step','2026-11-12T00:00:00',('OTLC Guardian'),(''),'','','');",
    "FILE_SCHEMA(('AUTOMOTIVE_DESIGN { 1 0 10303 214 1 1 1 1 }'));", "ENDSEC;", "DATA;",
    "#1=CARTESIAN_POINT('',(0.,0.,0.));", "ENDSEC;", "END-ISO-10303-21;", "",
  ].join("\n"));
}

/** An IGES file in the fixed 80-column format. `start` is the free text of its start section. */
export function iges(start = "Guardian-made IGES file") {
  const line = (text, section, n) => `${text.padEnd(72).slice(0, 72)}${section}${String(n).padStart(7)}`;
  return Buffer.from([
    line(start, "S", 1),
    line("1H,,1H;,7Hfixture,11Hfixture.igs,8HGuardian,3H1.5,32,38,6,308,15,,1.,2,2HMM,1,", "G", 1),
    line("0.01,15H20261112.000000,0.001,100.,,,11,0,15H20261112.000000;", "G", 2),
    line("     116       1       0       0       0       0       0       000000000", "D", 1),
    line("     116       0       0       1       0                               0", "D", 2),
    line("116,0.,0.,0.,0;", "P", 1),
    line("S      1G      2D      2P      1", "T", 1), "",
  ].join("\n"));
}

export const avClean = () => ({ engine: "mock engine", status: "clean", detail: "no threats (mock)" });
export const avThreat = () => ({ engine: "mock engine", status: "threat", detail: "Virus:DOS/EICAR_Test_File (mock)" });
export const avUnavailable = () => ({ engine: null, status: "unavailable", detail: "no engine (mock)" });
export const avError = () => ({ engine: "mock engine", status: "error", detail: "exit code 0x80508023 (mock)" });
