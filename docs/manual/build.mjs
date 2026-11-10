#!/usr/bin/env node
// Builds the OTLC Guardian manual from chapters/*.html.
//
//   node docs/manual/build.mjs
//
// Same layout and checks as DevNeural's manual build (DevNeural
// docs/manual/build.mjs), with Guardian's name and mark.
//
// Output:
//   docs/manual/GUARDIAN-MANUAL.html   one self-contained page (CSS and JS inline)
//   docs/manual/site/index.html         cover plus contents
//   docs/manual/site/<chapter>.html     one page per chapter, sharing site/manual.css
//
// A chapter file is one <section class="chapter" id="..." data-num="..."
// data-title="..." data-blurb="..."> fragment. 00-cover.html is the cover.
// The build fails on an em or en dash anywhere, or on an in-page link whose
// target id does not exist in any chapter.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const chapterDir = path.join(here, 'chapters');
const siteDir = path.join(here, 'site');
const css = fs.readFileSync(path.join(here, 'manual.css'), 'utf8');

const FONTS = '<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Inter+Tight:wght@500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap">';
const MARK = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3 5 6v5c0 4.4 3 8.3 7 9.5 4-1.2 7-5.1 7-9.5V6z"/><path d="m9 12 2 2 4-4"/></svg>';

const files = fs.readdirSync(chapterDir).filter((f) => f.endsWith('.html')).sort();
const chapters = [];
let cover = null;
for (const f of files) {
  const html = fs.readFileSync(path.join(chapterDir, f), 'utf8');
  if (f.startsWith('00-')) { cover = html; continue; }
  const open = html.match(/<section class="chapter"[^>]*>/);
  if (!open) throw new Error(`${f}: no <section class="chapter"> opening tag`);
  const attr = (name) => (open[0].match(new RegExp(`${name}="([^"]*)"`)) || [])[1] || '';
  const id = attr('id');
  const subs = [...html.matchAll(/<h3 id="([^"]+)">([\s\S]*?)<\/h3>/g)].map((m) => ({ id: m[1], title: m[2].replace(/<[^>]+>/g, '') }));
  chapters.push({ file: f, id, num: attr('data-num'), title: attr('data-title'), blurb: attr('data-blurb'), html, subs, page: `${id}.html` });
}
if (!cover) throw new Error('chapters/00-cover.html is missing');

// ---- checks ----
const problems = [];
const allIds = new Map();
// En dash U+2013 and em dash U+2014, written as escapes so this file never holds one.
const DASH = /[\u2013\u2014]/;
for (const c of [{ id: 'cover', html: cover, page: 'index.html' }, ...chapters]) {
  for (const m of c.html.matchAll(/\sid="([^"]+)"/g)) {
    if (allIds.has(m[1]) && allIds.get(m[1]) !== c.page) problems.push(`duplicate id "${m[1]}" in ${c.page} and ${allIds.get(m[1])}`);
    allIds.set(m[1], c.page);
  }
}
for (const c of [{ file: '00-cover.html', html: cover }, ...chapters]) {
  const lines = c.html.split('\n');
  lines.forEach((line, i) => { if (DASH.test(line)) problems.push(`${c.file}:${i + 1}: em or en dash`); });
  for (const m of c.html.matchAll(/href="#([^"]+)"/g)) if (!allIds.has(m[1])) problems.push(`${c.file}: link to missing #${m[1]}`);
  // SVG markers are per figure; a marker id must be defined in the same file.
  for (const m of c.html.matchAll(/url\(#([^)]+)\)/g)) if (!c.html.includes(`id="${m[1]}"`)) problems.push(`${c.file}: url(#${m[1]}) has no definition`);
}
if (DASH.test(css)) problems.push('manual.css: em or en dash');
if (problems.length) { console.error(problems.join('\n')); process.exit(1); }

// ---- shared pieces ----
const totalChapters = chapters.length;
const builtOn = new Date().toISOString().slice(0, 10);

function rail({ single, current }) {
  const items = chapters.map((c) => {
    const href = single ? `#${c.id}` : c.page;
    const on = !single && c.id === current ? ' class="on"' : '';
    const sub = c.subs.length
      ? `<ul class="sub">${c.subs.map((s) => `<li><a href="${single ? '' : c.page}#${s.id}">${s.title}</a></li>`).join('')}</ul>`
      : '';
    return `<li${!single && c.id === current ? ' class="open"' : ''}><a href="${href}"${on} data-ch="${c.id}"><span class="n">${c.num}</span><span>${c.title}</span></a>${sub}</li>`;
  }).join('');
  const home = single ? '#top' : 'index.html';
  return `<nav class="rail" aria-label="Chapters">
<a class="brand" href="${home}"><span class="mark">${MARK}</span><span><b>OTLC Guardian</b><small>The manual</small></span></a>
<div class="tools"><button type="button" data-theme-toggle>Theme</button>${single ? '' : '<a class="chip" href="../GUARDIAN-MANUAL.html" style="border:0">One page</a>'}</div>
<ol>${items}</ol>
<div class="foot">${totalChapters} chapters<br>Built ${builtOn}<br>From the code, not the brochure.</div>
</nav>`;
}

// Storage can be blocked (a file:// page, a privacy mode). The theme then
// still toggles, it just is not remembered; data-theme-persist says so.
const SCRIPT = `<script>
(function(){
  var KEY='guardian-manual-theme';
  var persistOff=function(){document.documentElement.setAttribute('data-theme-persist','off');};
  try{var t=localStorage.getItem(KEY);if(t)document.documentElement.setAttribute('data-theme',t);}catch(e){persistOff();}
  document.addEventListener('click',function(e){
    var b=e.target.closest('[data-theme-toggle]');if(!b)return;
    var root=document.documentElement;
    var dark=root.getAttribute('data-theme')?root.getAttribute('data-theme')==='dark':window.matchMedia('(prefers-color-scheme: dark)').matches;
    var next=dark?'light':'dark';root.setAttribute('data-theme',next);
    try{localStorage.setItem(KEY,next);}catch(e2){persistOff();}
  });
  if(!('IntersectionObserver' in window))return;
  var links={};document.querySelectorAll('.rail a[data-ch]').forEach(function(a){links[a.getAttribute('data-ch')]=a;});
  var secs=document.querySelectorAll('section.chapter');
  if(secs.length<2)return;
  var io=new IntersectionObserver(function(es){es.forEach(function(en){
    if(!en.isIntersecting)return;var id=en.target.id;
    Object.keys(links).forEach(function(k){links[k].classList.toggle('on',k===id);links[k].parentNode.classList.toggle('open',k===id);});
  });},{rootMargin:'-20% 0px -70% 0px'});
  secs.forEach(function(s){io.observe(s);});
})();
</script>`;

function head(title, description, cssTag) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<meta name="description" content="${description}">
${FONTS}
${cssTag}
</head>`;
}

function contents(single) {
  return `<div class="toc-grid">${chapters.map((c) => `<a href="${single ? '#' + c.id : c.page}"><span class="n">${c.num}</span><b>${c.title}</b><span>${c.blurb}</span></a>`).join('')}</div>`;
}

function chapterHead(c) {
  return c.html.replace(/(<section class="chapter"[^>]*>)/, `$1\n<header class="chapter-head"><div class="num">${c.num}</div><div><h2>${c.title}</h2><p>${c.blurb}</p></div></header>`);
}

// ---- single page ----
// Images are embedded as data URIs so the one-page manual stays one file.
const imgDir = path.join(here, 'img');
function inlineImages(html) {
  return html.replace(/src="img\/([^"]+)"/g, (m, file) => {
    const p = path.join(imgDir, file);
    if (!fs.existsSync(p)) throw new Error(`missing image img/${file}`);
    const ext = path.extname(file).slice(1).replace('jpg', 'jpeg');
    return `src="data:image/${ext};base64,${fs.readFileSync(p).toString('base64')}"`;
  });
}
const coverSingle = cover.replace('<!--CONTENTS-->', contents(true));
const single = `${head('OTLC Guardian Manual', 'How OTLC Guardian works, end to end: the audit engine, the runtime guard, the Claude Code hooks, install and update, exemptions, and the systems that depend on it.', `<style>\n${css}\n</style>`)}
<body id="top">
${rail({ single: true })}
<main class="page">
${coverSingle}
${inlineImages(chapters.map(chapterHead).join('\n'))}
</main>
${SCRIPT}
</body>
</html>
`;
fs.writeFileSync(path.join(here, 'GUARDIAN-MANUAL.html'), single);

// ---- multi page ----
fs.mkdirSync(siteDir, { recursive: true });
fs.writeFileSync(path.join(siteDir, 'manual.css'), css);
if (fs.existsSync(imgDir)) {
  fs.mkdirSync(path.join(siteDir, 'img'), { recursive: true });
  for (const f of fs.readdirSync(imgDir)) fs.copyFileSync(path.join(imgDir, f), path.join(siteDir, 'img', f));
}
function relink(html, page) {
  return html.replace(/href="#([^"]+)"/g, (m, id) => {
    const target = allIds.get(id);
    return !target || target === page ? m : `href="${target}#${id}"`;
  });
}
const cssLink = '<link rel="stylesheet" href="manual.css">';
fs.writeFileSync(path.join(siteDir, 'index.html'), `${head('OTLC Guardian Manual', 'How OTLC Guardian works, end to end.', cssLink)}
<body id="top">
${rail({ single: false, current: '' })}
<main class="page">
${relink(cover.replace('<!--CONTENTS-->', contents(false)), 'index.html')}
</main>
${SCRIPT}
</body>
</html>
`);
chapters.forEach((c, i) => {
  const prev = chapters[i - 1];
  const next = chapters[i + 1];
  const pager = `<nav class="pager">${prev ? `<a href="${prev.page}">&larr; ${prev.num} ${prev.title}</a>` : '<a href="index.html">&larr; Contents</a>'}${next ? `<a href="${next.page}">${next.num} ${next.title} &rarr;</a>` : '<span></span>'}</nav>`;
  fs.writeFileSync(path.join(siteDir, c.page), `${head(`${c.title} | OTLC Guardian Manual`, c.blurb, cssLink)}
<body>
${rail({ single: false, current: c.id })}
<main class="page">
${relink(chapterHead(c), c.page)}
${pager}
</main>
${SCRIPT}
</body>
</html>
`);
});

const kb = (n) => `${Math.round(n / 1024)} KB`;
process.stdout.write(`built ${chapters.length} chapters: GUARDIAN-MANUAL.html ${kb(Buffer.byteLength(single))}, site/ ${chapters.length + 1} pages
`);
