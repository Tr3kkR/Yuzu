#!/usr/bin/env node
/**
 * ASCII-diagram alignment linter — the enforced guarantee from design Q8.
 *
 * Scans every in-scope doc (from the manifest) and every <pre class="diagram">
 * in the site's .astro sources. For any block containing box-drawing characters
 * it asserts that every FRAME line — a line that begins with a box-drawing
 * character, i.e. carries the left+right border — has the same display width
 * (East-Asian-Width aware). Connector/arrow lines (which begin with spaces) are
 * exempt, and every line is right-trimmed first, so the check is immune to
 * trailing-whitespace stripping by editors or the trailing-whitespace pre-commit
 * hook. It also rejects the retired inline arrow glyphs (►◄▶◀).
 *
 * Any violation exits non-zero so the build/CI refuses to ship a misaligned
 * diagram. Pure Node — no dependencies.
 */
import fs from 'node:fs';
import path from 'node:path';
import { ENTRIES } from '../src/nav.mjs';

const repoRoot = path.resolve(process.cwd(), '..');
const docsRoot = path.join(repoRoot, 'docs');
const srcRoot = path.join(process.cwd(), 'src');

const BOX = /[─-╿▀-▟■-◿]/; // box-drawing, blocks, geometric shapes
const RETIRED = /[►◄▶◀]/; // ► ◄ ▶ ◀  — retired per design Q8
const isFrameStart = (l) => l.length > 0 && l.codePointAt(0) >= 0x2500 && l.codePointAt(0) <= 0x257f;

const failures = [];

/** East-Asian-Width-aware cell width. Ambiguous (▼ · etc.) counts as 1. */
function charWidth(cp) {
  if (cp === 0) return 0;
  if (
    (cp >= 0x1100 && cp <= 0x115f) || cp === 0x2329 || cp === 0x232a ||
    (cp >= 0x2e80 && cp <= 0x303e) || (cp >= 0x3041 && cp <= 0x33ff) ||
    (cp >= 0x3400 && cp <= 0x4dbf) || (cp >= 0x4e00 && cp <= 0x9fff) ||
    (cp >= 0xa000 && cp <= 0xa4cf) || (cp >= 0xac00 && cp <= 0xd7a3) ||
    (cp >= 0xf900 && cp <= 0xfaff) || (cp >= 0xfe10 && cp <= 0xfe19) ||
    (cp >= 0xfe30 && cp <= 0xfe6f) || (cp >= 0xff00 && cp <= 0xff60) ||
    (cp >= 0xffe0 && cp <= 0xffe6) || (cp >= 0x1f300 && cp <= 0x1faff) ||
    (cp >= 0x20000 && cp <= 0x3fffd)
  ) return 2;
  return 1;
}
const width = (s) => [...s].reduce((w, ch) => w + charWidth(ch.codePointAt(0)), 0);

function checkBlock(fileLabel, firstLineNo, rawLines) {
  // right-trim every line: alignment must NOT depend on trailing whitespace.
  const lines = rawLines.map((l) => l.replace(/[ \t]+$/, ''));

  lines.forEach((l, i) => {
    const m = l.match(RETIRED);
    if (m) failures.push(`${fileLabel}:${firstLineNo + i}  retired arrow glyph "${m[0]}" in diagram — normalise it`);
  });

  const frame = [];
  lines.forEach((l, i) => { if (isFrameStart(l)) frame.push({ l, i, w: width(l) }); });
  if (frame.length < 2) return; // not a framed box diagram

  const target = Math.max(...frame.map((o) => o.w));
  for (const o of frame) {
    if (o.w !== target) {
      failures.push(
        `${fileLabel}:${firstLineNo + o.i}  frame edge misaligned: width ${o.w} ≠ ${target} (Δ${o.w - target})  | ${o.l}`
      );
    }
  }
}

function scanMarkdown(fp) {
  const src = fs.readFileSync(fp, 'utf8');
  const lines = src.split('\n');
  const label = path.relative(repoRoot, fp);
  for (let i = 0; i < lines.length; i++) {
    const fence = lines[i].match(/^(\s*)(`{3,}|~{3,})/);
    if (!fence) continue;
    const marker = fence[2][0];
    const block = [];
    const start = i + 1;
    i++;
    while (i < lines.length && !lines[i].trimStart().startsWith(marker.repeat(3))) {
      block.push(lines[i]);
      i++;
    }
    if (block.some((l) => BOX.test(l))) checkBlock(label, start + 1, block);
  }
}

function scanAstro(fp) {
  const src = fs.readFileSync(fp, 'utf8');
  const label = path.relative(repoRoot, fp);
  const re = /<pre[^>]*class="[^"]*\bdiagram\b[^"]*"[^>]*>([\s\S]*?)<\/pre>/g;
  let m;
  while ((m = re.exec(src))) {
    let inner = m[1]
      .replace(/<\/?[a-zA-Z][^>]*>/g, '')
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
    const block = inner.replace(/^\n/, '').split('\n');
    while (block.length && block[block.length - 1].trim() === '') block.pop();
    if (block.some((l) => BOX.test(l))) checkBlock(label, 1, block);
  }
}

function walk(dir, fn) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const fp = path.join(dir, e.name);
    if (e.isDirectory()) walk(fp, fn);
    else fn(fp);
  }
}

let scanned = 0;
for (const e of ENTRIES) {
  const fp = path.join(docsRoot, `${e.file}.md`);
  if (!fs.existsSync(fp)) {
    failures.push(`manifest entry "${e.file}" -> ${path.relative(repoRoot, fp)} does not exist`);
    continue;
  }
  scanMarkdown(fp);
  scanned++;
}
if (fs.existsSync(srcRoot)) walk(srcRoot, (fp) => { if (fp.endsWith('.astro')) scanAstro(fp); });

if (failures.length) {
  console.error(`\n✗ diagram linter: ${failures.length} problem(s)\n`);
  for (const f of failures) console.error('  ' + f);
  console.error('');
  process.exit(1);
}
console.log(`✓ diagram linter: ${scanned} doc(s) + .astro sources — all frame edges aligned, no retired glyphs.`);
