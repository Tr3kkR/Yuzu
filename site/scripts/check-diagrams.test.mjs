import test from 'node:test';
import assert from 'node:assert/strict';
import { lintBlock, markdownBlocks, astroDiagramBlocks, width } from './check-diagrams.mjs';

const bar = (n) => '─'.repeat(n);

test('aligned framed block passes', () => {
  const block = ['┌' + bar(10) + '┐', '│' + ' '.repeat(10) + '│', '└' + bar(10) + '┘'];
  assert.deepEqual(lintBlock(block), []);
});

test('misaligned frame edge is flagged', () => {
  const block = ['┌' + bar(10) + '┐', '│' + ' '.repeat(8) + '│', '└' + bar(10) + '┘']; // middle is 2 short
  const problems = lintBlock(block);
  assert.ok(problems.some((p) => /misaligned/.test(p.message)), 'expected a misalignment problem');
});

test('connector lines are exempt and trailing whitespace is ignored', () => {
  // connector line is shorter AND has trailing spaces — must still pass
  const block = ['┌' + bar(10) + '┐', '     │      ', '└' + bar(10) + '┘'];
  assert.deepEqual(lintBlock(block), []);
});

test('retired arrow glyph is flagged even when widths are fine', () => {
  const inner = '► hi      '; // 10 cells
  assert.equal(width(inner), 10);
  const block = ['┌' + bar(10) + '┐', '│' + inner + '│', '└' + bar(10) + '┘'];
  const problems = lintBlock(block);
  assert.ok(problems.some((p) => /retired arrow/.test(p.message)), 'expected a retired-arrow problem');
  assert.ok(!problems.some((p) => /misaligned/.test(p.message)), 'should not also report misalignment');
});

test('markdownBlocks only extracts box-drawing fences', () => {
  const md = [
    'text', '```', 'plain code, no boxes', '```',
    'more', '```text', '┌──┐', '└──┘', '```', 'end',
  ].join('\n');
  const blocks = markdownBlocks(md);
  assert.equal(blocks.length, 1);
  assert.deepEqual(blocks[0].lines, ['┌──┐', '└──┘']);
});

test('astroDiagramBlocks strips tags/entities and finds the diagram', () => {
  const astro = '<pre class="diagram" id="x">\n┌──┐\n│<b>A</b>&lt;│\n└──┘\n</pre>';
  const blocks = astroDiagramBlocks(astro);
  assert.equal(blocks.length, 1);
  assert.deepEqual(blocks[0].lines, ['┌──┐', '│A<│', '└──┘']);
});
