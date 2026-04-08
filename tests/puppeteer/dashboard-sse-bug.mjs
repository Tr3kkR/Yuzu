/**
 * Puppeteer test: Dashboard SSE response display bug
 *
 * Reproduces the issue where after a few commands, responses stop
 * appearing in the dashboard UI despite server/agent logs showing
 * successful execution.
 *
 * Usage: node tests/puppeteer/dashboard-sse-bug.mjs
 */

import puppeteer from 'puppeteer';

const BASE_URL = 'http://localhost:8080';
const USERNAME = 'admin';
const PASSWORD = 'YuzuUatAdmin1!';

// Commands to send in sequence
const COMMANDS = [
  'os_info os_name',
  'os_info os_version',
  'hardware cpu_info',
  'network interfaces',
  'os_info uptime',
];

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function main() {
  console.log('=== Dashboard SSE Response Bug Test ===\n');

  const browser = await puppeteer.launch({
    headless: false,  // visible so we can watch
    args: ['--window-size=1400,900'],
    defaultViewport: { width: 1400, height: 900 },
  });

  const page = await browser.newPage();

  // Track SSE events
  const sseEvents = [];
  let sseConnectionCount = 0;

  // Listen for SSE connections via CDP
  const client = await page.createCDPSession();
  await client.send('Network.enable');

  client.on('Network.requestWillBeSent', (params) => {
    if (params.request.url.includes('/events')) {
      sseConnectionCount++;
      console.log(`  [SSE] Connection #${sseConnectionCount} opened: ${params.request.url}`);
    }
  });

  // Intercept console messages
  page.on('console', msg => {
    const text = msg.text();
    if (text.includes('SSE') || text.includes('sse') || text.includes('htmx'))
      console.log(`  [console] ${text}`);
  });

  // ── Step 1: Login ─────────────────────────────────────────────
  console.log('[1] Logging in...');
  await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USERNAME);
  await page.type('input[name="password"]', PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForNavigation({ waitUntil: 'networkidle2' });
  console.log(`  Logged in. URL: ${page.url()}\n`);

  // Wait for SSE to connect
  await sleep(2000);
  console.log(`  SSE connections so far: ${sseConnectionCount}\n`);

  // ── Step 2: Send commands and check responses ──────────────────
  const results = [];

  for (let i = 0; i < COMMANDS.length; i++) {
    const cmd = COMMANDS[i];
    console.log(`[${i + 2}] Sending command: "${cmd}"`);

    // Clear the command input and type the new command
    const inputSelector = '#command-input, input[name="instruction"], #instruction-input';
    await page.waitForSelector(inputSelector, { timeout: 5000 });

    // Find the actual input element
    const input = await page.$(inputSelector);
    if (!input) {
      console.log('  ERROR: Could not find command input');
      results.push({ command: cmd, rowCount: 0, error: 'no input' });
      continue;
    }

    // Clear and type
    await input.click({ clickCount: 3 });
    await input.type(cmd);

    // Count rows BEFORE sending
    const rowsBefore = await page.$$eval(
      '#results-tbody tr.result-row',
      rows => rows.length
    ).catch(() => 0);

    // Click Send button
    const sendBtn = await page.$('button[type="submit"], #send-btn, button.send-btn');
    if (sendBtn) {
      await sendBtn.click();
    } else {
      // Try pressing Enter
      await input.press('Enter');
    }

    // Wait for responses to arrive via SSE
    console.log(`  Waiting for SSE responses...`);
    let rowsAfter = 0;
    let waited = 0;
    const maxWait = 8000; // 8 seconds max

    while (waited < maxWait) {
      await sleep(500);
      waited += 500;
      rowsAfter = await page.$$eval(
        '#results-tbody tr.result-row',
        rows => rows.length
      ).catch(() => 0);

      if (rowsAfter > 0) break;
    }

    // Also check if tbody has any content at all (not just result-row class)
    const tbodyContent = await page.$eval('#results-tbody', el => ({
      innerHTML: el.innerHTML.substring(0, 500),
      childCount: el.children.length,
      hasSSESwap: el.hasAttribute('sse-swap'),
      sseSwapValue: el.getAttribute('sse-swap'),
      hxSwapValue: el.getAttribute('hx-swap'),
    })).catch(() => null);

    // Check the result context area
    const statusText = await page.$eval('#result-context', el => el.textContent).catch(() => '');
    const rowCount = await page.$eval('#row-count', el => el.textContent).catch(() => '?');

    results.push({
      command: cmd,
      rowsBefore,
      rowsAfter,
      statusText: statusText.trim(),
      displayedRowCount: rowCount,
      waited,
    });

    console.log(`  Rows: before=${rowsBefore}, after=${rowsAfter}, displayed count=${rowCount}`);
    console.log(`  Status: "${statusText.trim()}"`);
    if (tbodyContent) {
      console.log(`  tbody: children=${tbodyContent.childCount}, sse-swap=${tbodyContent.sseSwapValue}, hx-swap=${tbodyContent.hxSwapValue}`);
      if (rowsAfter === 0) {
        console.log(`  tbody innerHTML (first 500 chars): ${tbodyContent.innerHTML}`);
      }
    }
    console.log(`  SSE connections: ${sseConnectionCount}`);
    console.log('');

    // Small delay between commands
    await sleep(1500);
  }

  // ── Step 3: Summary ────────────────────────────────────────────
  console.log('\n=== Results Summary ===');
  console.log(`Total SSE connections: ${sseConnectionCount}`);
  console.log('');

  let bugReproduced = false;
  for (const r of results) {
    const ok = r.rowsAfter > 0;
    const icon = ok ? 'OK' : 'FAIL';
    console.log(`  [${icon}] "${r.command}" - ${r.rowsAfter} rows (waited ${r.waited}ms)`);
    if (!ok) bugReproduced = true;
  }

  if (bugReproduced) {
    console.log('\n  >>> BUG REPRODUCED: Some commands produced no visible rows <<<');
  } else {
    console.log('\n  All commands showed responses. Bug may need more iterations.');
    console.log('  Trying additional rapid-fire commands...\n');

    // Try rapid-fire commands
    for (let i = 0; i < 5; i++) {
      const cmd = COMMANDS[i % COMMANDS.length];
      const input = await page.$('#command-input, input[name="instruction"], #instruction-input');
      if (!input) break;
      await input.click({ clickCount: 3 });
      await input.type(cmd);
      const sendBtn = await page.$('button[type="submit"], #send-btn, button.send-btn');
      if (sendBtn) await sendBtn.click();
      else await input.press('Enter');
      await sleep(2000);

      const rows = await page.$$eval('#results-tbody tr.result-row', rows => rows.length).catch(() => 0);
      const rowCount = await page.$eval('#row-count', el => el.textContent).catch(() => '?');
      console.log(`  Rapid #${i + 1}: "${cmd}" -> ${rows} rows (count display: ${rowCount})`);
      if (rows === 0) {
        bugReproduced = true;
        console.log('  >>> BUG REPRODUCED on rapid-fire <<<');
      }
    }
  }

  // Final SSE connection state
  const finalSSE = await page.$eval('[sse-connect]', el => ({
    hasAttr: true,
    value: el.getAttribute('sse-connect'),
  })).catch(() => ({ hasAttr: false }));
  console.log(`\nFinal SSE state: connected=${finalSSE.hasAttr}, url=${finalSSE.value || 'none'}`);
  console.log(`Total SSE connections opened: ${sseConnectionCount}`);

  // Keep browser open for manual inspection
  console.log('\nBrowser left open for inspection. Press Ctrl+C to exit.');
  await new Promise(() => {}); // hang forever
}

main().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
