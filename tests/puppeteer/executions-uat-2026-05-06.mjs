// End-to-end regression for the four UAT 2026-05-06 contracts on the
// executions drawer:
//
//   #8  drawer responses table populates from the SSE bus without a
//       page reload (initial drawer-open + a subsequent dispatch both
//       produce per-agent rows + responses rows visible to the operator
//       within a few seconds, with no manual refresh).
//   #9  the right-hand instruction-line timestamp matches
//       /^\d{2}:\d{2}:\d{2}\.\d{3} [A-Z]{2,5}$/ — wall-clock format
//       in the operator's local timezone, e.g. `12:22:33.251 BST`.
//   #10 each per-agent response row's "Time" cell carries the same
//       wall-clock format, sourced from the new received_at_ms column
//       stamped on response ingest.
//   #11 exactly one logical response row per (instruction_id, agent_id)
//       — terminal SUCCESS / FAILURE frames are folded into the existing
//       RUNNING row in place rather than producing an empty sentinel
//       row that operators misread as a failure exit code.
//
// Pre-condition: server + gateway + agent stack running on :8080
// (bash scripts/start-UAT.sh). Login admin / YuzuUatAdmin1!.
//
// This locks the four UX invariants together: a future change to one
// can't silently regress any of the others.

import puppeteer from 'puppeteer';

const TIME_REGEX = /^\d{2}:\d{2}:\d{2}\.\d{3} [A-Z]{2,5}$/;
const FAILED = [];

function assert(name, ok, detail) {
  if (ok) {
    console.log(`  PASS  ${name}`);
  } else {
    FAILED.push({ name, detail });
    console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

async function main() {
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--window-size=1400,900', '--no-sandbox'],
    defaultViewport: { width: 1400, height: 900 },
  });
  const page = await browser.newPage();

  page.on('pageerror', err => console.log('[pageerror]', err.message));
  page.on('console', msg => {
    if (msg.type() === 'error') console.log('[console.error]', msg.text());
  });

  // -- Login + navigate to Instructions -------------------------------
  await page.goto('http://localhost:8080/login', {
    waitUntil: 'networkidle2', timeout: 15000,
  });
  await page.type('input[name="username"]', 'admin');
  await page.type('input[name="password"]', 'YuzuUatAdmin1!');
  await page.click('button[type="submit"]');
  await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 });

  // Find an agent_id and a definition_id we can dispatch against.
  // Use the same /api/command quick-fanout dispatch first so we have at
  // least one registered agent to target via /api/instructions/.../execute.
  const probe = await page.evaluate(async () => {
    const r = await fetch('/api/command', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ plugin: 'os_info', action: 'os_name' }),
      credentials: 'include',
    });
    return await r.json();
  });
  if (!probe.command_id) {
    console.log('SETUP FAIL: /api/command returned no command_id', probe);
    process.exit(1);
  }
  // Wait for the response to land so the agent_id is in the responses DB.
  await new Promise(r => setTimeout(r, 1500));

  // Dispatch via the workflow-routes path so an executions row exists.
  await page.goto('http://localhost:8080/instructions', {
    waitUntil: 'networkidle2', timeout: 15000,
  });
  // Switch to the Executions tab.
  await page.evaluate(() => {
    const tab = Array.from(document.querySelectorAll('.tab')).find(
      t => t.textContent.trim() === 'Executions');
    if (tab) tab.click();
  });

  // Trigger a fresh dispatch via the workflow execute path so an
  // executions row materialises with a known definition. This dispatches
  // synchronously from the browser session with cookies attached.
  const dispatch = await page.evaluate(async () => {
    // Pull the most-recently-responded agent from the responses surface
    // by trusting the /api/responses/<cmd> path on the prior probe.
    // Easier: just re-read /fragments/agents (HTMX) or call
    // /api/instructions/<id>/execute against scope=__all__.
    const r = await fetch(
      '/api/instructions/device.os_info.os_name/execute',
      {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scope: '__all__', params: {} }),
        credentials: 'include',
      },
    );
    return { status: r.status, body: await r.json() };
  });
  console.log('dispatch:', dispatch);
  if (dispatch.status !== 200 && dispatch.status !== 201) {
    console.log('SETUP FAIL: dispatch returned non-2xx');
    process.exit(1);
  }

  // -- #9: instruction-line wall-clock format -------------------------
  // Reload the executions list so the new row renders.
  await page.evaluate(() => {
    const ev = document.getElementById('exec-history');
    if (ev) htmx.trigger(ev, 'revealed');
  });
  // Give HTMX a beat to fetch + renderLocalTimes to format.
  await new Promise(r => setTimeout(r, 1500));

  const timeText = await page.evaluate(() => {
    const cell = document.querySelector('.exec-time[data-epoch-ms]');
    return cell ? cell.textContent.trim() : null;
  });
  assert('#9 instruction-line shows wall-clock HH:MM:SS.mmm TZ',
    timeText && TIME_REGEX.test(timeText),
    `got: ${JSON.stringify(timeText)}`);

  // -- #8: open the drawer; per-agent + responses tables populate ----
  const opened = await page.evaluate(() => {
    const row = document.querySelector('.exec-row');
    if (!row) return { ok: false, reason: 'no exec-row' };
    row.click();
    return { ok: true };
  });
  if (!opened.ok) {
    console.log('SETUP FAIL: no .exec-row to click', opened);
    process.exit(1);
  }
  // Drawer detail loads via hx-trigger="click once" so HTMX fetches it.
  // Wait for either the per-agent row OR the responses table to land.
  let drawerOk = false;
  for (let attempt = 0; attempt < 20; attempt++) {
    await new Promise(r => setTimeout(r, 500));
    const state = await page.evaluate(() => {
      const peragent = document.querySelectorAll(
        '.exec-detail.open tr[id^="per-agent-row-"]').length;
      const responses = document.querySelectorAll(
        '.exec-detail.open .resp-arrived').length;
      return { peragent, responses };
    });
    if (state.peragent >= 1 && state.responses >= 1) {
      drawerOk = true;
      break;
    }
  }
  assert('#8 drawer per-agent + responses tables populate without reload',
    drawerOk);

  // -- #10: per-agent response cell wall-clock format ----------------
  const arrivedText = await page.evaluate(() => {
    const cell = document.querySelector(
      '.exec-detail.open .resp-arrived[data-epoch-ms]');
    return cell ? cell.textContent.trim() : null;
  });
  assert('#10 per-agent arrival cell shows wall-clock HH:MM:SS.mmm TZ',
    arrivedText && TIME_REGEX.test(arrivedText),
    `got: ${JSON.stringify(arrivedText)}`);

  // -- #11: exactly one row per (instruction, agent), no failure --
  // sentinel preceding the data row.
  const rowShape = await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll(
      '.exec-detail.open .per-agent-responses-table tbody tr'));
    return rows.map(tr => {
      const tds = tr.querySelectorAll('td');
      return {
        agent: tds[0] ? tds[0].textContent.trim() : '',
        statusValue: tds[2] ? tds[2].textContent.trim() : '',
      };
    });
  });
  // Group by agent.
  const byAgent = new Map();
  for (const r of rowShape) {
    const arr = byAgent.get(r.agent) || [];
    arr.push(r.statusValue);
    byAgent.set(r.agent, arr);
  }
  let allSingle = byAgent.size > 0;
  let firstViolation = '';
  for (const [agent, statuses] of byAgent) {
    if (statuses.length !== 1) {
      allSingle = false;
      firstViolation = `${agent} → [${statuses.join(', ')}]`;
      break;
    }
  }
  assert('#11 exactly one response row per (instruction, agent)',
    allSingle,
    firstViolation || (byAgent.size === 0 ? 'no rows at all' : ''));

  // Also pin: status field on every row is a terminal value (SUCCESS=1,
  // FAILURE=2, TIMEOUT=3, REJECTED=4) — never RUNNING (0) or
  // empty / sentinel-shaped.
  const allTerminal = rowShape.every(r =>
    /^[1234]$/.test(r.statusValue));
  assert('#11 every visible response row carries a terminal status enum',
    allTerminal,
    rowShape.find(r => !/^[1234]$/.test(r.statusValue))?.statusValue || '');

  await browser.close();

  if (FAILED.length === 0) {
    console.log('\nAll UAT 2026-05-06 contracts pass.');
    process.exit(0);
  } else {
    console.log(`\n${FAILED.length} contract(s) failed:`);
    for (const f of FAILED) {
      console.log(` - ${f.name}${f.detail ? `: ${f.detail}` : ''}`);
    }
    process.exit(1);
  }
}

main().catch(err => { console.error(err); process.exit(2); });
