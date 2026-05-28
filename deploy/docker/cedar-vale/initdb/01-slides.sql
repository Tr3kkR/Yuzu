-- Cedar & Vale demo — presentation content store.
--
-- This is the "db" tier of the three-tier viz demo. The node "app" tier reads
-- these rows on each page load and renders them as impress.js steps, so the
-- presentation's content genuinely lives in Postgres (per the demo's design):
-- editing a row here changes the live deck on the next reload.
--
-- Runs automatically on first boot via the official postgres image's
-- /docker-entrypoint-initdb.d hook. Idempotent-ish: CREATE TABLE IF NOT EXISTS
-- + TRUNCATE before insert so a re-seed (same volume wiped) is clean.
--
-- Each row is one impress.js step. The data_* columns are the impress.js
-- canvas transform (https://github.com/impress/impress.js): x/y position the
-- step on the infinite canvas, scale zooms, rotate tilts — together they make
-- the Prezi-style fly-through. body_html is the slide's inner markup, styled by
-- app/public/deck.css.

CREATE TABLE IF NOT EXISTS slides (
    position    INT  PRIMARY KEY,
    slug        TEXT NOT NULL,
    title       TEXT NOT NULL,
    body_html   TEXT NOT NULL,
    data_x      INT  NOT NULL,
    data_y      INT  NOT NULL,
    data_z      INT  NOT NULL DEFAULT 0,
    data_rotate INT  NOT NULL DEFAULT 0,
    data_scale  INT  NOT NULL DEFAULT 1
);

TRUNCATE slides;

INSERT INTO slides (position, slug, title, body_html, data_x, data_y, data_z, data_rotate, data_scale) VALUES
(1, 'title', 'Agentic Colleagues',
 '<p class="eyebrow">Yuzu</p>'
 '<h1>Agentic Colleagues</h1>'
 '<h2>IT''s force multiplier &amp; thinking partner</h2>'
 '<p class="footnote">A presentation about agentic IT &mdash; served by a three-tier app, on a fleet managed by Yuzu, drawn live in Yuzu''s own fleet view.</p>',
 0, 0, 0, 0, 2),

(2, 'strain', 'The strain is structural',
 '<h2>The strain is structural</h2>'
 '<ul>'
 '<li><b>Ticket backlog</b> grows faster than headcount.</li>'
 '<li><b>Fleet sprawl</b> &mdash; more endpoints, OSes, and edge than any team can hold in its head.</li>'
 '<li><b>Alert fatigue</b> buries the signal that matters.</li>'
 '<li><b>Tribal knowledge</b> walks out the door with every departure.</li>'
 '</ul>'
 '<p class="footnote">You can''t hire your way out of an exponential.</p>',
 2200, 0, 0, 0, 1),

(3, 'what', 'What an Agentic Colleague is',
 '<h2>What an Agentic Colleague <em>is</em></h2>'
 '<p>Not a chatbot. Not autocomplete for runbooks.</p>'
 '<p>An <b>operator</b> that can, across the whole fleet, in real time:</p>'
 '<ul>'
 '<li><b>Query</b> &mdash; ask the fleet anything and get a live answer.</li>'
 '<li><b>Command</b> &mdash; act on the answer at scale.</li>'
 '<li><b>Scan &amp; patch</b> &mdash; find exposure, close it.</li>'
 '<li><b>Enforce</b> &mdash; hold desired state, continuously.</li>'
 '</ul>',
 3800, 1100, 0, 0, 1),

(4, 'force', 'Force multiplier',
 '<h2>Force multiplier</h2>'
 '<p>One human + agentic colleagues = <b>fleet-wide action from a single intent</b>.</p>'
 '<ul>'
 '<li><b>Scope engine</b> targets the right machines by expression, not by spreadsheet.</li>'
 '<li><b>Instructions</b> turn intent into a typed, auditable command.</li>'
 '<li><b>Guaranteed-state policy</b> makes "stay fixed" the default, not a follow-up ticket.</li>'
 '</ul>'
 '<p class="footnote">The human sets direction. The colleagues cover the distance.</p>',
 3800, 2900, 0, 90, 1),

(5, 'thinking', 'Thinking partner',
 '<h2>Thinking partner</h2>'
 '<p>A multiplier executes. A <em>colleague</em> reasons.</p>'
 '<ul>'
 '<li><b>Scope-walking</b> &mdash; one query''s results become the next query''s target.</li>'
 '<li><b>TAR</b> &mdash; time-aware retention to ask "what changed, and when?"</li>'
 '<li><b>Reasoning over live inventory</b> &mdash; correlate, hypothesise, propose &mdash; not just run.</li>'
 '</ul>'
 '<p class="footnote">It brings you the question behind the question.</p>',
 2200, 3600, 0, 0, 1),

(6, 'how', 'How it runs',
 '<h2>How it runs</h2>'
 '<p>A single control plane, built for both humans and agents:</p>'
 '<ul>'
 '<li><b>Server / Gateway / Agent</b> &mdash; one control plane, millions of endpoints.</li>'
 '<li><b>MCP + REST + dashboard</b> &mdash; every surface an agent can drive, a human can too.</li>'
 '</ul>'
 '<p class="callout">&mdash; and this very deck is running on it: Envoy &rarr; node &rarr; Postgres, three managed agents, drawn live in the fleet view you''re about to see.</p>',
 200, 3600, 0, 0, 1),

(7, 'trust', 'Trust &amp; governance',
 '<h2>Trust &amp; governance</h2>'
 '<p>Agentic-first <b>without</b> losing control:</p>'
 '<ul>'
 '<li><b>RBAC</b> &mdash; tier-before-permission, least privilege by default.</li>'
 '<li><b>Audit trail</b> &mdash; who did what, when, on which devices.</li>'
 '<li><b>Guardrails &amp; kill switches</b> &mdash; bounded autonomy, reversible by design.</li>'
 '<li><b>SOC 2 path</b> &mdash; evidence generated as a by-product of doing the work.</li>'
 '</ul>',
 -1500, 2100, 0, -30, 1),

(8, 'vision', 'Your fleet, with colleagues',
 '<h1>Your fleet, with colleagues</h1>'
 '<h2>Today.</h2>'
 '<p class="footnote">Yuzu &mdash; agentic endpoint management.</p>',
 1100, 1500, 0, 0, 5);
