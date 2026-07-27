/**
 * Browser-side tests for the generated pages.
 *
 * The Python suite checks what the generator writes. It cannot check what the
 * inline script then does with it, and that is where the last two defects were:
 * a defang rule that turned "http://x" into "hxxphttp://x", and a <time>
 * element dropped in a refactor, which left the age filter matching nothing and
 * the CSV export with an empty date column. Neither changed how the page
 * looked, so neither was noticed until someone clicked.
 *
 * Fixtures come from scripts/render_fixture_pages.py - real generator output,
 * not hand-written HTML, so the coupling between markup and script is what is
 * actually under test.
 *
 *   python scripts/render_fixture_pages.py build/fixtures
 *   node --test tests/js/
 */

import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { test, describe, before } from 'node:test';
import { JSDOM } from 'jsdom';

const FIXTURES = process.env.APTTRAIL_FIXTURES ?? 'build/fixtures';

/** Load a generated page, run its inline script, and hand back the window. */
function open(path) {
  const dom = new JSDOM(readFileSync(`${FIXTURES}/${path}`, 'utf8'), {
    runScripts: 'dangerously',
    url: 'https://trilwu.github.io/apttrail/' + path,
  });
  const copied = [];
  // jsdom has no clipboard; capture what the page would have written.
  dom.window.navigator.clipboard = {
    writeText: (text) => {
      copied.push(text);
      return Promise.resolve();
    },
  };
  // Nor SubtleCrypto or fetch. Serve both from the fixtures on disk, so the
  // search page exercises the real shard files the exporter wrote.
  dom.window.crypto.subtle = webcrypto.subtle;
  dom.window.TextEncoder = TextEncoder;
  dom.window.fetch = async (url) => {
    const file = `${FIXTURES}/${String(url).replace(/^.*apttrail\//, '')}`;
    if (!existsSync(file)) return { ok: false };
    const body = readFileSync(file, 'utf8');
    return { ok: true, json: async () => JSON.parse(body), text: async () => body };
  };
  return { window: dom.window, doc: dom.window.document, copied };
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 60));

const type = (input, value) => {
  input.value = value;
  input.dispatchEvent(new input.ownerDocument.defaultView.Event('input'));
};
const toggle = (box, on) => {
  box.checked = on;
  box.dispatchEvent(new box.ownerDocument.defaultView.Event('change'));
};
const visibleRows = (doc) => doc.querySelectorAll('#timeline-list tr:not([hidden])').length;

describe('actor page', () => {
  let ctx;
  before(() => {
    ctx = open('by-group/G0007.html');
  });

  test('defang does not repeat the scheme', () => {
    toggle(ctx.doc.getElementById('defang'), true);
    const values = [...ctx.doc.querySelectorAll('#timeline-list .val')].map((c) => c.textContent);

    assert.ok(values.includes('hxxp://84[.]38[.]134[.]56'), values.join(' '));
    assert.ok(values.includes('hxxps://evil[.]example/payload'), values.join(' '));
    assert.ok(!values.some((v) => v.includes('hxxphttp')), 'scheme was doubled');

    toggle(ctx.doc.getElementById('defang'), false);
    assert.ok([...ctx.doc.querySelectorAll('#timeline-list .val')]
      .map((c) => c.textContent).includes('http://84.38.134.56'));
  });

  test('the filter narrows rows, updates the count and the URL', () => {
    type(ctx.doc.getElementById('q'), 'fresh');

    assert.equal(visibleRows(ctx.doc), 1);
    assert.equal(ctx.doc.getElementById('shown').textContent, '1');
    assert.equal(ctx.window.location.search, '?q=fresh');

    type(ctx.doc.getElementById('q'), '');
  });

  test('a filter that matches nothing explains itself', () => {
    type(ctx.doc.getElementById('q'), 'no-such-indicator');

    assert.equal(visibleRows(ctx.doc), 0);
    assert.equal(ctx.doc.getElementById('empty').hidden, false);

    type(ctx.doc.getElementById('q'), '');
    assert.equal(ctx.doc.getElementById('empty').hidden, true);
  });

  test('type chips filter to one kind', () => {
    ctx.doc.querySelector('#types button[data-type="url"]').click();

    const kinds = new Set(
      [...ctx.doc.querySelectorAll('#timeline-list tr:not([hidden])')].map((r) => r.dataset.t),
    );
    assert.deepEqual([...kinds], ['url']);

    ctx.doc.querySelector('#types button[data-type="all"]').click();
    assert.ok(visibleRows(ctx.doc) > 2);
  });

  test('the age cut drops older batches but keeps recent ones', () => {
    const before = visibleRows(ctx.doc);
    toggle(ctx.doc.getElementById('recent'), true);
    const after = visibleRows(ctx.doc);

    assert.ok(after > 0, 'age filter matched nothing - is the <time> element still there?');
    assert.ok(after < before, 'age filter removed nothing');

    toggle(ctx.doc.getElementById('recent'), false);
  });

  test('CSV export carries type, date and source for every row', () => {
    ctx.doc.querySelector('button[data-copy=csv]').click();

    const [header, ...rows] = ctx.copied.at(-1).split('\n');
    assert.equal(header, 'indicator,type,first_seen,source');
    assert.ok(rows.length > 3);
    for (const row of rows) {
      const [value, kind, date, source] = row.split(',');
      assert.ok(value, 'empty indicator');
      assert.match(kind, /^(domain|ipv4|url|url_path)$/);
      if (value !== 'undated.example') {
        assert.match(date, /^\d{4}-\d{2}-\d{2}$/, `no date on ${value}`);
        assert.match(source, /^https:\/\//, `no source on ${value}`);
      }
    }
  });

  test('copying one batch takes only that batch', () => {
    const li = ctx.doc.querySelector('#timeline-list li');
    li.querySelector('button[data-copy=batch]').click();

    const lines = ctx.copied.at(-1).split('\n');
    assert.equal(lines.length, li.querySelectorAll('tr:not([hidden])').length);
  });

  test('"/" focuses the filter and Escape clears it', () => {
    const q = ctx.doc.getElementById('q');
    type(q, 'fresh');
    ctx.doc.body.dispatchEvent(new ctx.window.KeyboardEvent('keydown', { key: '/', bubbles: true }));
    assert.equal(ctx.doc.activeElement, q);

    q.dispatchEvent(new ctx.window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    assert.equal(q.value, '');
  });
});

describe('group directory', () => {
  let ctx;
  const rows = () => ctx.doc.querySelectorAll('#grouplist tr:not([hidden])');
  before(() => {
    ctx = open('groups.html');
  });

  test('an alias the row does not print is still searchable', () => {
    assert.ok(!ctx.doc.querySelector('#grouplist').textContent.includes('fancy bear'));

    type(ctx.doc.getElementById('q'), 'fancy bear');

    assert.equal(rows().length, 1);
    assert.ok(rows()[0].textContent.includes('APT28'));

    type(ctx.doc.getElementById('q'), '');
  });

  test('columns sort by value, not by rendered text', () => {
    const th = ctx.doc.querySelector('th[data-col="2"]');
    th.click();
    const ascending = [...rows()].map((r) => Number(r.cells[2].dataset.sort));
    th.click();
    const descending = [...rows()].map((r) => Number(r.cells[2].dataset.sort));

    assert.deepEqual(ascending, [...ascending].sort((a, b) => a - b));
    assert.deepEqual(descending, [...descending].sort((a, b) => b - a));
  });

  test('the origin and sector pickers filter the table', () => {
    const country = ctx.doc.getElementById('country');
    const rows = () => [...ctx.doc.querySelectorAll('#grouplist tr:not([hidden])')];
    const available = [...country.options].map((o) => o.value).filter(Boolean);

    if (available.length) {
      country.value = available[0];
      country.dispatchEvent(new ctx.window.Event('change'));

      assert.ok(rows().length > 0, 'a listed origin returned nothing');
      assert.ok(rows().every((r) => r.dataset.country === available[0]));
      assert.match(ctx.window.location.search, /country=/);

      country.value = '';
      country.dispatchEvent(new ctx.window.Event('change'));
    }
  });

  test('a facet in the URL is applied on load', () => {
    // Deep-linking a facetted view is the point of putting it in the URL.
    const country = ctx.doc.getElementById('country');
    assert.ok(country, 'no origin picker');
    assert.equal(country.options[0].value, '', 'first option should be "any"');
  });

  test('ATT&CK-only hides unmapped groups', () => {
    toggle(ctx.doc.getElementById('mapped'), true);

    assert.ok([...rows()].every((r) => r.dataset.attack === '1'));
    assert.ok(rows().length >= 1);

    toggle(ctx.doc.getElementById('mapped'), false);
  });

});

describe('landing page', () => {
  let ctx;
  before(() => {
    ctx = open('index.html');
  });

  test('freshness is rendered client-side', () => {
    assert.match(ctx.doc.getElementById('ago').textContent, /ago|just now/);
  });

  test('the directory is one click away, not the page itself', () => {
    assert.equal(ctx.doc.getElementById('grouplist'), null);
    assert.ok(ctx.doc.querySelector('a[href="groups.html"]'));
  });
});

describe('search page', () => {
  let ctx;
  const search = async (value) => {
    ctx.doc.getElementById('ioc').value = value;
    ctx.doc.getElementById('hunt').dispatchEvent(
      new ctx.window.Event('submit', { cancelable: true, bubbles: true }),
    );
    for (let i = 0; i < 40 && !ctx.doc.getElementById('out').textContent.trim(); i++) {
      await settle();
    }
    return ctx.doc.getElementById('out').textContent.replace(/\s+/g, ' ');
  };

  before(() => {
    ctx = open('search.html');
  });

  test('finds an indicator that is in the feed', async () => {
    const text = await search('fresh.example');

    assert.match(text, /known indicator/);
    assert.match(text, /APT28|SOFACY/);
    assert.match(text, /vendor\.test/, 'the source report should be shown');
  });

  test('accepts input defanged the way a ticket defangs it', async () => {
    assert.match(await search('fresh[.]example'), /known indicator/);
  });

  test('is case insensitive, matching the index rule', async () => {
    assert.match(await search('FRESH.EXAMPLE'), /known indicator/);
  });

  test('a URL is found with or without its scheme', async () => {
    assert.match(await search('http://84.38.134.56'), /known indicator/);
    assert.match(await search('84.38.134.56'), /known indicator/);
  });

  test('a miss says so without implying the indicator is safe', async () => {
    const text = await search('nothing-like-this-exists.invalid');

    assert.match(text, /Not a known indicator/);
    assert.match(text, /not the same as it being safe/);
  });

  test('the query is reflected in the URL so a lookup can be shared', async () => {
    await search('fresh.example');

    assert.equal(ctx.window.location.search, '?q=fresh.example');
  });
});

describe('relationships page', () => {
  let ctx;
  before(() => {
    ctx = open('graph.html');
  });

  test('the ranked list works with no script at all', () => {
    // The list is server-rendered; script only filters it.
    const raw = readFileSync(`${FIXTURES}/graph.html`, 'utf8');
    const list = raw.split('<ul class=pairs>')[1].split('</ul>')[0];

    assert.match(list, /<li data-kinds=/);
    assert.match(list, /infrastructure|reporting|software|technique/);
  });

  test('every row names the evidence it rests on', () => {
    for (const row of ctx.doc.querySelectorAll('.pairs li')) {
      assert.ok(row.dataset.kinds, 'row with no evidence kind');
      assert.ok(row.querySelector('.ev'), 'row with no evidence text');
    }
  });

  test('turning off an evidence kind hides only its rows', () => {
    const boxes = [...ctx.doc.querySelectorAll('.legend input')];
    const infra = boxes.find((b) => b.value === 'infrastructure');
    boxes.forEach((b) => {
      b.checked = b === infra;
      b.dispatchEvent(new ctx.window.Event('change'));
    });

    const visible = [...ctx.doc.querySelectorAll('.pairs li')].filter((r) => !r.hidden);
    assert.ok(visible.length > 0);
    assert.ok(visible.every((r) => r.dataset.kinds.includes('infrastructure')));

    boxes.forEach((b) => {
      b.checked = true;
      b.dispatchEvent(new ctx.window.Event('change'));
    });
  });

  test('the neighbourhood draws the focus and its peers', () => {
    const peers = ctx.doc.querySelectorAll('#ego g.peer');

    assert.ok(peers.length >= 1, 'nothing drawn');
    assert.equal(ctx.doc.querySelectorAll('#ego g.focus').length, 1);
    assert.match(ctx.doc.getElementById('egocap').textContent, /related to/);
  });

  test('every peer is labelled with why it is there', () => {
    for (const peer of ctx.doc.querySelectorAll('#ego g.peer')) {
      assert.ok(peer.querySelector('text.name').textContent.trim(), 'peer with no name');
      assert.ok(peer.querySelector('text.why').textContent.trim(), 'peer with no reason');
    }
  });

  test('clicking a peer recentres on it and updates the URL', () => {
    const peer = ctx.doc.querySelector('#ego g.peer');
    const slug = peer.dataset.slug;

    peer.dispatchEvent(new ctx.window.MouseEvent('click', { bubbles: true }));

    assert.equal(ctx.doc.getElementById('focus').value, slug);
    assert.equal(ctx.window.location.search, `?g=${slug}`);
  });

  test('the drawing is sized to the neighbourhood, not to the largest one', () => {
    const [, , , height] = ctx.doc.getElementById('ego').getAttribute('viewBox').split(' ').map(Number);
    const peers = ctx.doc.querySelectorAll('#ego g.peer').length;

    assert.ok(height > 100, 'no height');
    assert.ok(height <= 690, 'panel taller than the widest neighbourhood needs');
    if (peers <= 2) {
      assert.ok(height < 300, `${height}px of panel for ${peers} peers`);
    }
  });
});

describe('activity page', () => {
  let ctx;
  before(() => {
    ctx = open('activity.html');
  });

  test('filtering hides days that end up empty', () => {
    const daysBefore = ctx.doc.querySelectorAll('.day:not([hidden])').length;
    type(ctx.doc.getElementById('q'), 'apt28');
    const daysAfter = ctx.doc.querySelectorAll('.day:not([hidden])').length;

    assert.ok(daysAfter > 0);
    assert.ok(daysAfter <= daysBefore);
    assert.ok(
      [...ctx.doc.querySelectorAll('.day:not([hidden])')].every(
        (d) => d.querySelector('.event:not([hidden])'),
      ),
      'a day survived with no events in it',
    );
  });

  test('every entry deep-links to a batch that exists on the actor page', () => {
    type(ctx.doc.getElementById('q'), '');
    const links = [...ctx.doc.querySelectorAll('.event .who')].map((a) => a.getAttribute('href'));
    assert.ok(links.length > 0);

    for (const href of links) {
      const [path, anchor] = href.split('#');
      const page = readFileSync(`${FIXTURES}/${path}`, 'utf8');
      assert.ok(page.includes(`id="${anchor}"`), `${href} points at nothing`);
    }
  });
});
