// Presence audiences on the WAN (P§6): Bob (relay B) publishes available for everyone and busy for his `family`
// audience. Alice (relay A) watches him at his relay (found through his hint, spec-gap 143); presence is private, so
// his relay refuses her and she answers the refusal with nothing (§9.3). She introduces herself and Bob grants her
// the family audience; she must see busy (both records combined, P§4), then do-not-disturb when he changes the family
// state 40 s later, each from his signed records (P§3).
//   ROLE=bob   URL=https://<relay-b>/ NAME=Bob              node browser-presence-audiences.mjs → prints {"did": …}, publishes, stays 120 s
//   ROLE=alice URL=https://<relay-a>/ NAME=Alice PEER=<did> node browser-presence-audiences.mjs → watches, reports
import { chromium, firefox } from 'playwright';

const role = process.env.ROLE || 'alice', url = process.env.URL, name = process.env.NAME || role, peer = process.env.PEER;
const which = process.env.BROWSER || 'firefox';
const browser = await (which === 'firefox' ? firefox : chromium).launch({ headless: true, args: which === 'chromium' ? ['--no-sandbox'] : [] });
const page = await (await browser.newContext()).newPage();
const out = { role, browser: which, url, started: new Date().toISOString() };
const t = () => Date.now();
const until = (fn, arg = null, timeout = 60000) => page.waitForFunction(fn, arg, { timeout });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
try {
  const t0 = t();
  await page.goto(url);
  await page.waitForSelector('#view-welcome:not(.hidden)');
  await page.fill('#welcome-name', name);
  await page.click('#welcome-continue');
  await page.waitForSelector('#view-contacts:not(.hidden)');
  await until(() => window.dsip && window.dsip.relay());
  out.bound_ms = t() - t0;
  out.did = await page.evaluate(() => window.dsip.identity());
  await until(() => /hint published → .*(accepted|wins)/.test(document.getElementById('log').textContent), null, 30000).catch(() => {});
  console.log(JSON.stringify({ did: out.did }));
  if (role === 'bob') {
    await page.evaluate(() => { window.dsip.setPresence('available'); window.dsip.setAudience('family', 'busy'); });
    await until(() => window.dsip.requests().length === 1, null, 180000);
    await page.locator('#request-list li').first().locator('select.grant-audience').selectOption('family');
    await page.click('#request-list button:text-is("Grant")');
    await sleep(3000);   // Bob has no contact row for Alice here (she added him, not he her): the log is the evidence
    out.family_record = /→ presence +busy for audience family/.test(await page.textContent('#log'));
    await sleep(40000);
    await page.evaluate(() => window.dsip.setAudience('family', 'dnd'));
    await sleep(80000);
    out.sent = (await page.textContent('#log')).split('\n').filter((l) => /→ presence/.test(l)).length;
    out.refused = /our presence record was refused/.test(await page.textContent('#log'));
    if (out.refused || !out.family_record) throw new Error(out.refused ? 'a record was refused' : 'no family record');
  } else {
    await page.fill('#contact-name', 'Bob');
    await page.fill('#contact-did', peer);
    await page.click('#contact-add button[type=submit]');
    await page.waitForSelector('#contact-list li .name:text("Bob")');
    await until(() => /presence of .*: not available from that relay/.test(document.getElementById('log').textContent), null, 60000);
    out.refused_before_grant = (await page.evaluate((d) => window.dsip.presence(d), peer)) === null;
    out.answered_refusal = /→ error/.test(await page.textContent('#log'));
    await page.click('#contact-list li button:text("Introduce")');
    await page.fill('#introduce-purpose', 'presence on the WAN');
    await page.click('#introduce-form button[type=submit]');
    await until((did) => window.dsip.contactStatus(did) === 'they granted you', peer, 120000);
    await page.evaluate((did) => window.dsip.watchPresence(did), peer);
    const tAdd = t();
    const shows = (f) => until((a) => { const v = window.dsip.presence(a[0]); return v && new Function('v', `return ${a[1]}`)(v); }, [peer, f], 90000);
    await shows("v.source === 'record' && v.state === 'busy'");
    out.busy_ms = t() - tAdd;
    out.badge_busy = await page.evaluate((d) => window.dsip.presenceBadge(d), peer);
    await shows("v.source === 'record' && v.state === 'dnd'");
    out.dnd_ms = t() - tAdd;
    out.badge_dnd = await page.evaluate((d) => window.dsip.presenceBadge(d), peer);
    const log = await page.textContent('#log');
    out.subscribed_at = (log.match(/→ subscribe +presence of .* at (\S+)/) || [])[1] || null;
    out.presented_grant = /→ subscribe +presence of .* presenting 1 grant/.test(log);
    if (!out.refused_before_grant || out.answered_refusal || !out.presented_grant) throw new Error('P§6 / §9.3 check failed');
  }
  out.ok = true;
} catch (e) {
  out.ok = false; out.error = String(e.message || e).split('\n')[0];
} finally {
  const log = await page.textContent('#log').catch(() => '');
  console.log(log.trim().split('\n').filter((l) => /presence|subscribe|notify|hello/.test(l)).map((l) => '  ' + l).join('\n'));
  await browser.close();
}
console.log(JSON.stringify(out));
process.exit(out.ok ? 0 : 1);
