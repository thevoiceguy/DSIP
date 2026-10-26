// Sealed presence on the WAN (P§12): Bob (relay B) turns sealing on, publishes available for everyone and busy for his
// sealed `family` audience: his relay sees only the tag. Alice (relay A) watches him at his relay; she introduces
// herself and Bob grants her family, the grant carrying both keys sealed to her (P§12.3). She must read busy, then
// dnd when he changes the family state 40 s later, opened from his sealed records (P§12.4). Then Bob revokes her
// grant: his relay ends her watch (P§7) and both keys rotate (P§12.5), his records going again under epoch 1.
//   ROLE=bob   URL=https://<relay-b>/ NAME=Bob              node browser-presence-sealed.mjs → prints {"did": …}
//   ROLE=alice URL=https://<relay-a>/ NAME=Alice PEER=<did> node browser-presence-sealed.mjs → watches, reports
import { chromium, firefox } from 'playwright';

const role = process.env.ROLE || 'alice', url = process.env.URL, name = process.env.NAME || role, peer = process.env.PEER;
const which = process.env.BROWSER || 'firefox';
const browser = await (which === 'firefox' ? firefox : chromium).launch({ headless: true, args: which === 'chromium' ? ['--no-sandbox'] : [] });
const page = await (await browser.newContext()).newPage();
const out = { role, browser: which, url, started: new Date().toISOString() };
const t = () => Date.now();
const until = (fn, arg = null, timeout = 60000) => page.waitForFunction(fn, arg, { timeout });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const logHas = (re, timeout = 30000) => until((src) => new RegExp(src).test(document.getElementById('log').textContent), re.source, timeout)
  .then(() => true, () => false);
const bound = () => until(() => window.dsip && window.dsip.relay());
try {
  const t0 = t();
  await page.goto(url);
  await page.waitForSelector('#view-welcome:not(.hidden)');
  await page.fill('#welcome-name', name);
  await page.click('#welcome-continue');
  await page.waitForSelector('#view-contacts:not(.hidden)');
  await bound();
  out.bound_ms = t() - t0;
  out.did = await page.evaluate(() => window.dsip.identity());
  await until(() => /hint published → .*(accepted|wins)/.test(document.getElementById('log').textContent), null, 30000).catch(() => {});
  if (role === 'bob') {
    await page.evaluate(() => window.dsip.setSealPresence(true));
    await page.reload(); await page.waitForSelector('#view-contacts:not(.hidden)'); await bound();
    const loaded = page.waitForEvent('load');
    await page.evaluate(() => window.dsip.setAudience('family', 'busy')).catch(() => {});
    await loaded; await page.waitForSelector('#view-contacts:not(.hidden)'); await bound();
    const s = await page.evaluate(() => window.dsip.sealing());
    out.sealed = s?.sealed === true; out.family_tag = s?.audiences?.family || null;
    if (!out.sealed || !out.family_tag) throw new Error(`not sealed: ${JSON.stringify(s)}`);
    await page.evaluate(() => window.dsip.setPresence('available'));
    console.log(JSON.stringify({ did: out.did }));
    out.main_sealed = await logHas(/→ presence {5}sealed under main\.0 seq/);
    out.family_sealed = await logHas(new RegExp(`→ presence {5}sealed under ${out.family_tag}\\.0 for audience family seq`));
    await until(() => window.dsip.requests().length === 1, null, 180000);
    const alice = await page.evaluate(() => window.dsip.requests()[0][1]);
    await page.locator('#request-list li').first().locator('select.grant-audience').selectOption('family');
    await page.click('#request-list button:text-is("Grant")');
    out.grant_with_keys = await logHas(/→ grant [^\n]*with presence keys \(P§12\.3\)/);
    await sleep(40000);
    await page.evaluate(() => window.dsip.setAudience('family', 'dnd'));
    await sleep(40000);
    await page.fill('#contact-name', 'Alice'); await page.fill('#contact-did', alice);
    await page.click('#contact-add button[type=submit]');
    const row = page.locator('#contact-list li', { has: page.locator(`code.did:text-is("${alice}")`) });
    await row.locator('button:text-is("Revoke grant")').click();
    out.revoked = await logHas(/→ grant-revocation of our grant/);
    out.rotated = await logHas(/presence key main rotated to epoch 1/) && await logHas(/presence key family rotated to epoch 1/);
    out.resent_epoch1 = await logHas(/→ presence {5}sealed under main\.1 seq/, 30000);
    await sleep(20000);
    out.sent = (await page.textContent('#log')).split('\n').filter((l) => /→ presence/.test(l)).length;
    out.plain_sent = /→ presence {5}(available|busy|dnd|away|offline) /.test(await page.textContent('#log'));
    out.refused = /our presence record[^\n]* was refused/.test(await page.textContent('#log'));
    if (out.refused || out.plain_sent || !out.main_sealed || !out.family_sealed || !out.grant_with_keys || !out.revoked || !out.rotated || !out.resent_epoch1)
      throw new Error('sealed publisher check failed');
  } else {
    console.log(JSON.stringify({ did: out.did }));
    await page.fill('#contact-name', 'Bob');
    await page.fill('#contact-did', peer);
    await page.click('#contact-add button[type=submit]');
    await page.waitForSelector('#contact-list li .name:text("Bob")');
    await until(() => /presence of .*: not available from that relay/.test(document.getElementById('log').textContent), null, 60000);
    out.refused_before_grant = (await page.evaluate((d) => window.dsip.presence(d), peer)) === null;
    out.answered_refusal = /→ error/.test(await page.textContent('#log'));
    await page.click('#contact-list li button:text("Introduce")');
    await page.fill('#introduce-purpose', 'sealed presence on the WAN');
    await page.click('#introduce-form button[type=submit]');
    await until((did) => window.dsip.contactStatus(did) === 'they granted you', peer, 180000);
    await page.evaluate((did) => window.dsip.watchPresence(did), peer);
    const tAdd = t();
    const shows = (f, timeout = 90000) => until((a) => { const v = window.dsip.presence(a[0]); return v && new Function('v', `return ${a[1]}`)(v); }, [peer, f], timeout);
    await shows("v.source === 'record' && v.state === 'busy' && !v.unreadable");
    out.busy_ms = t() - tAdd;
    out.badge_busy = await page.evaluate((d) => window.dsip.presenceBadge(d), peer);
    await shows("v.source === 'record' && v.state === 'dnd' && !v.unreadable");
    out.dnd_ms = t() - tAdd;
    out.badge_dnd = await page.evaluate((d) => window.dsip.presenceBadge(d), peer);
    await until((d) => window.dsip.presence(d) === null, peer, 120000);
    out.ended_ms = t() - tAdd;
    const log = await page.textContent('#log');
    out.stopped_sharing = /they stopped sharing it with us/.test(log);
    out.presented_grant = /→ subscribe +presence of .* presenting 1 grant/.test(log);
    if (!out.refused_before_grant || out.answered_refusal || !out.presented_grant) throw new Error('P§6 / §9.3 check failed');
  }
  out.ok = true;
} catch (e) {
  out.ok = false; out.error = String(e.message || e).split('\n')[0];
} finally {
  const log = await page.textContent('#log').catch(() => '');
  console.log(log.trim().split('\n').filter((l) => /presence|subscribe|notify|grant|sealed/.test(l)).map((l) => '  ' + l).join('\n'));
  await browser.close();
}
console.log(JSON.stringify(out));
process.exit(out.ok ? 0 : 1);
