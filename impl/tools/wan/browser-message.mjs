// A browser conversation on the WAN (client stage 6): one headless browser as one person, driven like
// impl/web/test/messaging.mjs does, against a deployed relay and its mailbox (real certificates, hints on the nodes).
// Run one as Bob on one operator and one as Alice on another: Alice introduces herself through the relay Bob's hint
// names, Bob grants, Alice finds Bob's mailbox through his hint, fetches a KeyPackage there, creates the conversation
// at her mailbox; the hub finds Bob's mailbox through his hint; text both ways, delivered receipts.
//
//   ROLE=bob   URL=https://<relay-b>/ NAME=Bob              node browser-message.mjs   → prints {"did": …}, grants, replies, reports
//   ROLE=alice URL=https://<relay-a>/ NAME=Alice PEER=<did> node browser-message.mjs   → introduces, messages, measures, reports
//
// Needs `playwright` beside it (see browser-call.mjs); BROWSER=firefox uses Firefox. Output: one JSON record on the
// last line (the WAN record's shape), the page's log before it.
import { chromium, firefox } from 'playwright';

const role = process.env.ROLE || 'alice', url = process.env.URL, name = process.env.NAME || role, peer = process.env.PEER;
const t = () => Date.now();
const which = process.env.BROWSER || 'chromium';
const browser = which === 'firefox' ? await firefox.launch({ headless: true }) : await chromium.launch({ headless: true, args: ['--no-sandbox'] });
const ctx = await browser.newContext();
const page = await ctx.newPage();
const out = { role, browser: which, url, started: new Date().toISOString() };
const until = (fn, arg = null, timeout = 60000) => page.waitForFunction(fn, arg, { timeout });
const logHas = (re, timeout) => until((src) => new RegExp(src).test(document.getElementById('log').textContent), re.source, timeout);
const wait = Number(process.env.WAIT_S || 600) * 1000;
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
  out.relay = await page.evaluate(() => window.dsip.relay());
  await until(() => window.dsip.mailbox(), null, 60000);
  out.mailbox_bound_ms = t() - t0;
  out.mailbox = await page.evaluate(() => window.dsip.mailbox());
  await logHas(/◇ personal /, 60000);
  out.personal_ms = t() - t0;
  await logHas(/hint published → .*\+ mailbox .*(accepted|wins)/, 60000);
  out.hint = (await page.textContent('#log')).split('\n').filter((l) => /hint published/.test(l)).map((l) => l.replace(/^\S+\s+/, '')).at(-1) || null;
  console.log(JSON.stringify({ did: out.did, relay: out.relay, mailbox: out.mailbox }));
  if (role === 'bob') {
    await until(() => window.dsip.requests().length === 1, null, wait);
    out.request_text = (await page.textContent('#request-list')).replace(/\s+/g, ' ').trim().slice(0, 200);
    await page.click('#request-list button:text-is("Grant")');
    // PEER may be unset for Bob: any direct conversation counts
    await until((did) => window.dsip.conversations().some((c) => c.kind === 'direct' && (!did || c.peer === did)), peer || '', wait);
    out.joined_ms = t() - t0;
    const conv = await page.evaluate(() => window.dsip.conversations().find((c) => c.kind === 'direct'));
    out.conversation = { group: conv.group, hub: conv.hub.did, members: conv.members.length };
    await until((g) => window.dsip.thread(g).length >= 1, conv.group, wait);
    out.received = await page.evaluate((g) => window.dsip.thread(g).map((m) => [m.mine ? 'me' : 'them', m.object.text, m.seq]), conv.group);
    await page.click('nav button[data-view=messages]');
    await page.evaluate((g) => window.dsip.openConversation(g), conv.group);
    await page.fill('#compose-text', `hi ${name === 'Bob' ? 'Alice' : 'there'}, from ${name} on ${new URL(url).host}`);
    await page.click('#compose-send');
    await logHas(/◇ sent .*seq=/, 60000);
    out.reply_sent_ms = t() - t0;
    await logHas(/◇ receipt .*kind=delivered/, 120000).catch(() => {});
    out.thread = await page.evaluate((g) => window.dsip.thread(g).map((m) => [m.mine ? 'me' : 'them', m.object.text, m.seq, m.delivered ? Object.keys(m.delivered) : null]), conv.group);
  } else {
    await page.fill('#contact-name', 'Bob');
    await page.fill('#contact-did', peer);
    await page.click('#contact-add button[type=submit]');
    await page.waitForSelector('#contact-list li .name:text("Bob")');
    await page.click('#contact-list li button:text("Introduce")');
    await page.fill('#introduce-purpose', 'Stage 6 on the WAN: can we message?');
    const tIntro = t();
    await page.click('#introduce-form button[type=submit]');
    await logHas(/introduction to .* goes through their relay|hints for .*: 0 record/, 60000);
    out.introduction_route = (await page.textContent('#log')).split('\n').filter((l) => /introduction to .* goes through|introducing through our own/.test(l)).map((l) => l.replace(/^\S+\s+/, '')).at(-1) || 'own relay';
    await until((did) => window.dsip.contactStatus(did) === 'they granted you', peer, wait);
    out.granted_ms = t() - tIntro;
    const tMsg = t();
    await page.click('#contact-list li button:text("Message")');
    await logHas(/mailbox of .*HINT-SOURCED|mailbox of .*DID document/, 60000);
    out.mailbox_lookup_ms = t() - tMsg;
    out.peer_mailbox = (await page.textContent('#log')).split('\n').filter((l) => /mailbox of /.test(l)).map((l) => l.replace(/^\S+\s+/, '')).at(-1);
    await logHas(/◇ committed .*added=/, 120000);
    out.conversation_ms = t() - tMsg;
    const conv = await page.evaluate((did) => window.dsip.conversations().find((c) => c.kind === 'direct' && c.peer === did), peer);
    out.conversation = { group: conv.group, hub: conv.hub.did, members: conv.members.length };
    await page.evaluate((g) => window.dsip.openConversation(g), conv.group);
    const tText = t();
    await page.fill('#compose-text', `hello Bob, from ${name} on ${new URL(url).host}`);
    await page.click('#compose-send');
    await logHas(/◇ sent .*seq=/, 60000);
    out.accepted_ms = t() - tText;
    await logHas(/◇ receipt .*kind=delivered/, wait);
    out.delivered_ms = t() - tText;
    await until((g) => window.dsip.thread(g).some((m) => !m.mine), conv.group, wait);
    out.reply_ms = t() - tText;
    await new Promise((r) => setTimeout(r, 3000));
    out.thread = await page.evaluate((g) => window.dsip.thread(g).map((m) => [m.mine ? 'me' : 'them', m.object.text, m.seq, m.delivered ? Object.keys(m.delivered) : null]), conv.group);
    // a reload: the conversation, the thread and the MLS state survive
    await page.reload();
    await page.waitForSelector('#view-contacts:not(.hidden)');
    await until(() => window.dsip.mailbox(), null, 60000);
    await new Promise((r) => setTimeout(r, 2000));
    out.thread_after_reload = await page.evaluate((g) => window.dsip.thread(g).map((m) => [m.mine ? 'me' : 'them', m.object.text, m.seq]), conv.group);
  }
  out.ok = true;
} catch (e) {
  out.ok = false; out.error = String(e.message || e).split('\n')[0];
} finally {
  const log = await page.textContent('#log').catch(() => '');
  console.log(log.trim().split('\n').map((l) => '  ' + l).join('\n'));
  await browser.close();
}
console.log(JSON.stringify(out));
process.exit(out.ok ? 0 : 1);
