/**
 * Conformance runner: every vector under `impl/vectors`, compared with its `expect` block.
 *
 * Spec: none (infrastructure). Output contract: `impl/vectors/README.md`, "Runner results".
 */
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Authority, Subscriber, type BroadcastContext } from "./broadcast-state.js";
import { Candidates, Renegotiation, checkAnswer, checkOffer, dtlsRoles, oneAnswer } from "./binding.js";
import { verifyPublication, type Capabilities } from "./broadcast.js";
import { verifyHint } from "./dht.js";
import { Endpoint, type EndpointContext } from "./endpoint.js";
import type { Json, JsonObject } from "./did.js";
import { verifyEnvelope, type ReceiverContext } from "./envelope.js";
import { GatewayCall, descriptorsToSdp, downgrade, downgradeError, reasonInbound, reasonOutbound, sdpToDescriptors, telClaim } from "./gateway.js";
import { checkConversationExt, checkConversationUpdate, checkMessage } from "./messaging/message.js";
import { checkObject, type ObjectContext } from "./messaging/object.js";
import { CommitRetry, GapTracker, HubOutage, type Machine } from "./messaging/device.js";
import { Client } from "./messaging/client.js";
import { History, Resume, SuccessorTracker } from "./messaging/sync.js";
import * as mcrypto from "./messaging/crypto.js";
import * as blobs from "./messaging/blobs.js";
import * as rules from "./messaging/rules.js";
import { messagingSchemas } from "./messaging/schemas.js";
import { Relay, type RelayContext } from "./relay.js";
import { SchemaSet } from "./schema.js";
import { checkPayload } from "./semantic.js";
import { downgradeSummary, telCallerLine, verificationBasis } from "./trust.js";
import { reject, type Verdict } from "./verdict.js";

const VECTORS = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "impl", "vectors");
const schemas = new SchemaSet();

type Vector = { vector: string; kind: string; context?: JsonObject; input: JsonObject; expect: JsonObject };

/** Kinds this implementation covers so far; the rest are reported as skipped, never as passed. */
const RUNNERS: Record<string, (v: Vector) => Json | undefined> = {
  envelope: (v) => envelope(v),
  transport: (v) => envelope(v),
  dht: (v) =>
    verifyHint(v.input["envelope"]!, v.context as unknown as ReceiverContext, schemas, v.context?.["existing"]),
  payload: (v) =>
    schemas.validMessage(v.input["schema"] as string, v.input["payload"] as JsonObject)
      ? { verdict: "accept" }
      : reject("schema-invalid"),
  broadcast: (v) =>
    verifyPublication(
      v.input["publication"]!,
      v.input["provenance"] as Json[],
      v.input["capabilities"] as unknown as Capabilities,
      v.context as unknown as ReceiverContext,
      schemas,
    ),
  "media-binding": (v) => mediaBinding(v),
  gateway: (v) => gateway(v),
  messaging: (v) => messaging(v),
  trust: (v) =>
    v.input["check"] === "basis"
      ? verificationBasis(v.input["identity"] as string, v.input["claims"] as JsonObject[])
      : v.input["check"] === "tel-caller"
        ? telCallerLine(v.input["claim"] as JsonObject)
        : downgradeSummary(v.input["losses"] as string[]),
  semantic: (v) => checkPayload(v.input["payload"] as JsonObject, v.context ?? {}, schemas),
};

/** A component a state trace can drive. */
interface Component {
  step(event: JsonObject): Json[];
  snapshot(expect: JsonObject): JsonObject;
}

const COMPONENTS: Record<string, (ctx: JsonObject) => Component> = {
  endpoint: (ctx) => new Endpoint(ctx as unknown as EndpointContext),
  relay: (ctx) => new Relay(ctx as unknown as RelayContext),
  authority: (ctx) => new Authority(ctx as unknown as BroadcastContext),
  subscriber: (ctx) => new Subscriber(ctx as unknown as BroadcastContext),
};

/** Kind `state`: per step, `emit` exactly plus the snapshot members the step names. */
function trace(v: Vector): Json[] | null {
  const make = COMPONENTS[v.context?.["component"] as string];
  if (!make) return null;
  const component = make(v.context!);
  return (v.input["steps"] as JsonObject[]).map((step) => {
    const emit = component.step(step["event"] as JsonObject);
    return { emit, ...component.snapshot(step["expect"] as JsonObject) };
  });
}

function hex(value: Json | undefined): Buffer {
  return Buffer.from(value as string, "hex");
}

/** Messaging trace checks → the machine each drives. */
const MACHINES: Record<string, (ctx: never) => Machine> = {
  "gap-trace": (ctx) => new GapTracker(ctx),
  "commit-retry-trace": (ctx) => new CommitRetry(ctx),
  "hub-outage-trace": (ctx) => new HubOutage(ctx),
  "client-trace": (ctx) => new Client(ctx),
  "resume-trace": (ctx) => new Resume(ctx),
  "history-trace": (ctx) => new History(ctx),
  "successor-trace": (ctx) => new SuccessorTracker(ctx),
};

/** Kind `messaging`; a check this implementation does not cover yet returns `undefined` and is reported as skipped. */
function messaging(v: Vector): Json | undefined {
  const i = v.input;
  const make = MACHINES[i["check"] as string];
  if (make) {
    const machine = make(v.context as never);
    return { steps: (i["steps"] as JsonObject[]).map((s) => machine.step(s["event"] as JsonObject) as unknown as Json) };
  }
  switch (i["check"]) {
    case "payload":
      return messagingSchemas.valid(i["schema"] as string, i["payload"]!) ? { verdict: "accept" } : reject("schema-invalid");
    case "message":
      return checkMessage(i["payload"] as JsonObject);
    case "object":
      return checkObject(i["object"] as JsonObject, v.context as unknown as ObjectContext);
    case "voicemail-offer":
      return rules.voicemailOffer(i["voicemail"] as JsonObject | null, i["can_send"] as boolean, i["outcome"] as never);
    case "call-event":
      return rules.callEvent(i as never);
    case "peer-timeline":
      return rules.peerTimeline(i["content"] as never, i["calls"] as never);
    case "mailbox-select":
      return rules.mailboxSelect((i["document_entries"] ?? []) as JsonObject[], (i["hint_entries"] ?? []) as JsonObject[], i["reachable"] as string[] | undefined);
    case "mailbox-switch":
      return rules.mailboxSwitch(i["established"] as never, i["candidate"] as never);
    case "direct-select":
      return rules.directSelect(i["candidates"] as never);
    case "successor-select":
      return rules.successorSelect(i["candidates"] as string[]);
    case "successor-check":
      return rules.successorCheck(i["predecessor_roster"] as string[], i["creator"] as string, i["roster"] as string[]);
    case "external-join":
      return rules.externalJoin(i as never);
    case "registration-on-removal":
      return rules.registrationOnRemoval(i["me"] as string, i["remaining_identities"] as string[]);
    case "blob-put":
      return blobs.blobPut(i as never);
    case "blob-get":
      return blobs.blobGet(i["path_sha256"] as string, i["stored"] as string[]);
    case "blob-replicate":
      return blobs.blobReplicate(i as never);
    case "items-blobs":
      return blobs.itemsBlobs(i["blob_endpoint"] as string, i["stored"] as string[], i["manifest"] as never);
    case "blob-sources":
      return blobs.blobSources(i["blob"] as never, i["manifest"] as never);
    case "mls-extension-encode":
      return { hex: mcrypto.encodeExtension(i["extension_type"] as number, hex(i["data_hex"])).toString("hex") };
    case "mls-extension-decode":
      return mcrypto.decodeExtension(hex(i["hex"]));
    case "mls-conversation-bytes":
      return mcrypto.checkConversationBytes(hex(i["data_hex"]));
    case "mls-credential":
      return mcrypto.checkCredential(i["credential"] as never, hex(i["signature_key_hex"]), i["extensions"] as never, v.context as unknown as ReceiverContext);
    case "seal":
      return { sealed_hex: mcrypto.seal(i as never, hex(i["key_hex"]), hex(i["nonce_hex"]), hex(i["plaintext_hex"])).toString("hex") };
    case "open":
      return mcrypto.open(i as never, hex(i["key_hex"]), hex(i["sealed_hex"]));
    case "hpke-open": {
      const pt = mcrypto.hpkeOpen(hex(i["enc_hex"]), hex(i["sk_r_hex"]), hex(i["info_hex"]), hex(i["aad_hex"]), hex(i["ct_hex"]));
      return pt ? { verdict: "accept", plaintext_hex: pt.toString("hex") } : reject("hpke-open-failed");
    }
    case "hpke-derive-key-pair": {
      const { sk, pk } = mcrypto.hpkeDeriveKeyPair(hex(i["ikm_hex"]));
      return { sk_hex: sk.toString("hex"), pk_hex: pk.toString("hex") };
    }
    case "x25519-key-agreement":
      return { x25519_pk_hex: mcrypto.x25519FromEd25519Seed(hex(i["ed25519_seed_hex"])).pk.toString("hex") };
    case "sealed-introduction-open":
      return mcrypto.openIntroduction(i["payload"] as JsonObject, mcrypto.x25519FromEd25519Seed(hex(i["recipient_ed25519_seed_hex"])).sk);
    case "introduction": {
      // the profile's introduction is the core message: stage 13 shape, then the stage 14 rule
      const p = i["payload"] as JsonObject;
      const failed = checkPayload(p, {}, schemas);
      return failed.verdict === "reject" ? failed : { verdict: "accept", effective: { sealed: "sealed" in p } };
    }
    case "conversation-ext":
      return checkConversationExt(i["extension"] as JsonObject);
    case "conversation-update":
      return checkConversationUpdate(i["before"] as JsonObject, i["after"] as JsonObject);
    default:
      return undefined;
  }
}

function gateway(v: Vector): Json {
  const i = v.input;
  switch (i["check"]) {
    case "reason-inbound":
      return reasonInbound(i as never) as unknown as Json;
    case "reason-outbound":
      return reasonOutbound(i["reason"] as string, i["phase"] as string);
    case "sdp-to-descriptors":
      return sdpToDescriptors(i["sdp"] as string);
    case "descriptors-to-sdp":
      return descriptorsToSdp(i["media"] as JsonObject[]);
    case "claims":
      return telClaim(i as never);
    case "downgrade":
      return downgrade(i["facts"] as JsonObject);
    case "downgrade-error":
      return downgradeError(i["facts"] as JsonObject);
    case "trace": {
      const call = new GatewayCall(v.context as never);
      return { steps: (i["steps"] as JsonObject[]).map((s) => call.step(s["event"] as JsonObject)) };
    }
    default:
      throw new Error(`unknown gateway check ${String(i["check"])}`);
  }
}

function mediaBinding(v: Vector): Json {
  const i = v.input;
  switch (i["check"]) {
    case "offer":
      return checkOffer(i["payload"] as JsonObject);
    case "answer":
      return checkAnswer(i["offer"] as JsonObject, i["payload"] as JsonObject);
    case "role":
      return dtlsRoles(i["offer_setup"] as string, i["answer_setup"] as string);
    case "one-answer":
      return oneAnswer(i["offer"] as JsonObject, i["answers"] as JsonObject[]);
    case "candidates":
    case "renegotiation": {
      const machine =
        i["check"] === "candidates" ? new Candidates(v.context!["peer"] as string) : new Renegotiation(v.context!["ufrag"] as string);
      return { steps: (i["steps"] as JsonObject[]).map((s) => ({ emit: machine.step(s["event"] as JsonObject) })) };
    }
    default:
      throw new Error(`unknown media-binding check ${String(i["check"])}`);
  }
}

function envelope(v: Vector): Verdict {
  const frame = v.input["frame"];
  return verifyEnvelope(
    v.input["envelope"]!,
    v.context as unknown as ReceiverContext,
    schemas,
    typeof frame === "string" ? frame : undefined,
  );
}

/** Deep equality, arrays in order. README "Runner results": an absent member is a claim. */
function equal(a: Json, b: Json): boolean {
  if (a === null || b === null || typeof a !== "object" || typeof b !== "object") return a === b;
  if (Array.isArray(a) || Array.isArray(b)) {
    return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => equal(x, b[i]!));
  }
  const keys = Object.keys(a);
  return keys.length === Object.keys(b).length && keys.every((k) => k in b && equal(a[k]!, b[k]!));
}

function main(): number {
  const args = process.argv.slice(2);
  const jsonOut = args.includes("--json") ? args[args.indexOf("--json") + 1] : undefined;
  const verbose = args.includes("-v");
  const results: Record<string, { ok: boolean; actual?: Json; steps?: Json[]; skipped?: true }> = {};
  let passed = 0, failed = 0, skipped = 0;
  for (const kind of readdirSync(VECTORS, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort()) {
    for (const file of readdirSync(join(VECTORS, kind)).filter((f) => f.endsWith(".json")).sort()) {
      const v = JSON.parse(readFileSync(join(VECTORS, kind, file), "utf8")) as Vector;
      if (v.kind === "state") {
        let steps: Json[] | null;
        try {
          steps = trace(v);
        } catch (e) {
          steps = [{ crash: String(e) }];
        }
        if (!steps) {
          skipped++;
          results[v.vector] = { ok: false, skipped: true };
          continue;
        }
        const expected = (v.input["steps"] as JsonObject[]).map((st) => st["expect"]!);
        const ok = equal(expected, steps);
        results[v.vector] = { ok, steps };
        ok ? passed++ : failed++;
        if (!ok) {
          const i = expected.findIndex((e, n) => !equal(e, steps![n] ?? null));
          console.log(`[FAIL] ${v.vector} step ${i} ${JSON.stringify((v.input["steps"] as JsonObject[])[i]?.["event"]).slice(0, 200)}`);
          console.log(`   expect ${JSON.stringify(expected[i])}\n   actual ${JSON.stringify(steps[i])}`);
        }
        continue;
      }
      const run = RUNNERS[v.kind];
      if (!run) {
        skipped++;
        results[v.vector] = { ok: false, skipped: true };
        continue;
      }
      let actual: Json;
      try {
        const out = run(v);
        if (out === undefined) {
          skipped++;
          results[v.vector] = { ok: false, skipped: true };
          continue;
        }
        actual = out;
      } catch (e) {
        actual = { crash: String(e) };
      }
      const ok = equal(v.expect, actual);
      results[v.vector] = { ok, actual };
      ok ? passed++ : failed++;
      if (!ok || verbose) {
        console.log(`[${ok ? "ok" : "FAIL"}] ${v.vector}`);
        if (!ok) console.log(`   expect ${JSON.stringify(v.expect)}\n   actual ${JSON.stringify(actual)}`);
      }
    }
  }
  if (jsonOut) writeFileSync(jsonOut, JSON.stringify(results, null, 1));
  console.log(`dsip-ts: ${passed} passed, ${failed} failed, ${skipped} skipped (kinds not yet implemented)`);
  return failed ? 1 : 0;
}

process.exit(main());
