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
import { Relay, type RelayContext } from "./relay.js";
import { SchemaSet } from "./schema.js";
import { checkPayload } from "./semantic.js";
import { downgradeSummary, telCallerLine, verificationBasis } from "./trust.js";
import { reject, type Verdict } from "./verdict.js";

const VECTORS = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "impl", "vectors");
const schemas = new SchemaSet();

type Vector = { vector: string; kind: string; context?: JsonObject; input: JsonObject; expect: JsonObject };

/** Kinds this implementation covers so far; the rest are reported as skipped, never as passed. */
const RUNNERS: Record<string, (v: Vector) => Json> = {
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
        actual = run(v);
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
