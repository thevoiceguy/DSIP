/**
 * Conformance runner: every vector under `impl/vectors`, compared with its `expect` block.
 *
 * Spec: none (infrastructure). Output contract: `impl/vectors/README.md`, "Runner results".
 */
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Authority, Subscriber, type BroadcastContext } from "./broadcast-state.js";
import { verifyHint } from "./dht.js";
import { Endpoint, type EndpointContext } from "./endpoint.js";
import type { Json, JsonObject } from "./did.js";
import { verifyEnvelope, type ReceiverContext } from "./envelope.js";
import { Relay, type RelayContext } from "./relay.js";
import { SchemaSet } from "./schema.js";
import { checkPayload } from "./semantic.js";
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
