/**
 * The Messaging Profile schema set, loaded in place from the spec folder.
 *
 * Spec: M§5.1 (schemas are normative for shape). Spec: none beyond that (infrastructure).
 */
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { SchemaSet } from "../schema.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

/** Compiled `v0.8/dsip-messaging-schemas-draft/schemas`. */
export const messagingSchemas = new SchemaSet(join(REPO, "v0.8", "dsip-messaging-schemas-draft", "schemas"));
