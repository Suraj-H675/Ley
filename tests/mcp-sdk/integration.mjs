import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  mkdir,
  readFile,
  readlink,
  realpath,
  readdir,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";

import { Client as ModernClient } from "@modelcontextprotocol/client";
import { StdioClientTransport as ModernStdio } from "@modelcontextprotocol/client/stdio";
import { Client as LegacyClient } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport as LegacyStdio } from "@modelcontextprotocol/sdk/client/stdio.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
assert.ok(process.env.LEY_MCP_BIN, "LEY_MCP_BIN must name a built Ley binary");
assert.ok(process.env.LEY_MCP_EVIDENCE_DIR, "LEY_MCP_EVIDENCE_DIR must name an ignored evidence directory");
const binary = await realpath(process.env.LEY_MCP_BIN);
const evidenceRoot = resolve(process.env.LEY_MCP_EVIDENCE_DIR);
assert.ok((await stat(binary)).isFile(), "LEY_MCP_BIN must name a built Ley binary");
await mkdir(evidenceRoot, { recursive: true });
const runRoot = join(evidenceRoot, `sdk-acceptance-${Date.now()}-${process.pid}`);
await mkdir(runRoot, { recursive: false });

const store = join(runRoot, "store");
const otherStore = join(runRoot, "other-store");
const source = join(runRoot, "source");
const reportPath = join(runRoot, "report.json");
const timings = [];
const checks = [];

function record(check, detail = "passed") {
  checks.push({ check, detail });
}

function cli(args, input) {
  const result = spawnSync(binary, args, {
    cwd: repoRoot,
    encoding: "utf8",
    input,
    maxBuffer: 1024 * 1024,
    env: process.env,
  });
  assert.equal(result.error, undefined, `could not run ley ${args[0]}`);
  assert.equal(result.status, 0, `ley ${args[0]} failed: ${result.stderr}`);
  return result.stdout.trim();
}

function cliJson(args, input) {
  return JSON.parse(cli(args, input));
}

function retrieveWithCli(storePath, question) {
  return cliJson([
    "retrieve",
    "--store",
    storePath,
    "--question",
    question,
    "--max-hits",
    "8",
  ]);
}

function resolveWithCli(storePath, reference) {
  return cliJson(
    ["resolve-evidence", "--store", storePath, "--reference-file", "-"],
    `${JSON.stringify(reference)}\n`,
  );
}

function structured(result) {
  assert.ok(result && typeof result === "object");
  assert.equal(result.structuredContent === undefined, false, "tool result must be structured");
  if (result.isError !== true) {
    assert.equal(result.content.length, 1, "successful tool result must contain one text block");
    assert.equal(result.content[0].type, "text", "successful tool content must be text");
    assert.deepEqual(
      JSON.parse(result.content[0].text),
      result.structuredContent,
      "text-only hosts must receive the complete structured result",
    );
  }
  return result.structuredContent;
}

function assertNoStorePath(value, storePath) {
  assert.equal(JSON.stringify(value).includes(storePath), false, "MCP output must not expose the configured store path");
}

function toolText(result) {
  return result.content?.find((part) => part.type === "text")?.text ?? "";
}

async function treeSnapshot(root) {
  const files = [];
  async function visit(directory, prefix = "") {
    for (const entry of (await readdir(directory, { withFileTypes: true })).sort((a, b) =>
      a.name.localeCompare(b.name),
    )) {
      const absolute = join(directory, entry.name);
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        await visit(absolute, relative);
      } else {
        assert.ok(entry.isFile(), `unexpected non-regular store entry ${relative}`);
        const bytes = await readFile(absolute);
        files.push({
          path: relative,
          bytes: bytes.length,
          sha256: createHash("sha256").update(bytes).digest("hex"),
        });
      }
    }
  }
  await visit(root);
  return { files, sha256: createHash("sha256").update(JSON.stringify(files)).digest("hex") };
}

async function childNetworkSocketDescriptors(pid) {
  const fdRoot = `/proc/${pid}/fd`;
  const descriptors = await readdir(fdRoot);
  const targets = await Promise.all(
    descriptors.map(async (fd) => {
      try {
        return await readlink(join(fdRoot, fd));
      } catch {
        return "closed";
      }
    }),
  );
  const unixTable = await readFile(`/proc/${pid}/net/unix`, "utf8");
  const unixInodes = new Set(
    unixTable
      .trim()
      .split("\n")
      .slice(1)
      .map((line) => line.trim().split(/\s+/)[6]),
  );
  return targets.filter((target) => {
    const match = /^socket:\[(\d+)\]$/.exec(target);
    return match && !unixInodes.has(match[1]);
  });
}

function createTransport(Transport, storePath) {
  const transport = new Transport({
    command: binary,
    args: ["mcp", "--store", storePath],
    stderr: "pipe",
    maxBufferSize: 2 * 1024 * 1024,
  });
  let stderr = "";
  transport.stderr?.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });
  return { transport, getStderr: () => stderr };
}

async function connectModern(storePath) {
  const { transport, getStderr } = createTransport(ModernStdio, storePath);
  const client = new ModernClient(
    { name: "ley-mcp-acceptance-modern", version: "1.0.0" },
    { versionNegotiation: { mode: "auto", probe: { timeoutMs: 5000 } } },
  );
  let cancelNextToolCall;
  const send = transport.send.bind(transport);
  transport.send = async (message, options) => {
    await send(message, options);
    if (cancelNextToolCall && message.method === "tools/call") {
      const controller = cancelNextToolCall;
      cancelNextToolCall = undefined;
      await client.notification({
        method: "notifications/cancelled",
        params: { requestId: message.id, reason: "offline acceptance cancellation check" },
      });
      controller.abort();
    }
  };
  await client.connect(transport);
  return {
    client,
    transport,
    getStderr,
    cancelNextToolCall(controller) {
      cancelNextToolCall = controller;
    },
  };
}

async function connectLegacy(storePath) {
  const { transport, getStderr } = createTransport(LegacyStdio, storePath);
  const client = new LegacyClient({ name: "ley-mcp-acceptance-legacy", version: "1.0.0" });
  await client.connect(transport);
  return { client, transport, getStderr };
}

async function timed(name, operation) {
  const started = performance.now();
  const value = await operation();
  timings.push({ operation: name, elapsed_ms: Number((performance.now() - started).toFixed(3)) });
  return value;
}

function assertNoStoreConfiguration(tools) {
  const description = JSON.stringify(tools);
  assert.doesNotMatch(description, /store_path|storePath|filesystem path/i);
  assert.doesNotMatch(description, /"format"\s*:/, "tool schemas should use portable JSON Schema keywords");
  assert.equal(tools.length, 3);
  assert.deepEqual(
    tools.map((tool) => tool.name).sort(),
    ["resolve_evidence", "search_evidence", "source_transparency"],
  );
  for (const tool of tools) {
    assert.equal(tool.outputSchema?.type, "object");
    assert.equal(tool.annotations?.readOnlyHint, true);
    assert.equal(tool.annotations?.destructiveHint, false);
    assert.equal(tool.annotations?.idempotentHint, true);
    assert.equal(tool.annotations?.openWorldHint, false);
    assert.ok(!JSON.stringify(tool.inputSchema).includes("store_path"));
    assert.ok(!JSON.stringify(tool.inputSchema).includes("storePath"));
  }
}

async function mustResolveError(client, reference, expectedCode) {
  const result = await client.callTool({ name: "resolve_evidence", arguments: reference });
  assert.equal(result.isError, true);
  assert.deepEqual(structured(result), { error: expectedCode });
  assert.equal(toolText(result).includes(expectedCode), true);
}

let modern;
let legacy;
let secondModern;
let finalReport;

try {
  await mkdir(source, { recursive: false });
  await writeFile(
    join(source, "harbor.html"),
    "<!doctype html><html><head><title>Harbor Guide</title></head><body><p>The keeper at Harbor Bay tends the blue lantern each evening. The harbor café opens at dawn.</p></body></html>",
    "utf8",
  );
  await writeFile(
    join(source, "unchanged.html"),
    "<!doctype html><html><head><title>Quay Notes</title></head><body><p>A copper bell rings at noon above the quay.</p></body></html>",
    "utf8",
  );
  await writeFile(
    join(source, "deleted.html"),
    "<!doctype html><html><head><title>Inlet Map</title></head><body><p>The cedar bridge crosses the north inlet.</p></body></html>",
    "utf8",
  );
  const prefix = "https://fixture.example.invalid/ley-mcp/";
  cli(["local-collection", "init", "--store", store, "--directory", source, "--url-prefix", prefix]);
  cli([
    "local-collection",
    "init",
    "--store",
    otherStore,
    "--directory",
    source,
    "--url-prefix",
    "https://other.example.invalid/ley-mcp/",
  ]);
  const beforeModern = await treeSnapshot(store);

  modern = await connectModern(store);
  const discovered = modern.client.getDiscoverResult();
  assert.ok(discovered, "modern client must negotiate with server/discover");
  assert.equal(JSON.stringify(discovered).includes("2026-07-28"), true);
  assertNoStorePath(discovered, store);
  assert.equal(modern.client.getServerVersion()?.name, "ley");
  const modernTools = (await timed("modern tools/list", () => modern.client.listTools())).tools;
  assertNoStoreConfiguration(modernTools);
  record("modern server/discover and tools/list", "2026-07-28; three read-only tools");

  const question = "Which café keeps the blue lantern at Harbor Bay?";
  const searchResult = await timed("modern search_evidence", () =>
    modern.client.callTool({
      name: "search_evidence",
      arguments: { question, max_hits: 8 },
    }),
  );
  const searchValue = structured(searchResult);
  assertNoStorePath(searchValue, store);
  assert.deepEqual(searchValue, retrieveWithCli(store, question));
  assert.equal(searchValue.answer_assessment, "not_assessed");
  assert.ok(searchValue.hits.some((hit) => hit.passage.text.includes("blue lantern")));
  assert.equal(searchResult.isError, false);
  record("ordinary question parity", "structured MCP response equals the existing retrieve CLI JSON");

  const harborHit = searchValue.hits.find((hit) => hit.requested_url.endsWith("harbor.html"));
  assert.ok(harborHit, "expected the authored Harbor Guide hit");
  const harborReference = harborHit.passage.reference;
  const sourceValue = structured(
    await timed("modern source_transparency", () =>
      modern.client.callTool({
        name: "source_transparency",
        arguments: harborReference,
      }),
    ),
  );
  assert.deepEqual(sourceValue.reference, harborReference);
  assert.equal(sourceValue.requested_url, harborHit.requested_url);
  assert.deepEqual(sourceValue.source, { kind: "local_index" });
  record("exact source lookup", "MCP source metadata is bound to a current reference and local index");

  const resolutionResult = await timed("modern resolve_evidence", () =>
    modern.client.callTool({
      name: "resolve_evidence",
      arguments: harborReference,
    }),
  );
  const resolutionValue = structured(resolutionResult);
  assertNoStorePath(resolutionValue, store);
  assert.deepEqual(resolutionValue, resolveWithCli(store, harborReference));
  assert.equal(resolutionValue.text, harborHit.passage.text);
  assert.deepEqual(resolutionValue.reference, harborReference);
  record("exact reference parity", "resolved passage bytes and reference equal the retrieve CLI contract");

  const unchangedValue = retrieveWithCli(store, "What rings above the quay at noon?");
  const unchangedHit = unchangedValue.hits.find((hit) => hit.requested_url.endsWith("unchanged.html"));
  assert.ok(unchangedHit, "expected the authored Quay Notes hit");
  const unchangedReference = unchangedHit.passage.reference;
  const deletedValue = retrieveWithCli(store, "Where does the cedar bridge cross?");
  const deletedHit = deletedValue.hits.find((hit) => hit.requested_url.endsWith("deleted.html"));
  assert.ok(deletedHit, "expected the authored Inlet Map hit");
  const deletedReference = deletedHit.passage.reference;
  const otherReference = retrieveWithCli(otherStore, question).hits[0].passage.reference;

  await mustResolveError(modern.client, { ...harborReference, end_byte: harborReference.end_byte + 1 }, "malformed_reference");
  await mustResolveError(modern.client, otherReference, "wrong_store");
  const noMatch = structured(
    await modern.client.callTool({
      name: "search_evidence",
      arguments: { question: "quasar zither 90017", max_hits: 8 },
    }),
  );
  assert.equal(noMatch.status, "no_relevant_text_match");
  assert.deepEqual(noMatch.hits, []);
  const tooLong = await modern.client.callTool({
    name: "search_evidence",
    arguments: { question: "x".repeat(4097) },
  });
  assert.equal(tooLong.isError, true);
  assert.deepEqual(structured(tooLong), { error: "invalid_request" });
  const invalidLimit = await modern.client.callTool({
    name: "search_evidence",
    arguments: { question, max_hits: 0 },
  }).catch((error) => ({ clientRejected: true, error }));
  if (invalidLimit.clientRejected) {
    record("max_hits lower bound", "official client rejected 0 from inputSchema before sending");
  } else {
    assert.equal(invalidLimit.isError, true);
    assert.deepEqual(structured(invalidLimit), { error: "invalid_request" });
  }
  const tooManyHits = await modern.client.callTool({
    name: "search_evidence",
    arguments: { question, max_hits: 9 },
  }).catch((error) => ({ clientRejected: true, error }));
  if (tooManyHits.clientRejected) {
    record("max_hits upper bound", "official client rejected 9 from inputSchema before sending");
  } else {
    assert.equal(tooManyHits.isError, true);
    assert.deepEqual(structured(tooManyHits), { error: "invalid_request" });
  }
  let unknownToolRejected = false;
  try {
    await modern.client.callTool({ name: "not_a_ley_tool", arguments: {} });
  } catch {
    unknownToolRejected = true;
  }
  assert.equal(unknownToolRejected, true, "unknown tool calls must fail at the MCP boundary");
  const cancellationController = new AbortController();
  modern.cancelNextToolCall(cancellationController);
  const cancellationResult = await modern.client.callTool(
    {
      name: "search_evidence",
      arguments: { question: "What does the keeper tend at Harbor Bay?" },
    },
    { signal: cancellationController.signal },
  ).then(
    () => ({ cancelled: false }),
    (error) => ({ cancelled: true, error }),
  );
  assert.equal(cancellationResult.cancelled, true);
  const afterCancellation = structured(
    await modern.client.callTool({
      name: "search_evidence",
      arguments: { question, max_hits: 8 },
    }),
  );
  assert.deepEqual(afterCancellation, retrieveWithCli(store, question));
  const temporarilyUnavailable = join(runRoot, "temporarily-unavailable-store");
  await rename(store, temporarilyUnavailable);
  let unavailableResult;
  try {
    unavailableResult = await modern.client.callTool({
      name: "search_evidence",
      arguments: { question },
    });
  } finally {
    await rename(temporarilyUnavailable, store);
  }
  assert.equal(unavailableResult.isError, true);
  assert.deepEqual(structured(unavailableResult), { error: "storage_fault" });
  assert.deepEqual(structured(await modern.client.callTool({
    name: "search_evidence",
    arguments: { question },
  })), retrieveWithCli(store, question));
  const networkSockets = await childNetworkSocketDescriptors(modern.transport.pid);
  assert.deepEqual(networkSockets, [], "MCP child should not keep any IP network sockets open");
  const afterModernReads = await treeSnapshot(store);
  assert.deepEqual(afterModernReads, beforeModern, "MCP calls must not change store files");
  record("bounded inputs, invalidation errors, no-match, UTF-8, cancellation, store-unavailable recovery, and read-only state", "passed");

  await writeFile(
    join(source, "harbor.html"),
    "<!doctype html><html><head><title>Harbor Guide Updated</title></head><body><p>The keeper at Harbor Bay tends a green beacon at dawn. The harbor café opens at dawn.</p></body></html>",
    "utf8",
  );
  await rm(join(source, "deleted.html"));
  cli(["local-collection", "sync", "--store", store, "--directory", source, "--url-prefix", prefix]);
  const afterOperatorSync = await treeSnapshot(store);

  await mustResolveError(modern.client, harborReference, "version_superseded");
  await mustResolveError(modern.client, deletedReference, "not_live");
  const unchangedResolved = structured(
    await modern.client.callTool({
      name: "resolve_evidence",
      arguments: unchangedReference,
    }),
  );
  assert.equal(unchangedResolved.text, unchangedHit.passage.text);
  assert.deepEqual(unchangedResolved.reference, unchangedReference);
  const updatedQuestion = "green beacon dawn";
  const updatedResult = structured(
    await modern.client.callTool({
      name: "search_evidence",
      arguments: { question: updatedQuestion },
    }),
  );
  assert.deepEqual(updatedResult, retrieveWithCli(store, updatedQuestion));
  const updatedHit = updatedResult.hits.find((hit) => hit.requested_url.endsWith("harbor.html"));
  assert.ok(updatedHit?.passage.text.includes("green beacon"));
  const updatedResolution = structured(
    await modern.client.callTool({
      name: "resolve_evidence",
      arguments: updatedHit.passage.reference,
    }),
  );
  assert.deepEqual(updatedResolution, resolveWithCli(store, updatedHit.passage.reference));
  assert.equal(updatedResolution.text, updatedHit.passage.text);
  assert.deepEqual(await treeSnapshot(store), afterOperatorSync, "post-sync MCP calls must stay read-only");
  record("live freshness without server restart", "unchanged valid; changed superseded; deleted not_live");

  await modern.client.close();
  const modernStderr = modern.getStderr();
  assert.equal(modernStderr, "", "MCP server must not write startup banners or document data to stderr");
  record("stdout and stderr discipline", "official client parsed protocol-only stdout; server stderr was empty");
  modern = undefined;

  legacy = await connectLegacy(store);
  const legacyTools = (await legacy.client.listTools()).tools;
  assertNoStoreConfiguration(legacyTools);
  const legacyResult = await legacy.client.callTool({
    name: "search_evidence",
    arguments: { question: updatedQuestion, max_hits: 8 },
  });
  assert.deepEqual(structured(legacyResult), retrieveWithCli(store, updatedQuestion));
  record("2025 legacy initialize/initialized/tools/list/tools/call", "official TypeScript SDK v1.32.1 passed");
  await legacy.client.close();
  assert.equal(legacy.getStderr(), "");
  legacy = undefined;

  secondModern = await connectModern(store);
  const restarted = structured(
    await secondModern.client.callTool({
      name: "search_evidence",
      arguments: { question: updatedQuestion },
    }),
  );
  assert.deepEqual(restarted, retrieveWithCli(store, updatedQuestion));
  assert.deepEqual(await treeSnapshot(store), afterOperatorSync);
  const restartedNetworkSockets = await childNetworkSocketDescriptors(secondModern.transport.pid);
  assert.deepEqual(restartedNetworkSockets, []);
  await secondModern.client.close();
  assert.equal(secondModern.getStderr(), "");
  secondModern = undefined;
  record("EOF/close and restart", "fresh modern client connected and queried the operator-synced store");

  finalReport = {
    result: "PASS",
    server: {
      package: "ley",
      version: "0.1.0",
      sdk: "rmcp 3.6.0",
      rust: "1.88.0",
    },
    clients: {
      modern: "@modelcontextprotocol/client 2.3.1, versionNegotiation=auto, 2026-07-28",
      legacy: "@modelcontextprotocol/sdk 1.32.1, initialize 2025 era",
      node: process.version,
    },
    fixture: "authored UTF-8 HTML, offline managed local collection",
    store_before_calls: beforeModern,
    store_after_operator_sync: afterOperatorSync,
    store_after_final_calls: await treeSnapshot(store),
    timings,
    checks,
  };
  await writeFile(reportPath, `${JSON.stringify(finalReport, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ result: "PASS", report: reportPath, checks: checks.length })}\n`);
} catch (error) {
  await Promise.allSettled(
    [modern, legacy, secondModern]
      .filter(Boolean)
      .map(async ({ client }) => client.close()),
  );
  const failure = {
    result: "FAIL",
    message: error instanceof Error ? error.stack : String(error),
    timings,
    checks,
  };
  await writeFile(reportPath, `${JSON.stringify(failure, null, 2)}\n`, "utf8");
  throw error;
}
