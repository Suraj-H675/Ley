import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { access, mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { connect, createServer } from "node:net";
import { once } from "node:events";
import { PassThrough } from "node:stream";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(uiRoot, "..");
const scratch = process.env.LEY_E2E_STORE_PATH
  ? undefined
  : await mkdtemp(path.join(tmpdir(), "ley-http-e2e-store-"));
const storePath = process.env.LEY_E2E_STORE_PATH
  ? path.resolve(process.env.LEY_E2E_STORE_PATH)
  : path.join(scratch, "index");
const artifactDirectoryProvided = process.env.LEY_E2E_ARTIFACT_DIR !== undefined;
const artifacts = artifactDirectoryProvided
  ? path.resolve(process.env.LEY_E2E_ARTIFACT_DIR)
  : await mkdtemp(path.join(tmpdir(), "ley-http-e2e-browser-"));
const children = [];
let browser;
const RAW_HTTP_TIMEOUT_MS = 4000;

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { ...options, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve(stdout.trim());
      else reject(new Error(`${command} ${args.join(" ")} exited ${code}\n${stdout}\n${stderr}`));
    });
  });
}

async function freePort() {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return address.port;
}

async function selectedPort(name) {
  if (process.env[name] === undefined) return freePort();
  const port = Number(process.env[name]);
  assert.ok(Number.isInteger(port) && port > 0 && port <= 65535, `${name} must be a valid TCP port`);
  return port;
}

function start(command, args, options = {}) {
  const child = spawn(command, args, { ...options, stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr = `${stderr}${chunk}`.slice(-8192); });
  children.push(child);
  return { child, get stderr() { return stderr; } };
}

async function waitForHttp(url) {
  let lastError;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1000) });
      if (response.ok) return;
      lastError = new Error(`readiness returned HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`local server did not become ready at ${url}: ${lastError}`);
}

function createRawResponseReader(socket, timeoutMs = RAW_HTTP_TIMEOUT_MS) {
  let buffered = Buffer.alloc(0);
  let wakeReader;
  let socketError;
  let socketEnded = false;
  let socketClosed = false;
  const wake = () => {
    wakeReader?.();
  };
  socket.on("data", (chunk) => {
    buffered = Buffer.concat([buffered, chunk]);
    wake();
  });
  socket.on("error", (error) => {
    socketError = error;
    wake();
  });
  socket.on("end", () => {
    socketEnded = true;
    wake();
  });
  socket.on("close", () => {
    socketClosed = true;
    wake();
  });
  async function waitFor(predicate, deadline, stage) {
    while (!predicate()) {
      if (socketError) throw socketError;
      if (socketEnded || socketClosed) {
        throw new Error(`local HTTP socket closed before the complete ${stage}`);
      }
      const remainingMs = deadline - Date.now();
      if (remainingMs <= 0) throw new Error(`local HTTP response deadline expired during ${stage}`);
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          if (wakeReader === onWake) wakeReader = undefined;
          reject(new Error(`local HTTP response deadline expired during ${stage}`));
        }, remainingMs);
        const onWake = () => {
          clearTimeout(timer);
          if (wakeReader === onWake) wakeReader = undefined;
          resolve();
        };
        wakeReader = onWake;
        if (predicate() || socketError || socketEnded || socketClosed) onWake();
      });
    }
  }

  return {
    socket,
    dispose() {
      socket.destroy();
    },
    async readResponse() {
      const deadline = Date.now() + timeoutMs;
      await waitFor(() => buffered.indexOf("\r\n\r\n") >= 0, deadline, "response headers");
      const boundary = buffered.indexOf("\r\n\r\n");
      const header = buffered.subarray(0, boundary).toString("latin1");
      const lengthLine = header.split("\r\n").find((line) => /^content-length:/i.test(line));
      assert.ok(lengthLine, `response lacks bounded Content-Length: ${header}`);
      const bodyLength = Number(lengthLine.split(":", 2)[1].trim());
      assert.ok(Number.isSafeInteger(bodyLength) && bodyLength >= 0 && bodyLength <= 1024 * 1024);
      const bodyStart = boundary + 4;
      await waitFor(() => buffered.length >= bodyStart + bodyLength, deadline, "response body");
      const status = Number(header.split("\r\n", 1)[0].split(" ", 2)[1]);
      const body = buffered.subarray(bodyStart, bodyStart + bodyLength).toString("utf8");
      buffered = buffered.subarray(bodyStart + bodyLength);
      return { status, header, body };
    },
  };
}

async function connectRaw(port, timeoutMs = RAW_HTTP_TIMEOUT_MS) {
  const socket = connect(port, "127.0.0.1");
  const reader = createRawResponseReader(socket, timeoutMs);
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("local HTTP connection timed out"));
    }, timeoutMs);
    const onError = (error) => {
      clearTimeout(timer);
      reject(error);
    };
    socket.once("error", onError);
    socket.once("connect", () => {
      clearTimeout(timer);
      socket.removeListener("error", onError);
      resolve();
    });
  });
  socket.setTimeout(RAW_HTTP_TIMEOUT_MS, () => socket.destroy(new Error("local HTTP response timed out")));
  return reader;
}

async function verifyRawReaderFailures() {
  const eofSocket = new PassThrough();
  const eofReader = createRawResponseReader(eofSocket);
  const eofResponse = eofReader.readResponse();
  eofSocket.end();
  await assert.rejects(eofResponse, /closed before the complete response headers/);
  eofReader.dispose();

  const truncatedSocket = new PassThrough();
  const truncatedReader = createRawResponseReader(truncatedSocket);
  const truncatedResponse = truncatedReader.readResponse();
  truncatedSocket.write("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nxy");
  truncatedSocket.end();
  await assert.rejects(truncatedResponse, /closed before the complete response body/);
  truncatedReader.dispose();

  const timeoutReader = createRawResponseReader(new PassThrough(), 50);
  await assert.rejects(timeoutReader.readResponse(), /deadline expired during response headers/);
  timeoutReader.dispose();

  const errorSocket = new PassThrough();
  const errorReader = createRawResponseReader(errorSocket);
  const errorResponse = errorReader.readResponse();
  errorSocket.destroy(new Error("owned raw-socket error check"));
  await assert.rejects(errorResponse, /owned raw-socket error check/);
  errorReader.dispose();
  console.log("Raw HTTP EOF, truncated-body, socket-error, and deadline checks passed.");
}

async function chromiumExecutable() {
  if (process.env.CHROMIUM_EXECUTABLE) return process.env.CHROMIUM_EXECUTABLE;
  const base = path.join(homedir(), ".cache/ms-playwright");
  const entries = await readdir(base);
  const candidates = [];
  for (const entry of entries.sort().reverse()) {
    if (entry.startsWith("chromium_headless_shell-")) {
      candidates.push(path.join(base, entry, "chrome-headless-shell-linux64/chrome-headless-shell"));
    }
    if (entry.startsWith("chromium-")) {
      candidates.push(path.join(base, entry, "chrome-linux64/chrome"));
      candidates.push(path.join(base, entry, "chrome-linux/chrome"));
    }
  }
  for (const candidate of candidates) {
    try {
      await import("node:fs/promises").then(({ access }) => access(candidate));
      return candidate;
    } catch {
      continue;
    }
  }
  throw new Error("No local Chromium binary found. Set CHROMIUM_EXECUTABLE to a local browser path.");
}

async function measuredSmallTextContrast(page) {
  return page.evaluate(() => {
    function rgb(value) {
      const components = value.match(/[\d.]+/g)?.map(Number);
      if (!components || components.length < 3) return null;
      return [components[0], components[1], components[2], components[3] ?? 1];
    }
    function blend(foreground, background) {
      const alpha = foreground[3];
      return [0, 1, 2].map((index) => foreground[index] * alpha + background[index] * (1 - alpha)).concat(1);
    }
    function luminance(color) {
      const linear = color.slice(0, 3).map((channel) => {
        const value = channel / 255;
        return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
    }
    function backgroundFor(element) {
      const layers = [];
      for (let node = element; node; node = node.parentElement) {
        const color = rgb(getComputedStyle(node).backgroundColor);
        if (color && color[3] > 0) layers.push(color);
      }
      let background = [255, 255, 255, 1];
      for (const layer of layers.reverse()) background = blend(layer, background);
      return background;
    }
    const selectors = [
      ".eyebrow", ".intro", ".query-hint", ".field-error", ".masthead-note", ".result-meta",
      ".results-summary", ".question-metadata", ".candidate-disclaimer", ".partial-notice",
      ".result-url", ".unsafe-url", ".candidate-label", ".effective-url", ".passage-heading",
      ".evidence-passage", ".verification-message", ".evidence-matches", ".evidence-actions",
      ".reference-details", ".page-footer", ".page-footer a", ".error-panel p",
    ];
    const measurements = [];
    for (const selector of selectors) {
      for (const element of document.querySelectorAll(selector)) {
        const style = getComputedStyle(element);
        if (Number.parseFloat(style.fontSize) > 18 || element.getClientRects().length === 0) continue;
        const foreground = rgb(style.color);
        const background = backgroundFor(element);
        if (!foreground || !background) continue;
        const colors = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
        measurements.push({ selector, ratio: (colors[0] + 0.05) / (colors[1] + 0.05) });
      }
    }
    return measurements;
  });
}

async function stopChildren() {
  for (const child of children) {
    if (child.exitCode !== null || child.signalCode !== null) continue;
    child.kill("SIGTERM");
  }
  await Promise.all(children.map(async (child) => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    await Promise.race([
      once(child, "exit"),
      new Promise((resolve) => setTimeout(resolve, 3000)),
    ]);
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  }));
}

try {
  if (artifactDirectoryProvided) await mkdir(artifacts);
  await verifyRawReaderFailures();
  await run("cargo", ["build", "--locked", "--offline", "--bin", "ley"], { cwd: repoRoot });
  await run("npm", ["run", "build"], { cwd: uiRoot });
  const ley = path.join(repoRoot, "target", "debug", "ley");
  const questions = [
    "How should ordinary questions differ from advanced Boolean queries?",
    "How do UTF-8 byte offsets handle Crème brûlée?",
    "What does " + String.fromCharCode(96) + "resolve_evidence" + String.fromCharCode(96) + " validate?",
    "Does retrieval guarantee that every lexical match answers a question?",
    "How should the browser render hostile HTML looking text?",
  ];
  const noMatchQuestion = "What is quartzmonolith?";
  const emptyBodyQuestion = "What is qzemptytitle?";
  let storeExists = true;
  try {
    await access(storePath);
  } catch {
    storeExists = false;
  }
  if (storeExists) {
    assert.equal(process.env.LEY_E2E_REUSE_STORE, "1", "refusing to reuse a store without explicit opt-in");
  } else {
    const ingest = await run(ley, [
      "ingest-html", "--store", storePath,
      "--directory", path.join(repoRoot, "fixtures/m3-guide-v1/html"),
      "--url-prefix", "https://docs.example.invalid/ley-m3-guide-v1/",
    ], { cwd: repoRoot });
    assert.match(ingest, /Imported 11 local HTML documents, skipped 1 noindex documents/);
  }

  const cliQuestionByText = new Map();
  for (const question of [...questions, noMatchQuestion, emptyBodyQuestion]) {
    const value = JSON.parse(await run(ley, ["retrieve", "--store", storePath, "--question", question], { cwd: repoRoot }));
    assert.equal(value.contract_version, 1);
    assert.equal(value.mode, "question");
    assert.equal(value.answer_assessment, "not_assessed");
    assert.ok(["complete", "partial"].includes(value.completeness));
    if (question !== noMatchQuestion && question !== emptyBodyQuestion) assert.ok(value.hits.length > 0, "the authored guide should retrieve passages for " + question);
    cliQuestionByText.set(question, value);
  }
  assert.equal(cliQuestionByText.get(noMatchQuestion).status, "no_relevant_text_match");
  assert.equal(cliQuestionByText.get(emptyBodyQuestion).status.insufficient_evidence, "only_title_matches");
  assert.equal(cliQuestionByText.get(emptyBodyQuestion).hits.length, 0);
  assert.equal(cliQuestionByText.get(questions[1]).hits[0].passage.text.includes("Crème brûlée"), true);
  assert.ok(cliQuestionByText.get(questions[2]).hits[0].matched_phrases.length > 0);
  assert.equal(cliQuestionByText.get(questions[3]).answer_assessment, "not_assessed");

  const dslQueries = ["retrieval AND evidence", "\"Crème brûlée\"", "resolve_evidence"];
  const cliByQuery = new Map();
  for (const query of dslQueries) {
    const value = JSON.parse(await run(ley, ["search", "--store", storePath, "--query", query], { cwd: repoRoot }));
    assert.ok(value.results.length > 0, "legacy DSL query should find guide text: " + query);
    cliByQuery.set(query, value);
  }

  const apiPort = await selectedPort("LEY_E2E_API_PORT");
  const uiPort = await selectedPort("LEY_E2E_UI_PORT");
  const uiOrigin = "http://127.0.0.1:" + uiPort;
  const apiOrigin = "http://127.0.0.1:" + apiPort;
  let apiServer = start(ley, ["serve", "--store", storePath, "--bind", "127.0.0.1:" + apiPort], { cwd: repoRoot });
  const uiServer = start("node", ["scripts/dev-server.mjs"], {
    cwd: uiRoot,
    env: { ...process.env, LEY_UI_PORT: String(uiPort), LEY_API_PORT: String(apiPort) },
  });
  await waitForHttp(apiOrigin + "/api/health");
  await waitForHttp(uiOrigin);

  async function typedPost(origin, route, body, extraHeaders = {}) {
    return fetch(origin + route, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        origin,
        ...extraHeaders,
      },
      body: typeof body === "string" ? body : JSON.stringify(body),
    });
  }

  const apiQuestionByText = new Map();
  for (const question of [...questions, noMatchQuestion, emptyBodyQuestion]) {
    const request = {
      mode: "question",
      request: { contract_version: 1, question, max_hits: 8 },
    };
    const response = await typedPost(apiOrigin, "/api/v1/retrieve", request);
    assert.equal(response.status, 200);
    assert.match(response.headers.get("cache-control") ?? "", /no-store/i);
    const value = await response.json();
    assert.deepEqual(value, cliQuestionByText.get(question), "CLI/API question response parity: " + question);
    apiQuestionByText.set(question, value);
  }

  const initialReference = apiQuestionByText.get(questions[0]).hits[0].passage.reference;
  const referenceFile = path.join(artifacts, "evidence-reference.json");
  await writeFile(referenceFile, JSON.stringify(initialReference, null, 2));
  const cliResolution = JSON.parse(await run(ley, [
    "resolve-evidence", "--store", storePath, "--reference-file", referenceFile,
  ], { cwd: repoRoot }));
  const resolutionResponse = await typedPost(apiOrigin, "/api/v1/evidence/resolve", initialReference);
  assert.equal(resolutionResponse.status, 200);
  assert.match(resolutionResponse.headers.get("cache-control") ?? "", /no-store/i);
  const apiResolution = await resolutionResponse.json();
  assert.deepEqual(apiResolution, cliResolution, "CLI/API evidence resolver parity");
  assert.deepEqual(apiResolution.reference, initialReference);
  assert.equal(apiResolution.text, apiQuestionByText.get(questions[0]).hits[0].passage.text);

  const stopped = once(apiServer.child, "exit");
  apiServer.child.kill("SIGTERM");
  await stopped;
  apiServer = start(ley, ["serve", "--store", storePath, "--bind", "127.0.0.1:" + apiPort], { cwd: repoRoot });
  await waitForHttp(apiOrigin + "/api/health");
  const afterRestart = await typedPost(apiOrigin, "/api/v1/evidence/resolve", initialReference);
  assert.equal(afterRestart.status, 200);
  assert.deepEqual(await afterRestart.json(), cliResolution, "the same reference survives a fresh API process");

  const apiByQuery = new Map();
  for (const query of dslQueries) {
    const response = await fetch(apiOrigin + "/api/search?q=" + encodeURIComponent(query), {
      headers: { accept: "application/json" },
    });
    assert.equal(response.status, 200);
    const value = await response.json();
    assert.deepEqual(value, cliByQuery.get(query), "legacy CLI/API DSL parity: " + query);
    apiByQuery.set(query, value);
  }

  async function expectTypedError(route, body, status, code, headers = {}) {
    const response = await typedPost(apiOrigin, route, body, headers);
    assert.equal(response.status, status);
    assert.match(response.headers.get("cache-control") ?? "", /no-store/i);
    const bytes = await response.text();
    assert.ok(Buffer.byteLength(bytes) <= 1024);
    assert.equal(JSON.parse(bytes).error, code);
    assert.doesNotMatch(bytes, /Crème brûlée|ordinary questions and lexical candidates/i);
  }

  async function expectChunkedBodyLimit(port, target) {
    const socket = await connectRaw(port);
    try {
      const origin = "http://127.0.0.1:" + port;
      const chunk = "x".repeat(8192);
      const chunkedBody = [chunk, chunk, "x"].map((part) =>
        Buffer.byteLength(part).toString(16) + "\r\n" + part + "\r\n",
      ).join("") + "0\r\n\r\n";
      socket.socket.write(
        "POST " + target + " HTTP/1.1\r\n" +
        "Host: 127.0.0.1:" + port + "\r\n" +
        "Origin: " + origin + "\r\n" +
        "Content-Type: application/json\r\nAccept: application/json\r\n" +
        "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n" + chunkedBody,
      );
      const response = await socket.readResponse();
      assert.equal(response.status, 413);
      assert.match(response.header, /cache-control: no-store/i);
      assert.equal(JSON.parse(response.body).error, "resource_cap");
      assert.doesNotMatch(response.body, /Crème brûlée|ordinary questions and lexical candidates/i);
    } finally {
      socket.dispose();
    }
  }

  const validRequest = { mode: "question", request: { contract_version: 1, question: questions[0], max_hits: 8 } };
  const missingOrigin = await fetch(apiOrigin + "/api/v1/retrieve", {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify(validRequest),
  });
  assert.equal(missingOrigin.status, 403);
  assert.equal((await missingOrigin.json()).error, "invalid_origin");
  await expectTypedError("/api/v1/retrieve", validRequest, 403, "invalid_origin", { origin: "http://attacker.invalid" });
  await expectTypedError("/api/v1/retrieve", validRequest, 415, "unsupported_media_type", { "content-type": "text/plain" });
  await expectTypedError("/api/v1/retrieve", validRequest, 406, "not_acceptable", { accept: "text/plain" });
  await expectTypedError(
    "/api/v1/retrieve",
    "{\"mode\":\"question\",\"request\":{\"contract_version\":1,\"question\":\"rust\",\"max_hits\":8,\"unknown\":true}}",
    400,
    "invalid_request",
  );
  await expectTypedError(
    "/api/v1/retrieve",
    "{\"mode\":\"question\",\"mode\":\"question\",\"request\":{\"contract_version\":1,\"question\":\"rust\",\"max_hits\":8}}",
    400,
    "invalid_request",
  );
  await expectTypedError(
    "/api/v1/retrieve",
    { mode: "question", request: { contract_version: 99, question: "rust", max_hits: 8 } },
    422,
    "unsupported_contract",
  );
  await expectTypedError(
    "/api/v1/retrieve",
    "x".repeat(16 * 1024 + 1),
    413,
    "resource_cap",
  );
  await expectChunkedBodyLimit(apiPort, "/api/v1/retrieve");

  const invalidReference = { ...initialReference, start_byte: initialReference.start_byte + 1 };
  await expectTypedError("/api/v1/evidence/resolve", invalidReference, 400, "malformed_reference");
  const getQuestion = await fetch(apiOrigin + "/api/v1/retrieve", { headers: { origin: apiOrigin } });
  assert.equal(getQuestion.status, 405);
  assert.equal(getQuestion.headers.get("allow"), "POST");

  const otherStore = path.join(artifacts, "wrong-store");
  await run(ley, [
    "ingest-html", "--store", otherStore,
    "--directory", path.join(repoRoot, "fixtures/m3-guide-v1/html"),
    "--url-prefix", "https://other.example.invalid/ley-m3-guide-v1/",
  ], { cwd: repoRoot });
  const otherRetrieval = JSON.parse(await run(ley, [
    "retrieve", "--store", otherStore, "--question", questions[0],
  ], { cwd: repoRoot }));
  await expectTypedError(
    "/api/v1/evidence/resolve",
    otherRetrieval.hits[0].passage.reference,
    404,
    "wrong_store",
  );

  const partialSource = path.join(artifacts, "partial-source");
  const partialStore = path.join(artifacts, "partial-index");
  await mkdir(partialSource);
  for (let index = 0; index < 33; index += 1) {
    await writeFile(path.join(partialSource, "page-" + index + ".html"),
      "<!doctype html><html><head><title>Partial fixture " + index +
      "</title></head><body>partialprobe appears in every bounded fixture document.</body></html>");
  }
  await run(ley, [
    "ingest-html", "--store", partialStore, "--directory", partialSource,
    "--url-prefix", "https://partial.example.invalid/probe/",
  ], { cwd: repoRoot });
  const partialQuestion = "What does partialprobe find?";
  const partialCli = JSON.parse(await run(ley, [
    "retrieve", "--store", partialStore, "--question", partialQuestion,
  ], { cwd: repoRoot }));
  assert.equal(partialCli.completeness, "partial");
  assert.equal(partialCli.status, "retrieved_text");
  assert.ok(partialCli.hits.length > 0);
  const partialApiPort = await selectedPort("LEY_E2E_PARTIAL_API_PORT");
  const partialUiPort = await selectedPort("LEY_E2E_PARTIAL_UI_PORT");
  const partialApiOrigin = "http://127.0.0.1:" + partialApiPort;
  const partialUiOrigin = "http://127.0.0.1:" + partialUiPort;
  const partialApiServer = start(ley, ["serve", "--store", partialStore, "--bind", "127.0.0.1:" + partialApiPort], { cwd: repoRoot });
  const partialUiServer = start("node", ["scripts/dev-server.mjs"], {
    cwd: uiRoot,
    env: { ...process.env, LEY_UI_PORT: String(partialUiPort), LEY_API_PORT: String(partialApiPort) },
  });
  await waitForHttp(partialApiOrigin + "/api/health");
  await waitForHttp(partialUiOrigin);
  const partialApiResponse = await typedPost(partialApiOrigin, "/api/v1/retrieve", {
    mode: "question", request: { contract_version: 1, question: partialQuestion, max_hits: 8 },
  });
  assert.equal(partialApiResponse.status, 200);
  const partialApi = await partialApiResponse.json();
  assert.deepEqual(partialApi, partialCli, "partial work budget CLI/API parity");
  await expectChunkedBodyLimit(partialUiPort, "/api/v1/retrieve");

  for (const [port, target] of [
    [apiPort, "/api/v1/retrieve"],
    [uiPort, "/api/v1/retrieve"],
  ]) {
    const socket = await connectRaw(port);
    try {
      const origin = "http://127.0.0.1:" + port;
      const body = JSON.stringify(validRequest);
      socket.socket.write(
        "POST " + target + " HTTP/1.1\r\n" +
        "Host: attacker.invalid:" + port + "\r\n" +
        "Origin: " + origin + "\r\n" +
        "Content-Type: application/json\r\nAccept: application/json\r\n" +
        "Content-Length: " + Buffer.byteLength(body) + "\r\nConnection: close\r\n\r\n" + body,
      );
      const denied = await socket.readResponse();
      assert.equal(denied.status, 403);
      assert.match(denied.header, /cache-control: no-store/i);
      assert.equal(JSON.parse(denied.body).error, "invalid_host");
      assert.doesNotMatch(denied.body, /Crème brûlée|ordinary questions and lexical candidates/i);
    } finally {
      socket.dispose();
    }
  }

  const browserRequests = [];
  const browserErrors = [];
  const browserResults = [];
  const screenshotPaths = [];
  browser = await chromium.launch({
    executablePath: await chromiumExecutable(),
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  page.on("request", (request) => browserRequests.push(request.url()));
  page.on("pageerror", (error) => browserErrors.push(error.message));
  await page.goto(uiOrigin);
  const input = page.getByRole("textbox", { name: "Ask a question about indexed documents" });
  assert.equal(await page.getByRole("radio", { name: "Question" }).isChecked(), true, "ordinary question mode is the default");
  await page.keyboard.press("Control+k");
  assert.equal(await input.evaluate((element) => document.activeElement === element), true, "Ctrl+K focuses the question box");
  for (const [questionIndex, question] of questions.entries()) {
    const expected = apiQuestionByText.get(question);
    const responsePromise = page.waitForResponse((response) => response.url().includes("/api/v1/retrieve"));
    await input.fill(question);
    await input.press("Enter");
    const response = await responsePromise;
    assert.equal(response.status(), 200);
    const body = await response.json();
    assert.deepEqual(body, expected, "real browser/API response parity: " + question);
    assert.equal(body.answer_assessment, "not_assessed");
    const cards = page.locator(".evidence-card");
    if (body.hits.length > 0) {
      await cards.first().waitFor();
      assert.equal(await cards.count(), body.hits.length);
      await page.waitForFunction((expectedUrls) => {
        const urls = [...document.querySelectorAll(".evidence-card .result-url")].map((element) => element.textContent);
        return urls.length === expectedUrls.length && urls.every((url, index) => url === expectedUrls[index]);
      }, body.hits.map((hit) => hit.requested_url));
      const card = cards.first();
      assert.equal((await card.locator(".result-title").textContent()).trim(), body.hits[0].title);
      assert.equal(await card.locator(".result-title img").count(), 0);
      if (question.includes("hostile HTML")) {
        assert.ok((await page.locator(".results-section").textContent()).includes("<img src=x onerror=alert(1)>"));
      }
      assert.equal((await card.locator(".evidence-passage").textContent()).trim(), body.hits[0].passage.text);
      assert.ok((await card.locator(".candidate-label").textContent()).includes("Lexical candidate"));
      assert.match(await page.locator(".question-metadata").textContent(), /not_assessed/);
      assert.deepEqual(
        await page.locator(".evidence-card .result-url").allTextContents(),
        body.hits.map((hit) => hit.requested_url),
      );
      const hrefs = await page.locator(".evidence-card a.result-url").evaluateAll((links) => links.map((link) => link.href));
      assert.ok(hrefs.every((href) => ["http:", "https:"].includes(new URL(href).protocol)));
      assert.equal(await page.locator(".results-section img,.results-section script,.results-section [onerror]").count(), 0);

      if (questionIndex === 0) {
        const resolvePromise = page.waitForResponse((candidate) => candidate.url().includes("/api/v1/evidence/resolve"));
        await card.getByRole("button", { name: "Revalidate passage" }).click();
        const resolvedResponse = await resolvePromise;
        assert.equal(resolvedResponse.status(), 200);
        assert.deepEqual(await resolvedResponse.json(), cliResolution);
        await card.locator(".evidence-passage").waitFor();
        assert.match(await card.locator(".passage-heading").textContent(), /current index state/);
        assert.equal((await card.locator(".evidence-passage").textContent()).trim(), cliResolution.text);
        await card.locator("summary", { hasText: "Provenance and reference" }).click();
        const referenceText = await card.locator(".reference-details").textContent();
        assert.match(referenceText, /Store ID/);
        assert.match(referenceText, /Extracted body UTF-8 bytes/);
      }

      if (questionIndex === 0) {
        for (const width of [1280, 700, 390, 320]) {
          await page.setViewportSize({ width, height: 900 });
          const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
          assert.ok(scrollWidth <= width, "question UI at " + width + "px overflowed to " + scrollWidth);
          const screenshot = path.join(artifacts, "question-" + questionIndex + "-" + width + ".png");
          await page.screenshot({ path: screenshot, fullPage: true });
          screenshotPaths.push(screenshot);
        }
      }
    } else {
      assert.equal(await cards.count(), 0);
    }
    browserResults.push({
      question,
      generation_id: body.generation_id,
      status: body.status,
      completeness: body.completeness,
      answer_assessment: body.answer_assessment,
      requested_urls: body.hits.map((hit) => hit.requested_url),
      passages: body.hits.map((hit) => hit.passage.text),
      references: body.hits.map((hit) => hit.passage.reference),
    });
  }

  const contrastResults = await measuredSmallTextContrast(page);
  const lowContrast = contrastResults.filter((measurement) => measurement.ratio < 4.5);
  assert.deepEqual(lowContrast, [], "visible small text should meet 4.5:1 contrast");

  const noMatchResponsePromise = page.waitForResponse((response) => response.url().includes("/api/v1/retrieve"));
  await input.fill(noMatchQuestion);
  await input.press("Enter");
  assert.equal((await noMatchResponsePromise).status(), 200);
  await page.locator(".empty-panel").waitFor();
  assert.match(await page.locator(".empty-panel").textContent(), /No passage text matched/);
  assert.match(await page.locator(".empty-panel").textContent(), /answer support is not assessed/);
  const emptyBodyPromise = page.waitForResponse((response) => response.url().includes("/api/v1/retrieve"));
  await input.fill(emptyBodyQuestion);
  await input.press("Enter");
  assert.equal((await emptyBodyPromise).status(), 200);
  await page.locator(".empty-panel").waitFor();
  assert.match(await page.locator(".empty-panel").textContent(), /Terms matched titles, but no passage text/);

  const advancedMode = page.getByRole("radio", { name: "Advanced DSL" });
  await advancedMode.check();
  const dslInput = page.getByRole("textbox", { name: "Enter an advanced Boolean or phrase query" });
  const dslQuestion = dslQueries[0];
  const dslResponsePromise = page.waitForResponse((response) => response.url().includes("/api/search?"));
  await dslInput.fill(dslQuestion);
  await dslInput.press("Enter");
  const dslResponse = await dslResponsePromise;
  assert.equal(dslResponse.status(), 200);
  const dslJson = await dslResponse.json();
  assert.deepEqual(dslJson, cliByQuery.get(dslQuestion));
  assert.equal(await page.locator(".result-card").count(), dslJson.results.length);

  await page.getByRole("radio", { name: "Question", exact: true }).check();
  const questionInput = page.getByRole("textbox", { name: "Ask a question about indexed documents" });
  await questionInput.fill("\"");
  await questionInput.press("Enter");
  await page.getByRole("alert").waitFor();
  assert.match(await page.getByRole("alert").textContent(), /not valid/);

  const partialPage = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  partialPage.on("request", (request) => browserRequests.push(request.url()));
  partialPage.on("pageerror", (error) => browserErrors.push(error.message));
  const partialInput = partialPage.getByRole("textbox", { name: "Ask a question about indexed documents" });
  await partialPage.goto(partialUiOrigin);
  const partialBrowserResponsePromise = partialPage.waitForResponse((response) => response.url().includes("/api/v1/retrieve"));
  await partialInput.fill(partialQuestion);
  await partialInput.press("Enter");
  const partialBrowserResponse = await partialBrowserResponsePromise;
  assert.equal(partialBrowserResponse.status(), 200);
  assert.deepEqual(await partialBrowserResponse.json(), partialCli, "partial work budget browser/API parity");
  assert.ok(await partialPage.locator(".partial-notice").isVisible());
  const partialScreenshot = path.join(artifacts, "partial-work-budget-1280.png");
  await partialPage.screenshot({ path: partialScreenshot, fullPage: true });
  screenshotPaths.push(partialScreenshot);

  await page.getByRole("radio", { name: "Question", exact: true }).check();
  const staleQuestionInput = page.getByRole("textbox", { name: "Ask a question about indexed documents" });
  const beforeSwitch = page.waitForResponse((response) => response.url().includes("/api/v1/retrieve"));
  await staleQuestionInput.fill(questions[0]);
  await staleQuestionInput.press("Enter");
  assert.equal((await beforeSwitch).status(), 200);
  const affectedCard = page.locator(".evidence-card").first();
  await affectedCard.waitFor();
  const originalText = await affectedCard.locator(".evidence-passage").textContent();
  const oldApi = apiServer.child;
  const oldApiStopped = once(oldApi, "exit");
  oldApi.kill("SIGTERM");
  await oldApiStopped;
  apiServer = start(ley, ["serve", "--store", otherStore, "--bind", "127.0.0.1:" + apiPort], { cwd: repoRoot });
  await waitForHttp(apiOrigin + "/api/health");
  const staleResolvePromise = page.waitForResponse((response) => response.url().includes("/api/v1/evidence/resolve"));
  await affectedCard.getByRole("button", { name: "Revalidate passage" }).click();
  const staleResolve = await staleResolvePromise;
  assert.equal(staleResolve.status(), 404);
  const failureBody = await staleResolve.text();
  assert.equal(JSON.parse(failureBody).error, "wrong_store");
  assert.ok(originalText);
  assert.equal(failureBody.includes(originalText), false, "wrong-store response must not include previously retrieved passage text");
  const errorCode = affectedCard.locator(".error-code");
  await errorCode.waitFor({ state: "visible" });
  assert.equal(await affectedCard.locator(".evidence-passage").count(), 0);
  assert.match(await affectedCard.locator(".passage-heading").textContent(), /Revalidation failed.*prior text hidden/);
  assert.equal(await errorCode.textContent(), "wrong_store");
  const siblingCard = page.locator(".evidence-card").nth(1);
  assert.equal(await siblingCard.locator(".evidence-passage").count(), 1);
  assert.match(await siblingCard.locator(".passage-heading").textContent(), /Retrieved text · not revalidated/);
  browserResults.push({
    question: partialQuestion,
    generation_id: partialCli.generation_id,
    status: partialCli.status,
    completeness: partialCli.completeness,
    answer_assessment: partialCli.answer_assessment,
    requested_urls: partialCli.hits.map((hit) => hit.requested_url),
    passages: partialCli.hits.map((hit) => hit.passage.text),
    references: partialCli.hits.map((hit) => hit.passage.reference),
    revalidation_failure: "wrong_store",
    affected_card_prior_text_hidden: await affectedCard.locator(".evidence-passage").count() === 0,
  });

  assert.deepEqual(browserErrors, []);
  assert.ok(browserRequests.every((url) => url.startsWith(uiOrigin) || url.startsWith(partialUiOrigin)), "unexpected non-local browser request: " + browserRequests.join(", "));
  assert.equal(apiServer.child.exitCode, null);
  assert.equal(uiServer.child.exitCode, null);
  assert.equal(partialApiServer.child.exitCode, null);
  assert.equal(partialUiServer.child.exitCode, null);

  const overlapSource = path.join(artifacts, "overlap-source");
  const overlapStore = path.join(artifacts, "overlap-index");
  await mkdir(overlapSource);
  const block = "blockingprobe durable lexical retrieval scheduling storage query ";
  const htmlDocument = "<!doctype html><html><head><title>Overlap probe</title></head><body><p>" +
    block.repeat(Math.ceil(600000 / block.length)) +
    "</p></body></html>";
  for (let index = 0; index < 6; index += 1) {
    await writeFile(path.join(overlapSource, "page-" + index + ".html"), htmlDocument);
  }
  await run(ley, [
    "ingest-html", "--store", overlapStore, "--directory", overlapSource,
    "--url-prefix", "https://overlap.example.invalid/probe/",
  ], { cwd: repoRoot });
  const overlapPort = await selectedPort("LEY_E2E_OVERLAP_API_PORT");
  const overlapOrigin = "http://127.0.0.1:" + overlapPort;
  const overlapServer = start(ley, ["serve", "--store", overlapStore, "--bind", "127.0.0.1:" + overlapPort], { cwd: repoRoot });
  await waitForHttp(overlapOrigin + "/api/health");
  const searchStarted = performance.now();
  const heavySearch = fetch(overlapOrigin + "/api/search?q=blockingprobe%20AND%20durable")
    .then(async (response) => ({ status: response.status, body: await response.json() }));
  await new Promise((resolve) => setTimeout(resolve, 20));
  const healthStarted = performance.now();
  const health = await fetch(overlapOrigin + "/api/health");
  const healthBody = await health.json();
  const healthMs = performance.now() - healthStarted;
  const search = await heavySearch;
  const searchMs = performance.now() - searchStarted;
  assert.equal(health.status, 200);
  assert.equal(search.status, 200);
  assert.equal(search.body.results.length, 6);
  assert.ok(healthMs < 500, "health check should stay responsive during blocking retrieval (" + healthMs.toFixed(2) + " ms)");
  assert.ok(searchMs > healthMs, "health should finish while storage search is still running");
  await writeFile(path.join(artifacts, "overlap-timings.json"), JSON.stringify({
    documents: 6,
    body_bytes_each: Buffer.byteLength(block.repeat(Math.ceil(600000 / block.length))),
    health_ms: healthMs,
    search_ms: searchMs,
    health_status: health.status,
    search_status: search.status,
    assertion: "health completed before the storage-backed search",
  }, null, 2));
  assert.equal(overlapServer.child.exitCode, null);

  const results = {
    storePath,
    storeGeneration: cliQuestionByText.get(questions[0]).generation_id,
    sourceCollection: "authored CC0 Ley M3 Local Evidence Guide version 1",
    questionResponses: Object.fromEntries(cliQuestionByText),
    typedApiResponses: Object.fromEntries(apiQuestionByText),
    resolution: cliResolution,
    legacyDslCliResponses: Object.fromEntries(cliByQuery),
    legacyDslApiResponses: Object.fromEntries(apiByQuery),
    browserResults,
    contrastResults,
    viewportWidths: [1280, 700, 390, 320],
    browserRequests,
    browserErrors,
    apiServerStderr: apiServer.stderr,
    uiServerStderr: uiServer.stderr,
    screenshots: screenshotPaths,
  };
  await writeFile(path.join(artifacts, "results.json"), JSON.stringify(results, null, 2));
  console.log("Real Chromium question, evidence, legacy DSL, and CLI/API paths passed.");
  console.log("The authored fresh store returned " + cliQuestionByText.get(questions[0]).hits.length + " passages; browser screenshots and structured evidence: " + artifacts);
  console.log("Measured health=" + healthMs.toFixed(2) + " ms while six-document storage search took " + searchMs.toFixed(2) + " ms.");
} catch (error) {
  console.error("Real browser HTTP verification failed. UI and API use only 127.0.0.1. " + error.message);
  throw error;
} finally {
  if (browser) await browser.close();
  await stopChildren();
  if (scratch) await rm(scratch, { recursive: true, force: true });
  console.log("local servers stopped; browser artifacts retained at " + artifacts);
}
