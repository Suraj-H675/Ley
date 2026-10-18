import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { access, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
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
  const ley = path.join(repoRoot, "target", "debug", "ley");
  assert.ok(
    process.env.LEY_E2E_CORPUS === undefined || process.env.LEY_E2E_CORPUS === "gate7-loopback-v1",
    "LEY_E2E_CORPUS must be gate7-loopback-v1 when set",
  );
  const gate7Corpus = process.env.LEY_E2E_CORPUS === "gate7-loopback-v1";
  const loopbackManifest = gate7Corpus
    ? JSON.parse(await readFile(path.join(repoRoot, "fixtures/gate7-loopback-v1.json"), "utf8"))
    : undefined;
  const queries = gate7Corpus ? loopbackManifest.queries : ["rust", "bm25", "adversarial"];
  let storeExists = true;
  try {
    await access(storePath);
  } catch {
    storeExists = false;
  }
  if (storeExists) {
    assert.equal(process.env.LEY_E2E_REUSE_STORE, "1", "refusing to overwrite an existing fixture index");
  } else {
    assert.ok(!gate7Corpus, "Gate 7 corpus mode requires the retained controlled-demo index");
    await run(ley, ["fixture-index", "--store", storePath], { cwd: repoRoot });
  }
  const cliByQuery = new Map();
  for (const query of queries) {
    const response = JSON.parse(await run(ley, ["search", "--store", storePath, "--query", query], { cwd: repoRoot }));
    assert.ok(response.results.length > 0, `fixture query ${JSON.stringify(query)} has results`);
    if (gate7Corpus) assert.equal(response.corpusSize, loopbackManifest.expectedIndexedPaths.length);
    else assert.equal(response.corpusSize, 3);
    cliByQuery.set(query, response);
  }
  const cli = cliByQuery.get(queries[0]);

  const apiPort = await selectedPort("LEY_E2E_API_PORT");
  const uiPort = await selectedPort("LEY_E2E_UI_PORT");
  const uiOrigin = `http://127.0.0.1:${uiPort}`;
  const apiOrigin = `http://127.0.0.1:${apiPort}`;
  const apiServer = start(ley, ["serve", "--store", storePath, "--bind", `127.0.0.1:${apiPort}`], { cwd: repoRoot });
  const uiServer = start("node", ["scripts/dev-server.mjs"], {
    cwd: uiRoot,
    env: { ...process.env, LEY_UI_PORT: String(uiPort), LEY_API_PORT: String(apiPort) },
  });
  await waitForHttp(`${apiOrigin}/api/health`);
  await waitForHttp(uiOrigin);

  const apiByQuery = new Map();
  for (const query of queries) {
    const apiResponse = await fetch(`${apiOrigin}/api/search?q=${encodeURIComponent(query)}`);
    assert.equal(apiResponse.status, 200);
    const apiResult = await apiResponse.json();
    assert.deepEqual(apiResult, cliByQuery.get(query), `persistent CLI and HTTP API JSON must match for ${query}`);
    apiByQuery.set(query, apiResult);
  }
  if (gate7Corpus) {
    const actualPaths = new Set(
      [...apiByQuery.values()].flatMap((response) => response.results.map((result) => new URL(result.id).pathname)),
    );
    assert.deepEqual(
      [...actualPaths].sort(),
      [...loopbackManifest.expectedIndexedPaths].sort(),
      "manifest queries must reach every document in the retained crawler index",
    );
    const redirectHits = apiByQuery.get(loopbackManifest.redirectIdentityQuery).results;
    assert.equal(redirectHits.length, 1);
    assert.ok(redirectHits[0].id.endsWith(loopbackManifest.redirectRequestedPath));
    assert.ok(redirectHits[0].versionId.length > 10);
  }

  for (const [port, target] of [[apiPort, "/api/search?q=rust"], [uiPort, "/api/search?q=rust"]]) {
    for (const headers of [
      `Host: attacker.example:${port}`,
      `Host: 127.0.0.1:${port}\r\nOrigin: http://attacker.example`,
    ]) {
      const socket = await connectRaw(port);
      try {
        socket.socket.write(`GET ${target} HTTP/1.1\r\n${headers}\r\nConnection: close\r\n\r\n`);
        const denied = await socket.readResponse();
        assert.equal(denied.status, 403);
        assert.doesNotMatch(denied.body, /fixtures\.ley\.test|Rust in Ley|Controlled Ley fixture|Redirect target record/);
      } finally {
        socket.dispose();
      }
    }
  }

  const malformedSocket = await connectRaw(uiPort);
  try {
    malformedSocket.socket.write(`GET http://[bad HTTP/1.1\r\nHost: 127.0.0.1:${uiPort}\r\nConnection: keep-alive\r\n\r\n`);
    const malformed = await malformedSocket.readResponse();
    assert.equal(malformed.status, 400);
    assert.ok(Buffer.byteLength(malformed.body) <= 128);
    malformedSocket.socket.write(`GET / HTTP/1.1\r\nHost: 127.0.0.1:${uiPort}\r\nConnection: keep-alive\r\n\r\n`);
    assert.equal((await malformedSocket.readResponse()).status, 200);
  } finally {
    malformedSocket.dispose();
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
  const input = page.getByRole("textbox", { name: "Search indexed documents" });
  for (const [queryIndex, query] of queries.entries()) {
    const expected = apiByQuery.get(query);
    const responsePromise = page.waitForResponse((response) => {
      if (!response.url().includes("/api/search?")) return false;
      return new URL(response.url()).searchParams.get("q") === query;
    });
    await input.fill(query);
    await input.press("Enter");
    const response = await responsePromise;
    assert.equal(response.status(), 200, `${query} API response`);
    const body = await response.json();
    assert.deepEqual(body, expected, `browser API response matches CLI response for ${query}`);
    await page.waitForFunction((expectedIds) => {
      const currentIds = [...document.querySelectorAll(".result-url")].map((element) => element.textContent);
      return currentIds.length === expectedIds.length && currentIds.every((id, index) => id === expectedIds[index]);
    }, body.results.map((result) => result.id));
    const cards = page.locator(".result-card");
    assert.equal(await cards.count(), body.results.length, `${query} rendered result count`);
    assert.deepEqual(
      await page.locator(".result-url").allTextContents(),
      body.results.map((result) => result.id),
      `${query} rendered result IDs and order`,
    );
    assert.equal(body.generation, body.results[0].explanation.statisticsSource.generation);
    assert.equal(body.results[0].score, body.results[0].explanation.totalScore);
    for (const [resultIndex, result] of body.results.entries()) {
      const card = cards.nth(resultIndex);
      assert.equal((await card.locator(".result-title").textContent()).trim(), result.title);
      const scoreText = (await card.locator(".score-pill").textContent()).trim();
      assert.ok(scoreText.startsWith(result.score.toFixed(3)), `${query} UI score for ${result.id}`);
      const explanation = card.locator("details");
      await explanation.locator("summary").click();
      assert.equal(
        (await explanation.locator(".explanation-total strong").textContent()).trim(),
        result.explanation.totalScore.toFixed(6),
        `${query} UI explanation total for ${result.id}`,
      );
      assert.equal(
        (await explanation.locator(".version-id").textContent()).trim(),
        `Version ${result.versionId}`,
        `${query} UI version identity for ${result.id}`,
      );
      assert.deepEqual(
        await explanation.locator(".term-breakdown h4").allTextContents(),
        result.explanation.terms.map((term) => term.term),
        `${query} UI explanation terms for ${result.id}`,
      );
      for (const [termIndex, term] of result.explanation.terms.entries()) {
        const breakdown = explanation.locator(".term-breakdown").nth(termIndex);
        const expectedFields = [term.title, term.body];
        const rows = breakdown.locator(".field-row");
        assert.equal(await rows.count(), expectedFields.length);
        for (const [fieldIndex, field] of expectedFields.entries()) {
          const spans = rows.nth(fieldIndex).locator("span");
          assert.equal(
            (await spans.nth(0).textContent()).trim(),
            `tf ${field.termFrequency} / df ${field.documentFrequency}`,
          );
          assert.equal(
            (await spans.nth(1).textContent()).trim(),
            `len ${field.documentLength} · idf ${field.idf.toFixed(4)}`,
          );
          assert.equal(
            (await rows.nth(fieldIndex).locator(".contribution").textContent()).trim(),
            `+${field.contribution.toFixed(6)}`,
          );
        }
      }
    }
    browserResults.push({
      query,
      generation: body.generation,
      corpusSize: body.corpusSize,
      resultIds: body.results.map((result) => result.id),
      topScore: body.results[0].score,
      topExplanation: body.results[0].explanation,
    });
    assert.equal(await page.locator(".results-section img,.results-section script,.results-section [onerror]").count(), 0);
    await page.locator("details").first().evaluate((element) => { element.open = true; });
    for (const width of [1280, 700, 390, 320]) {
      await page.setViewportSize({ width, height: 900 });
      const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
      assert.ok(scrollWidth <= width, `${query} at ${width}px has horizontal overflow (${scrollWidth}px)`);
      const querySlug = query.replace(/[^a-zA-Z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || `query-${queryIndex + 1}`;
      const screenshot = path.join(artifacts, `${querySlug}-${width}.png`);
      await page.screenshot({ path: screenshot, fullPage: true });
      screenshotPaths.push(screenshot);
    }
  }
  await input.fill('"');
  await input.press("Enter");
  await page.getByRole("alert").waitFor();
  assert.deepEqual(browserErrors, []);
  assert.ok(browserRequests.every((url) => url.startsWith(uiOrigin)), `unexpected browser requests: ${browserRequests.join(", ")}`);

  const notice = await fetch(`${uiOrigin}/rust-stdlib-documentation-MIT.txt`);
  assert.equal(notice.status, 200);
  assert.match(await notice.text(), /MIT License/);
  assert.equal(apiServer.child.exitCode, null);
  assert.equal(uiServer.child.exitCode, null);
  await writeFile(path.join(artifacts, "results.json"), JSON.stringify({
    storePath,
    uiOrigin,
    apiOrigin,
    browserVersion: browser.version(),
    browserUserAgent: await page.evaluate(() => navigator.userAgent),
    generation: cli.generation,
    corpusMode: gate7Corpus ? "gate7-loopback-v1 retained crawler store" : "legacy authored fixture-index store",
    cliResponses: Object.fromEntries(cliByQuery),
    apiResponses: Object.fromEntries(apiByQuery),
    browserResults,
    viewportWidths: [1280, 700, 390, 320],
    malformedQueryStatus: "alert shown",
    browserRequests,
    browserErrors,
    apiServerStderr: apiServer.stderr,
    uiServerStderr: uiServer.stderr,
    noticeStatus: notice.status,
    screenshots: screenshotPaths,
  }, null, 2));
  console.log(`Real Chromium HTTP path passed: UI ${uiOrigin} -> API ${apiOrigin} -> generation ${cli.generation}.`);
  console.log(`Queries ${queries.map((query) => JSON.stringify(query)).join(", ")} and malformed-query error passed. Screenshots and results: ${artifacts}`);
} catch (error) {
  console.error(`Real browser HTTP verification failed. UI and API use only 127.0.0.1. ${error.message}`);
  throw error;
} finally {
  if (browser) await browser.close();
  await stopChildren();
  if (scratch) await rm(scratch, { recursive: true, force: true });
  console.log(`local servers stopped; browser artifacts retained at ${artifacts}`);
}
