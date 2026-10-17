import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { connect, createServer } from "node:net";
import { once } from "node:events";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(uiRoot, "..");
const scratch = await mkdtemp(path.join(tmpdir(), "ley-http-e2e-store-"));
const artifacts = await mkdtemp(path.join(tmpdir(), "ley-http-e2e-browser-"));
const storePath = path.join(scratch, "index");
const children = [];
let browser;

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

async function connectRaw(port) {
  const socket = connect(port, "127.0.0.1");
  await once(socket, "connect");
  let buffered = Buffer.alloc(0);
  let wakeReader;
  let socketError;
  socket.on("data", (chunk) => {
    buffered = Buffer.concat([buffered, chunk]);
    wakeReader?.();
    wakeReader = undefined;
  });
  socket.on("error", (error) => {
    socketError = error;
    wakeReader?.();
    wakeReader = undefined;
  });
  socket.setTimeout(4000, () => socket.destroy(new Error("local HTTP response timed out")));

  async function waitFor(predicate) {
    while (!predicate()) {
      if (socketError) throw socketError;
      await new Promise((resolve) => { wakeReader = resolve; });
    }
  }

  return {
    socket,
    async readResponse() {
      await waitFor(() => buffered.indexOf("\r\n\r\n") >= 0);
      const boundary = buffered.indexOf("\r\n\r\n");
      const header = buffered.subarray(0, boundary).toString("latin1");
      const lengthLine = header.split("\r\n").find((line) => /^content-length:/i.test(line));
      assert.ok(lengthLine, `response lacks bounded Content-Length: ${header}`);
      const bodyLength = Number(lengthLine.split(":", 2)[1].trim());
      assert.ok(Number.isSafeInteger(bodyLength) && bodyLength >= 0 && bodyLength <= 1024 * 1024);
      const bodyStart = boundary + 4;
      await waitFor(() => buffered.length >= bodyStart + bodyLength);
      const status = Number(header.split("\r\n", 1)[0].split(" ", 2)[1]);
      const body = buffered.subarray(bodyStart, bodyStart + bodyLength).toString("utf8");
      buffered = buffered.subarray(bodyStart + bodyLength);
      return { status, header, body };
    },
  };
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
  await run("cargo", ["build", "--locked", "--offline", "--bin", "ley"], { cwd: repoRoot });
  const ley = path.join(repoRoot, "target", "debug", "ley");
  await run(ley, ["fixture-index", "--store", storePath], { cwd: repoRoot });
  const cli = JSON.parse(await run(ley, ["search", "--store", storePath, "--query", "rust"], { cwd: repoRoot }));
  assert.equal(cli.corpusSize, 3);

  const apiPort = await freePort();
  const uiPort = await freePort();
  const uiOrigin = `http://127.0.0.1:${uiPort}`;
  const apiOrigin = `http://127.0.0.1:${apiPort}`;
  const apiServer = start(ley, ["serve", "--store", storePath, "--bind", `127.0.0.1:${apiPort}`], { cwd: repoRoot });
  const uiServer = start("node", ["scripts/dev-server.mjs"], {
    cwd: uiRoot,
    env: { ...process.env, LEY_UI_PORT: String(uiPort), LEY_API_PORT: String(apiPort) },
  });
  await waitForHttp(`${apiOrigin}/api/health`);
  await waitForHttp(uiOrigin);

  const apiResponse = await fetch(`${apiOrigin}/api/search?q=rust`);
  assert.equal(apiResponse.status, 200);
  assert.deepEqual(await apiResponse.json(), cli, "persistent CLI and HTTP API JSON must match");

  for (const [port, target] of [[apiPort, "/api/search?q=rust"], [uiPort, "/api/search?q=rust"]]) {
    for (const headers of [
      `Host: attacker.example:${port}`,
      `Host: 127.0.0.1:${port}\r\nOrigin: http://attacker.example`,
    ]) {
      const socket = await connectRaw(port);
      socket.socket.end(`GET ${target} HTTP/1.1\r\n${headers}\r\nConnection: close\r\n\r\n`);
      const denied = await socket.readResponse();
      assert.equal(denied.status, 403);
      assert.doesNotMatch(denied.body, /fixtures\.ley\.test|Rust in Ley/);
    }
  }

  const malformedSocket = await connectRaw(uiPort);
  malformedSocket.socket.write(`GET http://[bad HTTP/1.1\r\nHost: 127.0.0.1:${uiPort}\r\nConnection: keep-alive\r\n\r\n`);
  const malformed = await malformedSocket.readResponse();
  assert.equal(malformed.status, 400);
  assert.ok(Buffer.byteLength(malformed.body) <= 128);
  malformedSocket.socket.write(`GET / HTTP/1.1\r\nHost: 127.0.0.1:${uiPort}\r\nConnection: keep-alive\r\n\r\n`);
  assert.equal((await malformedSocket.readResponse()).status, 200);
  malformedSocket.socket.destroy();

  const browserRequests = [];
  const browserErrors = [];
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
  for (const query of ["rust", "bm25", "adversarial"]) {
    const responsePromise = page.waitForResponse((response) => response.url().includes(`/api/search?q=${query}`));
    await input.fill(query);
    await input.press("Enter");
    const response = await responsePromise;
    assert.equal(response.status(), 200, `${query} API response`);
    const body = await response.json();
    await page.locator(".result-card").first().waitFor();
    assert.ok((await page.locator(".result-title").allTextContents()).includes(body.results[0].title));
    assert.equal(body.generation, body.results[0].explanation.statisticsSource.generation);
    assert.equal(body.results[0].score, body.results[0].explanation.totalScore);
    assert.equal(await page.locator(".results-section img,.results-section script,.results-section [onerror]").count(), 0);
    await page.locator("details").first().evaluate((element) => { element.open = true; });
    for (const width of [1280, 700, 390, 320]) {
      await page.setViewportSize({ width, height: 900 });
      const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
      assert.ok(scrollWidth <= width, `${query} at ${width}px has horizontal overflow (${scrollWidth}px)`);
      await page.screenshot({ path: path.join(artifacts, `${query}-${width}.png`), fullPage: true });
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
  console.log(`Real Chromium HTTP path passed: UI ${uiOrigin} -> API ${apiOrigin} -> generation ${cli.generation}.`);
  console.log(`Queries rust, bm25, adversarial, and malformed-query error passed. Screenshots: ${artifacts}`);
} catch (error) {
  console.error(`Real browser HTTP verification failed. UI and API use only 127.0.0.1. ${error.message}`);
  throw error;
} finally {
  if (browser) await browser.close();
  await stopChildren();
  await rm(scratch, { recursive: true, force: true });
  console.log(`local servers stopped; browser artifacts retained at ${artifacts}`);
}
