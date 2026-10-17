import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { connect } from "node:net";
import { once } from "node:events";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { createUiServer } from "./dev-server.mjs";

const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(uiRoot, "..");
const scratch = await mkdtemp(path.join(process.env.TMPDIR ?? "/tmp", "ley-gate5-browser-"));
const artifactDir = process.env.LEY_GATE5_ARTIFACT_DIR ?? path.join("/tmp", `ley-gate5-browser-artifacts-${process.pid}`);
let uiServer;

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

async function openRawHttpSocket(port) {
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
      assert.ok(lengthLine, `response did not declare a bounded body: ${header}`);
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
  const headlessShells = entries
    .filter((entry) => entry.startsWith("chromium_headless_shell-"))
    .sort()
    .reverse();
  for (const entry of headlessShells) {
    const candidate = path.join(base, entry, "chrome-headless-shell-linux64/chrome-headless-shell");
    try {
      await import("node:fs/promises").then(({ access }) => access(candidate));
      return candidate;
    } catch {
      continue;
    }
  }
  const chromiumBuilds = entries.filter((entry) => entry.startsWith("chromium-")).sort().reverse();
  for (const entry of chromiumBuilds) {
    for (const suffix of ["chrome-linux64/chrome", "chrome-linux/chrome"]) {
      const candidate = path.join(base, entry, suffix);
      try {
        await import("node:fs/promises").then(({ access }) => access(candidate));
        return candidate;
      } catch {
        // Try the other packaged layout.
      }
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
      ".eyebrow", ".intro", ".loading-panel", ".error-panel p", ".unsafe-url",
      ".query-hint", ".masthead-note", ".result-meta", ".results-summary", ".result-url",
      ".score-pill", ".score-pill span", ".result-snippet", ".match-summary",
      ".explanation summary", ".explanation-overview", ".term-breakdown h4", ".field-row",
      ".field-row > strong", ".field-row .contribution",
      ".explanation-total", ".version-id", ".page-footer", ".page-footer a",
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
        measurements.push({ selector, color: style.color, background: style.backgroundColor, ratio: (colors[0] + 0.05) / (colors[1] + 0.05) });
      }
    }
    return measurements;
  });
}

async function mountApp(page, fixtures) {
  const [css, script] = await Promise.all([
    readFile(path.join(uiRoot, "dist/main.css"), "utf8"),
    readFile(path.join(uiRoot, "dist/main.js"), "utf8"),
  ]);
  await page.setContent(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Ley — local search</title><style>${css}</style></head><body><div id="root"></div></body></html>`);
  await page.evaluate((responses) => {
    window.__leyRequests = [];
    window.fetch = async (input, init = {}) => {
      const requestUrl = new URL(typeof input === "string" ? input : input.url, "http://ley.local/");
      window.__leyRequests.push(`${requestUrl.pathname}${requestUrl.search}`);
      const query = requestUrl.searchParams.get("q") ?? "";
      const makeResponse = (body, status = 200) => new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      });
      if (query === "older") {
        await new Promise((resolve) => setTimeout(resolve, 350));
        if (init.signal?.aborted) throw new DOMException("Aborted", "AbortError");
        return makeResponse({ ...responses.rust, query, corpusSize: 0, totalResults: 0, results: [] });
      }
      if (query === "newer") return makeResponse(responses.malicious);
      if (query === "empty") return makeResponse(responses.empty);
      if (query === "unavailable") return makeResponse({ error: "index_unavailable" }, 503);
      if (query === '"') return makeResponse({ error: "invalid_query" }, 400);
      return makeResponse(responses[query] ?? { ...responses.rust, query, corpusSize: 0, totalResults: 0, results: [] });
    };
  }, fixtures);
  await page.addScriptTag({ content: script });
}

let browser;
try {
  await mkdir(artifactDir, { recursive: true });
  const indexPath = path.join(scratch, "index");
  await run("cargo", ["run", "--locked", "--offline", "--", "fixture-index", "--store", indexPath], { cwd: repoRoot });
  await run("npm", ["run", "build"], { cwd: uiRoot });
  const storeSearch = async (query) => JSON.parse(await run(path.join(repoRoot, "target/debug/ley"), [
    "search", "--store", indexPath, "--query", query,
  ], { cwd: repoRoot }));
  const apiFixture = await storeSearch("rust");
  const bm25Fixture = await storeSearch("bm25");
  const adversarialFixture = await storeSearch("adversarial");
  assert.equal(apiFixture.corpusSize, 3);
  assert.equal(apiFixture.generation, apiFixture.results[0].explanation.statisticsSource.generation);
  assert.ok(apiFixture.results.some((result) => result.id === "https://fixtures.ley.test/guide/rust"));
  assert.equal(adversarialFixture.results.length, 1);

  uiServer = createUiServer({ root: path.join(uiRoot, "dist"), port: 0, apiPort: 1 });
  await new Promise((resolve, reject) => {
    uiServer.once("error", reject);
    uiServer.listen(0, "127.0.0.1", resolve);
  });
  const address = uiServer.address();
  assert.ok(address && typeof address === "object");
  const uiPort = address.port;

  const maliciousResponse = structuredClone(apiFixture);
  maliciousResponse.query = "<img src=x onerror=alert(2)>";
  maliciousResponse.results[0].id = "javascript:alert(3)";
  maliciousResponse.results[0].title = "<img src=x onerror=alert(4)>";

  const localSocket = await openRawHttpSocket(uiPort);
  localSocket.socket.write(`GET / HTTP/1.1\r\nHost: 127.0.0.1:${uiPort}\r\nConnection: keep-alive\r\n\r\n`);
  const localPage = await localSocket.readResponse();
  assert.equal(localPage.status, 200);
  assert.match(localPage.body, /Ley — local search/);
  localSocket.socket.destroy();

  const noticeSocket = await openRawHttpSocket(uiPort);
  noticeSocket.socket.write(`GET /rust-stdlib-documentation-MIT.txt HTTP/1.1\r\nHost: 127.0.0.1:${uiPort}\r\nConnection: close\r\n\r\n`);
  const servedNotice = await noticeSocket.readResponse();
  assert.equal(servedNotice.status, 200);
  assert.match(servedNotice.body, /MIT License/);
  assert.match(servedNotice.header, /content-type: text\/plain; charset=utf-8/i);
  noticeSocket.socket.destroy();

  for (const headers of [
    `Host: attacker.example:${uiPort}`,
    `Host: 127.0.0.1:${uiPort}\r\nOrigin: http://attacker.example`,
  ]) {
    const foreignSocket = await openRawHttpSocket(uiPort);
    foreignSocket.socket.write(`GET /api/search?q=rust HTTP/1.1\r\n${headers}\r\nConnection: close\r\n\r\n`);
    const rejected = await foreignSocket.readResponse();
    assert.equal(rejected.status, 403);
    assert.doesNotMatch(rejected.body, /fixtures\.ley\.test|Rust in Ley/);
    foreignSocket.socket.destroy();
  }

  const malformedSocket = await openRawHttpSocket(uiPort);
  malformedSocket.socket.write(`GET http://[bad HTTP/1.1\r\nHost: 127.0.0.1:${uiPort}\r\nConnection: keep-alive\r\n\r\n`);
  const malformed = await malformedSocket.readResponse();
  assert.equal(malformed.status, 400);
  assert.ok(Buffer.byteLength(malformed.body) <= 128);
  malformedSocket.socket.write(`GET / HTTP/1.1\r\nHost: 127.0.0.1:${uiPort}\r\nConnection: close\r\n\r\n`);
  const afterMalformed = await malformedSocket.readResponse();
  assert.equal(afterMalformed.status, 200);
  assert.match(afterMalformed.body, /Ley — local search/);
  malformedSocket.socket.destroy();

  for (const query of ["rust", "bm25", '"small corpus" OR bm25']) {
    const cli = await storeSearch(query);
    const expected = query === "rust" ? apiFixture : query === "bm25" ? bm25Fixture : await storeSearch(query);
    assert.deepEqual(cli, expected, `persistent CLI response changed between reads for ${JSON.stringify(query)}`);
    assert.ok(cli.results.every((result) => result.score === result.explanation.totalScore));
  }

  const externalRequests = [];
  browser = await chromium.launch({
    executablePath: await chromiumExecutable(),
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage", "--single-process", "--no-zygote"],
  });
  const page = await browser.newPage();
  page.on("request", (request) => {
    if (!request.url().startsWith("http://127.0.0.1:")) externalRequests.push(request.url());
  });

  await mountApp(page, {
    rust: apiFixture,
    bm25: bm25Fixture,
    adversarial: adversarialFixture,
    malicious: maliciousResponse,
    empty: { ...apiFixture, query: "empty", corpusSize: 0, totalResults: 0, truncated: false, results: [] },
  });
  assert.match(await page.title(), /Ley — local search/);
  assert.match(await page.getByText("Ready when you are.").textContent(), /Ready/);
  assert.equal(
    await page.getByRole("link", { name: "Candidate source and MIT notice" }).getAttribute("href"),
    "/rust-stdlib-documentation-MIT.txt",
  );

  const input = page.getByRole("textbox", { name: "Search indexed documents" });
  await page.locator("h1").click();
  await page.keyboard.press("Control+k");
  assert.equal(await input.evaluate((element) => element === document.activeElement), true);
  await input.fill("rust");
  await input.press("Enter");
  await page.getByRole("heading", { name: "Rust in Ley: retrieval notes" }).waitFor();
  assert.equal(await page.locator(".result-card").count(), 1);
  assert.match(await page.locator(".result-meta").textContent(), /3 indexed/);
  const explanationSummary = page.getByText("Why this result?");
  await explanationSummary.focus();
  await page.keyboard.press("Enter");
  assert.equal(await explanationSummary.evaluate((element) => element.parentElement.open), true);
  await page.getByText("Total BM25 score").waitFor();
  const contrast = await measuredSmallTextContrast(page);
  assert.ok(contrast.length > 10, "small metadata and explanation text were measured");
  const lowContrast = contrast.filter((measurement) => measurement.ratio < 4.5);
  assert.deepEqual(lowContrast, [], `small text contrast fell below 4.5:1: ${JSON.stringify(lowContrast)}`);

  for (const width of [1280, 700, 390, 320]) {
    const viewport = page;
    await viewport.setViewportSize({ width, height: 900 });
    await mountApp(viewport, {
      rust: apiFixture,
      bm25: bm25Fixture,
      adversarial: adversarialFixture,
      malicious: maliciousResponse,
      empty: { ...apiFixture, query: "empty", corpusSize: 0, totalResults: 0, truncated: false, results: [] },
    });
    const viewportInput = viewport.getByRole("textbox", { name: "Search indexed documents" });
    await viewportInput.fill("rust");
    await viewportInput.press("Enter");
    await viewport.getByRole("heading", { name: "Rust in Ley: retrieval notes" }).waitFor();
    await viewport.getByText("Why this result?").click();
    await viewport.getByText("Total BM25 score").waitFor();
    const dimensions = await viewport.evaluate(() => ({
      viewport: document.documentElement.clientWidth,
      document: document.documentElement.scrollWidth,
      body: document.body.scrollWidth,
    }));
    assert.ok(dimensions.document <= width && dimensions.body <= width, `${width}px ordinary reflow overflow: ${JSON.stringify(dimensions)}`);
    await viewport.screenshot({ path: path.join(artifactDir, `viewport-${width}.png`), fullPage: true });

    if (width === 320) {
      await viewportInput.fill("adversarial");
      await viewportInput.press("Enter");
      await viewport.locator(".result-card .result-title").waitFor();
      assert.equal(await viewport.locator(".result-card").count(), 1);
      await viewport.getByText("Why this result?").click();
      await viewport.getByText("Total BM25 score").waitFor();
      const longDimensions = await viewport.evaluate(() => ({
        viewport: document.documentElement.clientWidth,
        document: document.documentElement.scrollWidth,
        body: document.body.scrollWidth,
      }));
      assert.ok(longDimensions.document <= width && longDimensions.body <= width, `320px long-content reflow overflow: ${JSON.stringify(longDimensions)}`);
      await viewport.screenshot({ path: path.join(artifactDir, "viewport-320-long-adversarial.png"), fullPage: true });
    }
  }

  await input.fill("bm25");
  await input.press("Enter");
  await page.getByRole("heading", { name: "Search score <img src=x onerror=alert(1)> explanations" }).waitFor();
  assert.equal(await page.locator(".results-section img, .results-section script, .results-section [onerror]").count(), 0);
  const hostileSnippet = await page.locator(".result-snippet").textContent();
  assert.match(hostileSnippet ?? "", /<img src=x onerror=alert\(1\)>/);

  await input.fill("older");
  await input.press("Enter");
  await page.getByText("Searching for", { exact: false }).waitFor();
  const loadingContrast = await measuredSmallTextContrast(page);
  assert.deepEqual(loadingContrast.filter((measurement) => measurement.ratio < 4.5), [], "loading text contrast fell below 4.5:1");
  await input.fill("newer");
  await input.press("Enter");
  await page.locator(".results-summary").getByText("<img src=x onerror=alert(2)>", { exact: true }).waitFor();
  await new Promise((resolve) => setTimeout(resolve, 450));
  assert.equal(await page.locator(".results-section img, .results-section script, .results-section [onerror]").count(), 0);
  assert.equal(await page.locator('a[href^="javascript:"]').count(), 0);
  assert.equal(await page.locator(".empty-panel").count(), 0, "stale response replaced the newer result");
  const hostileContrast = await measuredSmallTextContrast(page);
  assert.deepEqual(hostileContrast.filter((measurement) => measurement.ratio < 4.5), [], "unsafe URL text contrast fell below 4.5:1");

  await input.fill('"');
  await input.press("Enter");
  await page.getByRole("alert").getByText("That query is not valid.", { exact: false }).waitFor();
  const errorContrast = await measuredSmallTextContrast(page);
  assert.deepEqual(errorContrast.filter((measurement) => measurement.ratio < 4.5), [], "error text contrast fell below 4.5:1");
  await input.fill("empty");
  await input.press("Enter");
  await page.getByText("Your index is empty.").waitFor();
  await input.fill("unavailable");
  await input.press("Enter");
  await page.getByRole("alert").getByText("could not complete the search", { exact: false }).waitFor();

  assert.deepEqual(externalRequests, [], "the UI initiated a browser network request outside its injected fixture adapter");
  assert.deepEqual(await page.evaluate(() => window.__leyRequests.every((entry) => entry.startsWith("/api/search?"))), true);
  process.stdout.write(`browser verified: persistent CLI fixture data, UI server boundary sockets, malformed-target recovery, 4 viewports, long-content reflow, measured small-text contrast, hostile text/URL handling, stale response order, malformed query, API failure; screenshots=${artifactDir}\n`);
} finally {
  if (browser) await browser.close();
  if (uiServer?.listening) await new Promise((resolve) => uiServer.close(resolve));
  await rm(scratch, { recursive: true, force: true });
}
