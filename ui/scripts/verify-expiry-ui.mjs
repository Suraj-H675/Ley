import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createUiServer } from "./dev-server.mjs";
import { chromium } from "playwright";

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

const body = "Authored expiry test passage. It grants no public rights.";
const expiredEvidenceMessage = "This collection has expired. Previously displayed passage and source notice are hidden.";
const bodyBytes = Buffer.byteLength(body);
const reference = {
  store_id: Array(16).fill(17),
  requested_url: "https://docs.example.invalid/manual/start.html",
  content_version: Array(32).fill(23),
  passage_schema_version: 1,
  start_byte: 0,
  end_byte: bodyBytes,
  identity_sha256: Array(32).fill(42),
};
const requestedUrl = reference.requested_url;
const effectiveUrl = "https://docs.example.invalid/manual/current.html";
const title = "Authored expiry test document";
const visibleUntilMs = Date.now() + 30 * 60 * 1000;
const retrieval = {
  contract_version: 1,
  mode: "question",
  generation_id: 1,
  status: "retrieved_text",
  completeness: "complete",
  normalized_terms: ["expiry"],
  hits: [{
    requested_url: requestedUrl,
    effective_url: effectiveUrl,
    title,
    score: 1,
    matched_terms: ["expiry"],
    matched_phrases: [],
    passage: { reference, text: body },
  }],
  answer_assessment: "not_assessed",
};
const source = {
  kind: "operator_source",
  policy_format: "notice_bound_v2",
  source_id: "synthetic-expiry-test",
  origin: "https://docs.example.invalid",
  license_label: "Synthetic test record with no granted rights",
  source_version: "test-v1",
  installed_at_ms: Date.now() - 1000,
  visible_until_ms: visibleUntilMs,
  display_permission_reviewed_at_ms: Date.now() - 2000,
  notice_sha256: "a".repeat(64),
  notice_text: "Synthetic test notice. This grants no rights to fetch, store, index, or display content.",
};
const transparency = {
  contract_version: 1,
  reference,
  requested_url: requestedUrl,
  effective_url: effectiveUrl,
  source,
};
const inspection = {
  contract_version: 1,
  reference,
  requested_url: requestedUrl,
  effective_url: effectiveUrl,
  title,
  start_byte: 0,
  end_byte: bodyBytes,
  total_bytes: bodyBytes,
  next_offset_byte: null,
  text: body,
};
const resolved = {
  reference,
  requested_url: requestedUrl,
  effective_url: effectiveUrl,
  title,
  text: body,
};

const expiryStarted = deferred();
const releaseExpiry = deferred();
const initialSourceLookupStarted = deferred();
const releaseInitialSourceLookup = deferred();
const inspectionStarted = deferred();
const releaseLateInspection = deferred();
const lateInspectionHandled = deferred();
const lateResolveStarted = deferred();
const releaseLateResolve = deferred();
const lateResolveHandled = deferred();
const timerInspectionStarted = deferred();
const releaseTimerInspection = deferred();
const timerInspectionHandled = deferred();
const staleSourceLookupStarted = deferred();
const releaseStaleSourceLookup = deferred();
const staleSourceLookupHandled = deferred();
let resolveCount = 0;
let inspectionCount = 0;
let sourceLookupCount = 0;
let holdInitialSourceLookup = false;
let withholdNextSource = false;
let holdTimerInspection = false;
let nextSourceErrorCode = null;
let nextSourceKind = null;
let nextResolveErrorCode = null;
let lateInspectionError;
let lateResolveError;
let timerInspectionError;
let staleSourceLookupError;
const server = createUiServer({ port: 0, apiPort: 7331 });
let browser;

await new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, "127.0.0.1", resolve);
});

try {
  const address = server.address();
  assert.ok(address && typeof address === "object");
  browser = await chromium.launch({ headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage"] });
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await page.route("**/api/v1/**", async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    if (pathname === "/api/v1/workspace/status") {
      await route.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify({ error: "not_bound" }) });
      return;
    }
    if (pathname === "/api/v1/retrieve") {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(retrieval) });
      return;
    }
    if (pathname === "/api/v1/evidence/source") {
      sourceLookupCount += 1;
      if (holdInitialSourceLookup) {
        holdInitialSourceLookup = false;
        initialSourceLookupStarted.resolve();
        await releaseInitialSourceLookup.promise;
        await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(transparency) });
      } else if (nextSourceErrorCode) {
        const code = nextSourceErrorCode;
        nextSourceErrorCode = null;
        await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: code }) });
      } else if (withholdNextSource) {
        withholdNextSource = false;
        await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ...transparency, source: { kind: "attribution_withheld" } }) });
      } else if (nextSourceKind) {
        const kind = nextSourceKind;
        nextSourceKind = null;
        await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ...transparency, source: { kind } }) });
      } else if (sourceLookupCount === 1) {
        await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(transparency) });
      } else if (sourceLookupCount === 2) {
        staleSourceLookupStarted.resolve();
        await releaseStaleSourceLookup.promise;
        try {
          await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(transparency) });
        } catch (error) {
          staleSourceLookupError = error instanceof Error ? error.message : String(error);
        } finally {
          staleSourceLookupHandled.resolve();
        }
      } else if (sourceLookupCount === 3) {
        await route.fulfill({ status: 410, contentType: "application/json", body: JSON.stringify({ error: "public_collection_expired" }) });
      } else {
        await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(transparency) });
      }
      return;
    }
    if (pathname === "/api/v1/evidence/resolve") {
      resolveCount += 1;
      if (nextResolveErrorCode) {
        const code = nextResolveErrorCode;
        nextResolveErrorCode = null;
        await route.fulfill({ status: 410, contentType: "application/json", body: JSON.stringify({ error: code }) });
      } else if (resolveCount === 1) {
        await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(resolved) });
      } else if (resolveCount === 2) {
        await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: "storage_fault" }) });
      } else if (resolveCount === 3) {
        expiryStarted.resolve();
        await releaseExpiry.promise;
        await route.fulfill({ status: 410, contentType: "application/json", body: JSON.stringify({ error: "public_collection_expired" }) });
      } else if (resolveCount === 4) {
        lateResolveStarted.resolve();
        await releaseLateResolve.promise;
        try {
          await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(resolved) });
        } catch (error) {
          lateResolveError = error instanceof Error ? error.message : String(error);
        } finally {
          lateResolveHandled.resolve();
        }
      } else {
        await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(resolved) });
      }
      return;
    }
    if (pathname === "/api/v1/evidence/inspect") {
      inspectionCount += 1;
      if (holdTimerInspection) {
        holdTimerInspection = false;
        timerInspectionStarted.resolve();
        await releaseTimerInspection.promise;
        try {
          await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(inspection) });
        } catch (error) {
          timerInspectionError = error instanceof Error ? error.message : String(error);
        } finally {
          timerInspectionHandled.resolve();
        }
      } else if (inspectionCount === 1) {
        inspectionStarted.resolve();
        await releaseLateInspection.promise;
        try {
          await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(inspection) });
        } catch (error) {
          lateInspectionError = error instanceof Error ? error.message : String(error);
        } finally {
          lateInspectionHandled.resolve();
        }
      } else {
        await route.fulfill({ status: 410, contentType: "application/json", body: JSON.stringify({ error: "public_collection_expired" }) });
      }
      return;
    }
    throw new Error(`Unexpected API request ${route.request().method()} ${pathname}`);
  });

  await page.goto(`http://127.0.0.1:${address.port}`);
  const input = page.getByRole("textbox", { name: "Ask a question about indexed documents" });
  holdInitialSourceLookup = true;
  await input.fill("Which source has the expiry test passage?");
  await input.press("Enter");
  await initialSourceLookupStarted.promise;
  await page.getByText("Checking each current source record before showing its passage.", { exact: true }).waitFor();
  releaseInitialSourceLookup.resolve();
  const card = page.locator(".evidence-card");
  await card.locator(".source-notice-text").waitFor();
  assert.ok(source.visible_until_ms > Date.now(), "the source deadline is still in the future");
  assert.equal((await card.locator(".evidence-passage").textContent()).trim(), body);

  await card.getByRole("button", { name: "Revalidate passage" }).click();
  await card.locator(".passage-heading").waitFor();
  await page.waitForFunction(() => document.querySelector(".passage-heading")?.textContent?.includes("current index state"));
  assert.equal(await card.locator(".source-notice-text").count(), 1, "valid resolution keeps current attribution visible");
  assert.equal((await card.locator(".evidence-passage").textContent()).trim(), body);

  const transientResponse = page.waitForResponse((response) => response.url().includes("/api/v1/evidence/resolve") && response.status() === 503);
  await card.getByRole("button", { name: "Revalidate passage" }).click();
  await transientResponse;
  assert.equal(await card.locator(".error-code").filter({ hasText: "storage_fault" }).count(), 1);
  assert.equal(await card.locator(".source-notice-text").count(), 1, "a transient storage error does not invalidate the source notice");
  assert.equal(await card.locator(".result-url").count(), 1, "a transient storage error keeps the source identity visible");

  const expiryResponse = page.waitForResponse((response) => response.url().includes("/api/v1/evidence/resolve") && response.status() === 410);
  await card.getByRole("button", { name: "Revalidate passage" }).click();
  await expiryStarted.promise;
  await card.getByRole("button", { name: "Read current indexed text" }).click();
  await inspectionStarted.promise;
  releaseExpiry.resolve();
  releaseInitialSourceLookup.resolve();
  const expired = await expiryResponse;
  const sourceDeadlineWasFutureAtExpiryResponse = visibleUntilMs > Date.now();
  assert.equal((await expired.json()).error, "public_collection_expired");
  assert.ok(sourceDeadlineWasFutureAtExpiryResponse, "the server expiry arrives before the browser deadline");
  await page.waitForFunction(() => document.querySelector(".result-url") === null, null, { timeout: 1000 });
  assert.equal(await card.locator(".source-notice-text").count(), 0, "typed server expiry hides the retained notice before the browser timer fires");
  assert.equal(await card.locator(".source-attribution").count(), 0);
  assert.equal(await card.locator(".result-url").count(), 0);
  assert.equal(await card.locator(".result-title").count(), 0);
  assert.equal(await card.locator(".indexed-document-text").count(), 0);
  assert.equal(await card.locator(".reference-details").count(), 0);
  assert.equal(await card.locator('[role="alert"]').count(), 1, "typed expiry is announced once");
  assert.equal(
    (await card.locator('.verification-message[role="alert"]').textContent()).trim(),
    expiredEvidenceMessage,
    "terminal expiry explains that the source ended rather than implying the record is temporarily unavailable",
  );
  await card.getByText("public_collection_expired", { exact: true }).waitFor();

  releaseLateInspection.resolve();
  await lateInspectionHandled.promise;
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.equal(await card.locator(".source-notice-text").count(), 0, "a delayed inspection cannot restore the expired notice");
  assert.equal(await card.locator(".indexed-document-text").count(), 0, "a delayed inspection cannot restore extracted text");
  assert.equal(await card.locator(".result-url").count(), 0);
  assert.deepEqual(pageErrors, []);

  const evidenceDirectory = process.env.LEY_EXPIRY_EVIDENCE_DIR ?? tmpdir();
  await mkdir(evidenceDirectory, { recursive: true });
  const screenshot = path.join(evidenceDirectory, "site-evidence-expired.png");
  await page.screenshot({ path: screenshot, fullPage: true });

  await input.fill("superseded source lookup");
  await input.press("Enter");
  await staleSourceLookupStarted.promise;
  const latestSourceFailure = page.waitForResponse((response) => response.url().includes("/api/v1/evidence/source") && response.status() === 410);
  await input.fill("current source lookup");
  await input.press("Enter");
  await latestSourceFailure;
  await card.locator(".source-error .error-code").filter({ hasText: "public_collection_expired" }).waitFor();
  assert.equal(await card.getByRole("button", { name: "Check source again" }).count(), 0, "terminal source errors do not offer a retry for the same reference");
  releaseStaleSourceLookup.resolve();
  await staleSourceLookupHandled.promise;
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.equal(await card.locator(".source-notice-text").count(), 0, "a superseded source lookup cannot restore its notice");
  assert.equal(await card.locator(".result-url").count(), 0);
  assert.equal(await card.locator(".result-title").count(), 0);
  assert.equal(await card.locator(".evidence-passage").count(), 0);

  await input.fill("late resolve response");
  await input.press("Enter");
  await card.locator(".source-notice-text").waitFor();
  await card.getByRole("button", { name: "Revalidate passage" }).click();
  await lateResolveStarted.promise;
  const inspectExpiryResponse = page.waitForResponse((response) => response.url().includes("/api/v1/evidence/inspect") && response.status() === 410);
  await card.getByRole("button", { name: "Read current indexed text" }).click();
  const inspectionExpired = await inspectExpiryResponse;
  assert.equal((await inspectionExpired.json()).error, "public_collection_expired");
  await card.getByText("public_collection_expired", { exact: true }).waitFor();
  assert.equal(await card.locator(".source-notice-text").count(), 0);
  assert.equal(await card.locator(".result-url").count(), 0);
  assert.equal(await card.locator(".result-title").count(), 0);
  assert.equal(await card.locator(".reference-details").count(), 0);
  releaseLateResolve.resolve();
  await lateResolveHandled.promise;
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.equal(await card.locator(".source-notice-text").count(), 0, "a delayed resolve cannot restore the expired notice");
  assert.equal(await card.locator(".result-url").count(), 0);
  assert.equal(await card.locator(".evidence-passage").count(), 0);

  source.visible_until_ms = Date.now() + 1500;
  await input.fill("local timer expiry");
  await input.press("Enter");
  await card.locator(".source-notice-text").waitFor();
  assert.ok(source.visible_until_ms > Date.now(), "the timer fixture starts before its deadline");
  holdTimerInspection = true;
  await card.getByRole("button", { name: "Read current indexed text" }).click();
  await timerInspectionStarted.promise;
  await card.getByText(expiredEvidenceMessage, { exact: true }).first().waitFor({ timeout: 5000 });
  assert.equal(await card.locator(".source-notice-text").count(), 0, "local expiry hides retained source notice");
  assert.equal(await card.locator(".result-url").count(), 0);
  assert.equal(await card.locator(".indexed-document-text").count(), 0);
  assert.equal(await card.locator('[role="alert"]').count(), 1, "local timer expiry is announced once");
  assert.equal(await card.getByText("Checking current indexed text. Previously retrieved text is hidden.", { exact: true }).count(), 0, "expiry clears inspection's loading state");
  releaseTimerInspection.resolve();
  await timerInspectionHandled.promise;
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.equal(await card.locator(".source-notice-text").count(), 0, "a late inspection cannot restore expired source disclosure");
  assert.equal(await card.locator(".indexed-document-text").count(), 0);

  source.visible_until_ms = Date.now() + 30 * 60 * 1000;
  nextSourceErrorCode = "storage_fault";
  await input.fill("transient source record error");
  await input.press("Enter");
  await card.locator(".source-error .error-code").filter({ hasText: "storage_fault" }).waitFor();
  assert.equal(await card.getByRole("button", { name: "Check source again" }).count(), 1, "transient source errors keep an actionable retry");
  await card.getByRole("button", { name: "Check source again" }).click();
  await card.locator(".source-notice-text").waitFor();

  withholdNextSource = true;
  await input.fill("withheld source attribution");
  await input.press("Enter");
  await card.locator('.verification-message[role="status"]')
    .filter({ hasText: "Source attribution is withheld. Source details and extracted text remain hidden." })
    .waitFor();
  assert.equal(await card.locator(".source-notice-text").count(), 0);
  assert.equal(await card.locator(".result-url").count(), 0);
  assert.equal(await card.locator(".evidence-passage").count(), 0);
  const withheldAlerts = await card.locator('.verification-message[role="alert"]').allTextContents();
  assert.ok(withheldAlerts.every((message) => !/until its current source disclosure is available/i.test(message)));

  nextSourceKind = "local_index";
  await input.fill("local index version invalidation");
  await input.press("Enter");
  await card.getByText("This document is in the local index. No public-source attribution is recorded.", { exact: true }).waitFor();
  nextResolveErrorCode = "not_live";
  const localReferenceInvalid = page.waitForResponse((response) => response.url().includes("/api/v1/evidence/resolve") && response.status() === 410);
  await card.getByRole("button", { name: "Revalidate passage" }).click();
  await localReferenceInvalid;
  await card.getByText("This source is no longer in the current index. Previously displayed evidence text is hidden.", { exact: true }).waitFor();
  assert.doesNotMatch(await card.locator('.verification-message[role="alert"]').textContent(), /source notice/i);
  assert.equal(await card.locator(".evidence-passage").count(), 0);

  await input.fill("revoked source invalidation");
  await input.press("Enter");
  await card.locator(".source-notice-text").waitFor();
  nextResolveErrorCode = "revoked";
  const sourceRevoked = page.waitForResponse((response) => response.url().includes("/api/v1/evidence/resolve") && response.status() === 410);
  await card.getByRole("button", { name: "Revalidate passage" }).click();
  await sourceRevoked;
  await card.getByText("This source has been revoked. Previously displayed passage and source notice are hidden.", { exact: true }).waitFor();
  assert.equal(await card.locator(".source-notice-text").count(), 0);
  assert.equal(await card.locator(".result-url").count(), 0);
  assert.equal(await card.locator(".result-title").count(), 0);
  assert.equal(await card.locator(".evidence-passage").count(), 0);
  assert.equal(await card.locator('[role="alert"]').count(), 1, "revocation is announced once");
  assert.deepEqual(pageErrors, []);

  process.stdout.write(JSON.stringify({ result: "PASS", resolveRequests: resolveCount, inspectionRequests: inspectionCount, sourceLookupRequests: sourceLookupCount, sourceDeadlineWasFutureAtExpiryResponse, timerExpiredWhileInspectionPending: true, lateInspectionError: lateInspectionError ?? null, lateResolveError: lateResolveError ?? null, timerInspectionError: timerInspectionError ?? null, staleSourceLookupError: staleSourceLookupError ?? null, pageErrors, screenshot }, null, 2) + "\n");
} finally {
  releaseExpiry.resolve();
  releaseLateInspection.resolve();
  releaseLateResolve.resolve();
  releaseTimerInspection.resolve();
  releaseStaleSourceLookup.resolve();
  await browser?.close();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
