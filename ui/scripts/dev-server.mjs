import { createReadStream } from "node:fs";
import { createServer } from "node:http";
import { stat } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const defaultRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../dist");
const MAX_API_BODY_BYTES = 16 * 1024;
const MAX_API_RESPONSE_BYTES = 512 * 1024;
const QUESTION_ROUTES = new Set(["/api/v1/retrieve", "/api/v1/evidence/resolve"]);

const mime = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".txt", "text/plain; charset=utf-8"],
]);

function reject(response, status, code) {
  const body = JSON.stringify({ error: code });
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(body);
}

function rawHeaderValues(request, name) {
  const values = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index].toLowerCase() === name.toLowerCase()) {
      values.push(request.rawHeaders[index + 1]);
    }
  }
  return values;
}

function rejectWithHeaders(response, status, code, headers = {}) {
  const body = JSON.stringify({ error: code });
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    ...headers,
  });
  response.end(body);
}

async function readBounded(request, limit) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    length += bytes.length;
    if (length > limit) throw new RangeError("request body exceeds limit");
    chunks.push(bytes);
  }
  return Buffer.concat(chunks, length);
}

async function readUpstreamBounded(response, limit) {
  const chunks = [];
  let length = 0;
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const bytes = Buffer.from(value);
    length += bytes.length;
    if (length > limit) {
      await reader.cancel().catch(() => {});
      throw new RangeError("upstream response exceeds limit");
    }
    chunks.push(bytes);
  }
  return Buffer.concat(chunks, length);
}

export function createUiServer({ root = defaultRoot, port = 0, apiPort = 7331 } = {}) {
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error("port must be a valid TCP port");
  }
  if (!Number.isInteger(apiPort) || apiPort < 1 || apiPort > 65535) {
    throw new Error("apiPort must be a valid TCP port");
  }

  function localAuthority(value) {
    if (typeof value !== "string" || value.includes(",")) return null;
    try {
      const parsed = new URL(`http://${value}`);
      const hostname = parsed.hostname.toLowerCase();
      const allowedHost = hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
      const boundPort = server.address()?.port ?? port;
      if (!allowedHost || parsed.port !== String(boundPort) || parsed.username || parsed.password) return null;
      return parsed.host.toLowerCase();
    } catch {
      return null;
    }
  }

  function validRequestBoundary(request, requireOrigin = false) {
    const hostValues = rawHeaderValues(request, "host");
    if (hostValues.length !== 1) return "invalid_host";
    const host = localAuthority(hostValues[0]);
    if (!host) return "invalid_host";

    const origins = rawHeaderValues(request, "origin");
    if (origins.length > 1 || (requireOrigin && origins.length !== 1)) return "invalid_origin";
    const origin = origins[0];
    if (origin !== undefined) {
      if (typeof origin !== "string" || origin.includes(",")) return "invalid_origin";
      try {
        const parsed = new URL(origin);
        if (
          parsed.protocol !== "http:" ||
          parsed.origin !== `http://${host}` ||
          parsed.pathname !== "/" ||
          parsed.search ||
          parsed.hash ||
          parsed.username ||
          parsed.password
        ) return "invalid_origin";
      } catch {
        return "invalid_origin";
      }
    }
    return null;
  }

  const server = createServer(async (request, response) => {
    const boundaryError = validRequestBoundary(request, request.method === "POST");
    if (boundaryError) {
      reject(response, 403, boundaryError);
      request.resume();
      return;
    }
    if (typeof request.url !== "string" || request.url.length > 12 * 1024) {
      reject(response, 414, "request_target_too_large");
      request.resume();
      return;
    }
    let url;
    try {
      if (!request.url.startsWith("/") || request.url.startsWith("//")) throw new TypeError("origin-form required");
      url = new URL(request.url, `http://${request.headers.host}`);
    } catch {
      reject(response, 400, "invalid_request_target");
      request.resume();
      return;
    }
    if (QUESTION_ROUTES.has(url.pathname)) {
      if (request.method !== "POST") {
        rejectWithHeaders(response, 405, "method_not_allowed", { allow: "POST" });
        request.resume();
        return;
      }
      if (url.search || url.hash) {
        reject(response, 400, "invalid_request_target");
        request.resume();
        return;
      }
      const contentTypes = rawHeaderValues(request, "content-type");
      const accepts = rawHeaderValues(request, "accept");
      if (contentTypes.length !== 1 || contentTypes[0].trim().toLowerCase() !== "application/json") {
        reject(response, 415, "unsupported_media_type");
        request.resume();
        return;
      }
      if (accepts.length !== 1 || accepts[0].trim().toLowerCase() !== "application/json") {
        reject(response, 406, "not_acceptable");
        request.resume();
        return;
      }
      const contentLengths = rawHeaderValues(request, "content-length");
      if (contentLengths.length > 1) {
        reject(response, 400, "invalid_request");
        request.resume();
        return;
      }
      if (contentLengths.length === 1) {
        const length = Number(contentLengths[0]);
        if (!Number.isSafeInteger(length) || length < 0) {
          reject(response, 400, "invalid_request");
          request.resume();
          return;
        }
        if (length > MAX_API_BODY_BYTES) {
          reject(response, 413, "resource_cap");
          request.resume();
          return;
        }
      }
      const contentEncodings = rawHeaderValues(request, "content-encoding");
      if (contentEncodings.length > 1 || (contentEncodings.length === 1 && contentEncodings[0].trim().toLowerCase() !== "identity")) {
        reject(response, 415, "unsupported_media_type");
        request.resume();
        return;
      }
      try {
        const body = await readBounded(request, MAX_API_BODY_BYTES);
        const apiOrigin = `http://127.0.0.1:${apiPort}`;
        const upstream = await fetch(`${apiOrigin}${url.pathname}`, {
          method: "POST",
          headers: {
            accept: "application/json",
            "content-type": "application/json",
            origin: apiOrigin,
          },
          body,
        });
        const bytes = await readUpstreamBounded(upstream, MAX_API_RESPONSE_BYTES);
        response.writeHead(upstream.status, {
          "content-type": upstream.headers.get("content-type") ?? "application/json; charset=utf-8",
          "content-length": bytes.length,
          "cache-control": "no-store",
          "x-content-type-options": "nosniff",
        });
        response.end(bytes);
      } catch (error) {
        if (error instanceof RangeError) {
          reject(response, 413, "resource_cap");
        } else {
          reject(response, 502, "index_api_unavailable");
        }
      }
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/search") {
      try {
        const upstream = await fetch(`http://127.0.0.1:${apiPort}/api/search${url.search}`, {
          headers: { accept: "application/json" },
        });
        const upstreamHeaders = {
          "content-type": upstream.headers.get("content-type") ?? "application/json",
          "cache-control": "no-store",
        };
        const bytes = await readUpstreamBounded(upstream, MAX_API_RESPONSE_BYTES);
        upstreamHeaders["content-length"] = bytes.length;
        response.writeHead(upstream.status, upstreamHeaders);
        response.end(bytes);
      } catch (error) {
        if (error instanceof RangeError) reject(response, 502, "upstream_response_too_large");
        else reject(response, 502, "index_api_unavailable");
      }
      return;
    }
    if (request.method !== "GET") {
      response.writeHead(405, { allow: "GET", "content-type": "text/plain; charset=utf-8" });
      response.end("Method not allowed");
      return;
    }

    const file = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
    if (!new Set(["index.html", "main.js", "main.css", "rust-stdlib-documentation-MIT.txt"]).has(file)) {
      response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      response.end("Not found");
      return;
    }
    const filePath = path.join(root, file);
    try {
      const details = await stat(filePath);
      response.writeHead(200, {
        "content-type": mime.get(path.extname(filePath)) ?? "application/octet-stream",
        "content-length": details.size,
        "x-content-type-options": "nosniff",
        "cache-control": file === "index.html" ? "no-store" : "public, max-age=300",
      });
      createReadStream(filePath).pipe(response);
    } catch {
      response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      response.end("Not found");
    }
  });
  return server;
}

const entryPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (entryPath === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.LEY_UI_PORT ?? 4173);
  const apiPort = Number(process.env.LEY_API_PORT ?? 7331);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    throw new Error("LEY_UI_PORT must be a TCP port between 1024 and 65535");
  }
  const server = createUiServer({ root: defaultRoot, port, apiPort });
  server.listen(port, "127.0.0.1", () => {
    process.stdout.write(`Ley UI listening at http://127.0.0.1:${port}\n`);
  });
}
