import { createReadStream } from "node:fs";
import { createServer } from "node:http";
import { stat } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const defaultRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../dist");

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

  function validRequestBoundary(request) {
    const host = localAuthority(request.headers.host);
    if (!host) return "invalid_host";

    const origin = request.headers.origin;
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
    const boundaryError = validRequestBoundary(request);
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
    if (request.method === "GET" && url.pathname === "/api/search") {
      try {
        const upstream = await fetch(`http://127.0.0.1:${apiPort}/api/search${url.search}`, {
          headers: { accept: "application/json" },
        });
        const upstreamHeaders = {
          "content-type": upstream.headers.get("content-type") ?? "application/json",
          "cache-control": "no-store",
        };
        const contentLength = upstream.headers.get("content-length");
        if (contentLength) upstreamHeaders["content-length"] = contentLength;
        response.writeHead(upstream.status, upstreamHeaders);
        response.end(Buffer.from(await upstream.arrayBuffer()));
      } catch {
        reject(response, 502, "index_api_unavailable");
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
