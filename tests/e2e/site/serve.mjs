// =============================================================================
// Static server for the website in design/, used by tests/e2e/site.spec.ts.
// =============================================================================
// Mirrors what Cloudflare Workers static assets does with the folder:
//   * design/_headers is parsed with Cloudflare's rules (comments, one block
//     per URL pattern, a single `*` splat, `! Name` detaches, repeated names
//     joined with ", ") and applied to every response. A syntax error aborts
//     start-up, so a broken _headers file fails the suite.
//   * `_headers` itself is never served.
//   * /foo serves foo.html, / serves index.html (html_handling default).
// It deliberately has no dependencies so it runs from a bare `node`.
// =============================================================================

import { createServer } from "node:http";
import { readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(
  process.env.SITE_ROOT ?? path.join(here, "..", "..", "..", "design"),
);
const PORT = Number(process.env.SITE_PORT ?? 19180);

const MAX_RULES = 100;
const MAX_LINE = 2000;

export function parseHeaders(text) {
  const rules = [];
  let current = null;
  text.split(/\r?\n/).forEach((line, i) => {
    const where = `_headers:${i + 1}`;
    if (line.length > MAX_LINE)
      throw new Error(`${where}: line over ${MAX_LINE} chars`);
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) return;
    if (!/^\s/.test(line)) {
      if (!/^(\/|https:\/\/)/.test(trimmed))
        throw new Error(`${where}: rule must start with / or https://`);
      if ((trimmed.match(/\*/g) ?? []).length > 1)
        throw new Error(`${where}: only one splat allowed`);
      current = { pattern: trimmed, set: [], detach: [] };
      rules.push(current);
      return;
    }
    if (!current)
      throw new Error(`${where}: header line before any URL pattern`);
    if (trimmed.startsWith("! ")) {
      current.detach.push(trimmed.slice(2).trim().toLowerCase());
      return;
    }
    const colon = trimmed.indexOf(":");
    if (colon <= 0) throw new Error(`${where}: expected "Name: value"`);
    const name = trimmed.slice(0, colon).trim();
    if (!/^[A-Za-z0-9-]+$/.test(name))
      throw new Error(`${where}: bad header name ${name}`);
    current.set.push([name, trimmed.slice(colon + 1).trim()]);
  });
  if (rules.length > MAX_RULES)
    throw new Error(`_headers: ${rules.length} rules, max ${MAX_RULES}`);
  for (const r of rules) {
    if (r.set.length === 0 && r.detach.length === 0)
      throw new Error(`_headers: rule ${r.pattern} has no headers`);
  }
  return rules;
}

function matches(pattern, pathname) {
  const re = new RegExp(
    "^" +
      pattern
        .split("*")
        .map((p) =>
          p
            .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
            .replace(/:[A-Za-z]\w*/g, "[^/]+"),
        )
        .join(".*") +
      "$",
  );
  return re.test(pathname);
}

export function headersFor(rules, pathname) {
  const out = new Map();
  const detached = new Set();
  for (const r of rules) {
    if (!matches(r.pattern, pathname)) continue;
    for (const [name, value] of r.set) {
      const key = name.toLowerCase();
      const prev = out.get(key);
      out.set(key, prev ? [prev[0], `${prev[1]}, ${value}`] : [name, value]);
    }
    r.detach.forEach((d) => detached.add(d));
  }
  detached.forEach((d) => out.delete(d));
  return [...out.values()];
}

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
  ".asc": "application/octet-stream",
};

function resolveFile(pathname) {
  const rel = decodeURIComponent(pathname).replace(/^\/+/, "");
  if (rel.split("/").includes("..") || rel === "_headers") return null;
  const candidates =
    rel === "" ? ["index.html"] : [rel, `${rel}.html`, `${rel}/index.html`];
  for (const c of candidates) {
    const full = path.join(ROOT, c);
    try {
      if (statSync(full).isFile()) return full;
    } catch {
      // try the next candidate
    }
  }
  return null;
}

const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  let text = "";
  try {
    text = readFileSync(path.join(ROOT, "_headers"), "utf8");
  } catch {
    // No _headers: serve without custom headers so the spec reports what is missing.
  }
  const rules = parseHeaders(text);
  createServer((req, res) => {
    const { pathname } = new URL(req.url ?? "/", "http://localhost");
    const file = resolveFile(pathname);
    for (const [name, value] of headersFor(rules, pathname))
      res.setHeader(name, value);
    if (!file) {
      res.statusCode = 404;
      res.end("not found");
      return;
    }
    if (!res.hasHeader("content-type")) {
      res.setHeader(
        "Content-Type",
        TYPES[path.extname(file)] ?? "application/octet-stream",
      );
    }
    res.end(readFileSync(file));
  }).listen(PORT, "127.0.0.1", () => {
    console.log(
      `design/ served on http://127.0.0.1:${PORT} (${rules.length} _headers rules)`,
    );
  });
}
