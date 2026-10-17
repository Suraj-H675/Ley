import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { build } from "esbuild";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const output = path.join(root, "dist");
await mkdir(output, { recursive: true });
await build({
  absWorkingDir: root,
  entryPoints: ["src/main.tsx"],
  bundle: true,
  format: "esm",
  target: "es2022",
  jsx: "automatic",
  minify: true,
  sourcemap: false,
  outdir: output,
  entryNames: "main",
  assetNames: "[name]",
  logLevel: "warning",
});
const document = await readFile(path.join(root, "index.html"), "utf8");
await writeFile(
  path.join(output, "index.html"),
  document.replace(
    '<script type="module" src="/src/main.tsx"></script>',
    '<link rel="stylesheet" href="/main.css" />\n    <script type="module" src="/main.js"></script>',
  ),
);
const notice = await readFile(
  path.join(root, "..", "notices", "rust-stdlib-documentation-MIT.txt"),
);
await writeFile(path.join(output, "rust-stdlib-documentation-MIT.txt"), notice);
