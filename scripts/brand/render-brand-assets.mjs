// Renders raster brand assets (favicon PNG, touch/app icons, OG share image)
// from our own SVG mark and fonts using a local headless Chrome.
//
// Usage:
//   PUPPETEER_CORE=<path to puppeteer-core> CHROME=<path to chrome> node scripts/brand/render-brand-assets.mjs
//
// puppeteer-core is intentionally not a project dependency; point
// PUPPETEER_CORE at any local install. Outputs go to web/public/.

import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const pub = join(root, "web/public");
const puppeteerPath = process.env.PUPPETEER_CORE;
const chromePath = process.env.CHROME ?? "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
if (!puppeteerPath) {
  console.error("Set PUPPETEER_CORE to a local puppeteer-core directory.");
  process.exit(1);
}
const puppeteer = (await import(pathToFileURL(join(puppeteerPath, "lib/esm/puppeteer/puppeteer-core.js")).href)).default;

const favicon = await readFile(join(pub, "favicon.svg"), "utf8");
const mark = await readFile(join(pub, "brand/mark.svg"), "utf8");
const fontSans = pathToFileURL(join(pub, "fonts/inter-var-latin.woff2")).href;
const fontMono = pathToFileURL(join(pub, "fonts/jetbrains-mono-var-latin.woff2")).href;

const iconHtml = (size, bg = "transparent") => `<!doctype html><html><head><style>
  html,body{margin:0;background:${bg}}
  svg{display:block;width:${size}px;height:${size}px}
</style></head><body>${favicon}</body></html>`;

const ogHtml = `<!doctype html><html><head><style>
@font-face{font-family:Inter;src:url("${fontSans}") format("woff2");font-weight:100 900}
@font-face{font-family:JBM;src:url("${fontMono}") format("woff2");font-weight:100 800}
*{box-sizing:border-box}
html,body{margin:0;width:1200px;height:630px;overflow:hidden}
body{font-family:Inter,sans-serif;color:#e8ece6;
  background:
    radial-gradient(700px 420px at 88% 20%, rgba(183,255,74,.12), transparent 65%),
    radial-gradient(640px 480px at 0% 100%, rgba(20,50,32,.75), transparent 65%),
    #07080a;
  position:relative}
.grid{position:absolute;inset:0;
  background-image:linear-gradient(rgba(233,240,228,.06) 1px,transparent 1px),linear-gradient(90deg,rgba(233,240,228,.06) 1px,transparent 1px);
  background-size:60px 60px;
  -webkit-mask-image:radial-gradient(ellipse 65% 70% at 75% 40%,#000 15%,transparent 75%)}
.wrap{position:absolute;inset:0;padding:64px 72px;display:flex;flex-direction:column}
.brand{display:flex;align-items:center;gap:16px}
.brand svg{width:52px;height:52px}
.brand svg path[stroke="#E8ECE6"]{stroke:#e8ece6}
.word{font-size:30px;font-weight:650;letter-spacing:-.02em}
.ai{margin-left:8px;font:600 15px/1 JBM;padding:5px 7px;border-radius:6px;color:#b7ff4a;border:1.5px solid rgba(183,255,74,.35);vertical-align:5px}
.tag{margin-left:auto;font:500 15px/1 JBM;letter-spacing:.14em;text-transform:uppercase;color:#a4acb2}
h1{margin:72px 0 0;font-size:74px;line-height:1.02;letter-spacing:-.045em;font-weight:650;max-width:900px}
h1 span{display:block;color:#b7ff4a}
.sub{margin-top:30px;font:500 22px/1.3 JBM;color:#c3c9cc}
.row{margin-top:auto;display:flex;gap:12px;align-items:center}
.pill{font:700 15px/1 JBM;letter-spacing:.1em;padding:10px 14px;border-radius:7px;border:1.5px solid}
.a{color:#b7ff4a;border-color:rgba(183,255,74,.4);background:rgba(183,255,74,.08)}
.r{color:#e9b54a;border-color:rgba(233,181,74,.4);background:rgba(233,181,74,.08)}
.b{color:#ee6a5f;border-color:rgba(238,106,95,.4);background:rgba(238,106,95,.08)}
.note{margin-left:18px;font-size:18px;color:#a4acb2}
</style></head><body><div class="grid"></div><div class="wrap">
  <div class="brand">${mark}<span class="word">Mother<span class="ai">AI</span></span><span class="tag">Control Plane for AI Agents</span></div>
  <h1>Your AI has permissions. <span>Mother enforces them.</span></h1>
  <div class="sub">Identity. Permissions. Human Approval. Audit Trails.</div>
  <div class="row"><span class="pill a">ALLOW</span><span class="pill r">REVIEW</span><span class="pill b">BLOCK</span><span class="note">Deterministic access control for AI agents and MCP tools</span></div>
</div></body></html>`;

const profile = await mkdtemp(join(process.env.QA_PROFILE_DIR ?? tmpdir(), "mother-brand-"));
const browser = await puppeteer.launch({
  executablePath: chromePath,
  headless: true,
  userDataDir: profile,
  args: ["--no-first-run", "--no-default-browser-check", "--allow-file-access-from-files"],
});

try {
  const page = await browser.newPage();

  for (const [name, size] of [
    ["favicon-32.png", 32],
    ["apple-touch-icon.png", 180],
    ["icon-512.png", 512],
  ]) {
    await page.setViewport({ width: size, height: size, deviceScaleFactor: 1 });
    await page.setContent(iconHtml(size, name === "apple-touch-icon.png" ? "#07080a" : "transparent"), { waitUntil: "load" });
    const buf = await page.screenshot({ type: "png", omitBackground: name !== "apple-touch-icon.png", clip: { x: 0, y: 0, width: size, height: size } });
    await writeFile(join(pub, name), buf);
    console.log("wrote", name);
  }

  const htmlFile = join(profile, "og.html");
  await writeFile(htmlFile, ogHtml);
  await page.setViewport({ width: 1200, height: 630, deviceScaleFactor: 1 });
  await page.goto(pathToFileURL(htmlFile).href, { waitUntil: "load" });
  await page.evaluate(() => document.fonts.ready);
  await writeFile(join(pub, "og.png"), await page.screenshot({ type: "png", clip: { x: 0, y: 0, width: 1200, height: 630 } }));
  console.log("wrote og.png");
} finally {
  await browser.close();
  await rm(profile, { recursive: true, force: true }).catch(() => {});
}
