// Smoke test for the static build: load the bundled engine in Pyodide (Node)
// and check that each sample gets the expected verdict.
//   node scripts/check_site.js site tests/samples
"use strict";
const path = require("path"), fs = require("fs");
const site = path.resolve(process.argv[2] || "site"), samples = path.resolve(process.argv[3] || "tests/samples");
const expected = {
  "legit_github.eml": "low", "phish_paypal.eml": "high", "o365_spoof.eml": "high", "esp_spoof_payload.eml": "high",
  "html_smuggling.eml": "high", "archive_payloads.eml": "high", "iso_lnk.eml": "high", "quishing.eml": "high",
  "thread_hijack.eml": "high", "calendar_phish.eml": "medium",
  "outlook_phish.msg": "high", "outlook_sent_item.msg": "low",
};
// Every message in the false-positive corpus must stay low risk in the browser too.
for (const f of fs.readdirSync(path.join(samples, "fp"))) if (f.endsWith(".eml")) expected["fp/" + f] = "low";
const { loadPyodide } = require(path.join(site, "static/pyodide/pyodide.js"));

(async () => {
  const py = await loadPyodide({ indexURL: path.join(site, "static/pyodide") + path.sep });
  const zip = new Uint8Array(fs.readFileSync(path.join(site, "static/py/esha-bundle.zip")));
  py.unpackArchive(zip.buffer, "zip", { extractDir: "/esha_lib" });
  py.runPython([
    "import sys, json",
    "sys.path.insert(0, '/esha_lib')",
    "from esha.core import analyze",
    "from esha.core.inputs import decode_bytes",
    "def run(data, name):",
    "    text, from_file, source = decode_bytes(bytes(data.to_py()), name)",
    "    return json.dumps(analyze(text, from_file=from_file, source=source), default=str)",
  ].join("\n"));
  let failed = 0;
  for (const [file, level] of Object.entries(expected)) {
    // Same path as the browser: raw file bytes through decode_bytes (handles .eml and .msg).
    const r = JSON.parse(py.globals.get("run")(new Uint8Array(fs.readFileSync(path.join(samples, file))), path.basename(file)));
    const ok = r.score.level === level;
    if (!ok) failed++;
    console.log(`${ok ? "ok  " : "FAIL"} ${file}: ${r.score.level} (${r.score.value}), expected ${level}`);
  }
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
