// Smoke test for the static build: load the bundled engine in Pyodide (Node)
// and check that each sample gets the expected verdict.
//   node scripts/check_site.js site tests/samples
"use strict";
const path = require("path"), fs = require("fs");
const site = path.resolve(process.argv[2] || "site"), samples = path.resolve(process.argv[3] || "tests/samples");
const expected = { "legit_github.eml": "low", "phish_paypal.eml": "high", "o365_spoof.eml": "high", "esp_spoof_payload.eml": "high" };
const { loadPyodide } = require(path.join(site, "static/pyodide/pyodide.js"));

(async () => {
  const py = await loadPyodide({ indexURL: path.join(site, "static/pyodide") + path.sep });
  const zip = new Uint8Array(fs.readFileSync(path.join(site, "static/py/esha-bundle.zip")));
  py.unpackArchive(zip.buffer, "zip", { extractDir: "/esha_lib" });
  py.runPython("import sys, json; sys.path.insert(0, '/esha_lib'); from esha.core import analyze");
  let failed = 0;
  for (const [file, level] of Object.entries(expected)) {
    py.globals.set("txt", fs.readFileSync(path.join(samples, file), "utf8"));
    const r = JSON.parse(py.runPython("json.dumps(analyze(txt, from_file=True), default=str)"));
    const ok = r.score.level === level;
    if (!ok) failed++;
    console.log(`${ok ? "ok  " : "FAIL"} ${file}: ${r.score.level} (${r.score.value}), expected ${level}`);
  }
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
