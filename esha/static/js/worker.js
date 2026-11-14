/* ESHA in-browser engine: runs the Python analyzer (esha.core) with Pyodide
   inside a Web Worker. Nothing leaves the browser: the only requests are for
   ESHA's own static files (Pyodide runtime and the bundled Python code). */
"use strict";

var base = new URL("../", self.location.href).href; // .../static/
importScripts(base + "pyodide/pyodide.js");

var ready = (async function () {
  var py = await loadPyodide({ indexURL: base + "pyodide/" });
  var resp = await fetch(base + "py/esha-bundle.zip");
  if (!resp.ok) throw new Error("Could not load the analysis engine (" + resp.status + ").");
  py.unpackArchive(await resp.arrayBuffer(), "zip", { extractDir: "/esha_lib" });
  py.runPython([
    "import sys, json",
    "sys.path.insert(0, '/esha_lib')",
    "from esha.core import analyze as _analyze",
    "def _decode(data):",
    "    for enc in ('utf-8', 'latin-1'):",
    "        try:",
    "            return data.decode(enc)",
    "        except UnicodeDecodeError:",
    "            pass",
    "    return data.decode('utf-8', 'replace')",
    "def esha_run(text, data, from_file):",
    "    if data is not None:",
    "        text = _decode(bytes(data.to_py()))",
    "    return json.dumps(_analyze(text, from_file=bool(from_file)), default=str)",
  ].join("\n"));
  return py;
})();

self.onmessage = async function (e) {
  var msg = e.data || {};
  try {
    var py = await ready;
    if (msg.type === "warmup") { self.postMessage({ id: msg.id, ok: true, result: null }); return; }
    var run = py.globals.get("esha_run");
    // undefined (not null) maps to Python None; Pyodide turns null into a JsNull object.
    var data = msg.bytes ? new Uint8Array(msg.bytes) : undefined;
    var out = run(msg.text || "", data, !!msg.fromFile);
    run.destroy();
    self.postMessage({ id: msg.id, ok: true, result: JSON.parse(out) });
  } catch (err) {
    self.postMessage({ id: msg.id, ok: false, error: String((err && err.message) || err).split("\n").slice(-2).join(" ").trim() });
  }
};
