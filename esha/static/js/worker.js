/* ESHA in-browser engine: runs the Python analyzer (esha.core) with Pyodide
   inside a Web Worker. Nothing leaves the browser: the only requests are for
   ESHA's own static files (Pyodide runtime and the bundled Python code). */
"use strict";

var base = new URL("../", self.location.href).href; // .../static/
importScripts(base + "pyodide/pyodide.js");

var ready = (async function () {
  var py = await loadPyodide({ indexURL: base + "pyodide/" });
  var resp = await fetch(base + "py/esha-bundle.zip" + self.location.search);  // ?v=<version> busts caches
  if (!resp.ok) throw new Error("Could not load the analysis engine (" + resp.status + ").");
  py.unpackArchive(await resp.arrayBuffer(), "zip", { extractDir: "/esha_lib" });
  py.runPython([
    "import sys, json",
    "sys.path.insert(0, '/esha_lib')",
    "from esha.core import analyze as _analyze",
    "from esha.core.inputs import MsgError, decode_bytes",
    "def esha_run(text, data, name):",
    "    source, from_file = None, False",
    "    if data is not None:",
    "        try:",
    "            text, from_file, source = decode_bytes(bytes(data.to_py()), name or '')",
    "        except MsgError as e:",
    "            raise ValueError(str(e)) from None",
    "    return json.dumps(_analyze(text, from_file=bool(from_file), source=source), default=str)",
    "def esha_export(report_json, fmt):",
    "    from esha.core.exports import export",
    "    return json.dumps(list(export(json.loads(report_json), fmt)))",
  ].join("\n"));
  return py;
})();

self.onmessage = async function (e) {
  var msg = e.data || {};
  try {
    var py = await ready;
    if (msg.type === "warmup") { self.postMessage({ id: msg.id, ok: true, result: null }); return; }
    if (msg.type === "export") {
      var exp = py.globals.get("esha_export");
      var res = JSON.parse(exp(msg.report, msg.format));
      exp.destroy();
      self.postMessage({ id: msg.id, ok: true, result: { content: res[0], type: res[1], name: res[2] } });
      return;
    }
    var run = py.globals.get("esha_run");
    // undefined (not null) maps to Python None; Pyodide turns null into a JsNull object.
    var data = msg.bytes ? new Uint8Array(msg.bytes) : undefined;
    var out = run(msg.text || "", data, msg.name || "");
    run.destroy();
    self.postMessage({ id: msg.id, ok: true, result: JSON.parse(out) });
  } catch (err) {
    self.postMessage({ id: msg.id, ok: false, error: String((err && err.message) || err).split("\n").slice(-2).join(" ").trim() });
  }
};
