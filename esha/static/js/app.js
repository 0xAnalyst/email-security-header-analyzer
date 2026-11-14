/* ESHA front end. All untrusted header content is inserted with textContent. */
(function () {
  "use strict";

  var $ = function (s, r) { return (r || document).querySelector(s); };
  var form = $("#form"), ta = $("#headers"), drop = $("#drop"), fileIn = $("#file");
  var intake = $("#intake"), report = $("#report"), errBox = $("#error");
  var btnAnalyze = $("#btn-analyze"), btnNew = $("#btn-new"), btnExport = $("#btn-export"), btnCopy = $("#btn-copy");
  var last = null;

  function h(tag, attrs) {
    var el = document.createElement(tag);
    if (attrs) for (var k in attrs) {
      var v = attrs[k];
      if (v == null || v === false) continue;
      if (k === "text") el.textContent = v;
      else if (k === "class") el.className = v;
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (var i = 2; i < arguments.length; i++) {
      var c = arguments[i];
      if (c == null || c === false) continue;
      if (Array.isArray(c)) c.forEach(function (x) { if (x != null && x !== false) el.append(x); });
      else el.append(c);
    }
    return el;
  }
  var SVG = "http://www.w3.org/2000/svg";
  function s(tag, attrs) {
    var el = document.createElementNS(SVG, tag);
    for (var k in attrs || {}) { if (k === "text") el.textContent = attrs[k]; else el.setAttribute(k, attrs[k]); }
    for (var i = 2; i < arguments.length; i++) if (arguments[i]) el.appendChild(arguments[i]);
    return el;
  }

  function dur(sec) {
    if (sec == null) return "";
    sec = Math.round(sec);
    if (sec < 60) return sec + " s";
    var parts = [], units = [["d", 86400], ["h", 3600], ["min", 60], ["s", 1]];
    units.forEach(function (u) { if (sec >= u[1]) { parts.push(Math.floor(sec / u[1]) + " " + u[0]); sec %= u[1]; } });
    return parts.slice(0, 2).join(" ");
  }
  function fmtTime(iso) {
    if (!iso) return "";
    var d = new Date(iso);
    if (isNaN(d)) return iso;
    return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC").replace("Z", " UTC");
  }
  function toast(msg) {
    var t = h("div", { class: "toast", role: "status", text: msg });
    document.body.append(t);
    setTimeout(function () { t.remove(); }, 2200);
  }
  function showError(msg) { errBox.textContent = msg; errBox.hidden = !msg; }

  /* ---------------- theme ---------------- */
  $("#btn-theme").addEventListener("click", function () {
    var next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("esha-theme", next); } catch (e) {}
  });

  /* ---------------- input ---------------- */
  /* Two engines: "server" posts to the Flask API; "browser" (static hosting such as
     GitHub Pages) runs the same Python analyzer locally in a Pyodide Web Worker. */
  var engineMeta = document.querySelector('meta[name="esha-engine"]');
  var ENGINE = engineMeta ? engineMeta.getAttribute("content") : "server";
  var engineStatus = $("#engine-status");
  var worker = null, seq = 0, pending = {};

  function failAll(msg) {
    Object.keys(pending).forEach(function (k) { pending[k].reject(new Error(msg)); });
    pending = {};
  }
  function engineWorker() {
    if (worker) return worker;
    worker = new Worker("static/js/worker.js");
    worker.onmessage = function (e) {
      var p = pending[e.data.id];
      if (!p) return;
      delete pending[e.data.id];
      if (e.data.ok) p.resolve(e.data.result); else p.reject(new Error(e.data.error || "The analysis failed."));
    };
    worker.onerror = function () {
      worker = null;
      failAll("The analysis engine could not be loaded. Reload the page to try again.");
    };
    return worker;
  }
  function callWorker(msg, transfer) {
    return new Promise(function (resolve, reject) {
      msg.id = ++seq;
      pending[msg.id] = { resolve: resolve, reject: reject };
      engineWorker().postMessage(msg, transfer || []);
    });
  }
  function setEngineStatus(text, state) {
    if (!engineStatus) return;
    engineStatus.textContent = text;
    engineStatus.setAttribute("data-state", state);
  }
  if (ENGINE === "browser") {
    setEngineStatus("Loading the analysis engine (about 6 MB, cached after the first visit)…", "loading");
    callWorker({ type: "warmup" }).then(function () {
      setEngineStatus("Engine ready. Analysis runs in this browser tab; nothing is uploaded.", "ready");
    }, function (e) { setEngineStatus(e.message, "error"); });
  }

  function runAnalysis(body) {
    if (ENGINE === "browser") {
      if (body instanceof Blob) {
        var name = body.name || "";
        return body.arrayBuffer().then(function (buf) {
          return callWorker({ bytes: buf, fromFile: /\.(eml|mbox)$/i.test(name) }, [buf]);
        });
      }
      return callWorker({ text: body });
    }
    var opts = { method: "POST" };
    if (body instanceof Blob) { var fd = new FormData(); fd.append("file", body, body.name || "message.eml"); opts.body = fd; }
    else { opts.headers = { "Content-Type": "application/json" }; opts.body = JSON.stringify({ headers: body }); }
    return fetch("api/analyze", opts)
      .catch(function () { throw new Error("The server could not be reached. Check that ESHA is still running."); })
      .then(function (r) {
        return r.json().then(function (j) {
          if (!r.ok) throw new Error(j.error || "The server could not analyze these headers.");
          return j;
        });
      });
  }

  function analyze(body) {
    showError("");
    btnAnalyze.disabled = true; btnAnalyze.textContent = "Analyzing…";
    return runAnalysis(body)
      .then(function (j) { last = j; render(j); })
      .catch(function (e) { showError(e.message || "The analysis failed."); })
      .finally(function () { btnAnalyze.disabled = false; btnAnalyze.textContent = "Analyze headers"; });
  }
  function analyzeFile(file) {
    if (!file) return;
    file.text().then(function (t) { ta.value = t.split(/\r?\n\r?\n/)[0]; });
    analyze(file);
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    if (!ta.value.trim()) { showError("Paste the message headers first, or open an .eml file."); ta.focus(); return; }
    analyze(ta.value);
  });
  ta.addEventListener("keydown", function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") form.requestSubmit();
  });
  fileIn.addEventListener("change", function () { analyzeFile(fileIn.files[0]); fileIn.value = ""; });
  ["dragenter", "dragover"].forEach(function (ev) {
    document.addEventListener(ev, function (e) {
      if (e.dataTransfer && Array.prototype.indexOf.call(e.dataTransfer.types, "Files") >= 0) { e.preventDefault(); drop.classList.add("dragging"); }
    });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    document.addEventListener(ev, function (e) {
      if (ev === "dragleave" && e.relatedTarget) return;
      drop.classList.remove("dragging");
      if (ev === "drop" && e.dataTransfer && e.dataTransfer.files.length) { e.preventDefault(); analyzeFile(e.dataTransfer.files[0]); }
    });
  });
  document.querySelectorAll("[data-sample]").forEach(function (b) {
    b.addEventListener("click", function () {
      fetch("static/samples/" + b.getAttribute("data-sample")).then(function (r) { return r.text(); })
        .then(function (t) { ta.value = t.trim(); analyze(ta.value); });
    });
  });

  btnNew.addEventListener("click", function () {
    report.hidden = true; intake.hidden = false;
    [btnNew, btnExport, btnCopy].forEach(function (b) { b.hidden = true; });
    history.replaceState(null, "", location.pathname);
    ta.focus(); ta.select();
  });
  btnExport.addEventListener("click", function () {
    if (!last) return;
    var blob = new Blob([JSON.stringify(last, null, 2)], { type: "application/json" });
    var a = h("a", { href: URL.createObjectURL(blob), download: "esha-report-" + (last.meta.analyzed_at || "").replace(/[:]/g, "") + ".json" });
    document.body.append(a); a.click(); a.remove();
  });
  btnCopy.addEventListener("click", function () {
    if (!last) return;
    var r = last, sm = r.summary, a = r.auth, lines = [
      "Verdict: " + r.score.label + " (" + r.score.value + "/100)",
      "Subject: " + (sm.subject || ""), "From: " + (sm.from.raw || ""), "Date: " + (sm.date || ""),
      "SPF: " + a.spf.result + "  DKIM: " + a.dkim.result + "  DMARC: " + a.dmarc.result + (a.dmarc.computed ? " (computed)" : ""),
    ];
    if (r.origin) lines.push("Origin IP: " + r.origin.ip + (r.origin.geo && r.origin.geo.country ? " (" + r.origin.geo.country + ")" : ""));
    lines.push("", "Findings:");
    r.findings.filter(function (f) { return f.severity !== "pass" && f.severity !== "info"; })
      .forEach(function (f) { lines.push("- [" + f.severity + "] " + f.title + (f.detail ? ": " + f.detail : "")); });
    navigator.clipboard.writeText(lines.join("\n")).then(function () { toast("Summary copied"); }, function () { toast("Copy failed"); });
  });

  /* ---------------- report ---------------- */
  var SEV_LABEL = { critical: "critical", high: "high", medium: "medium", low: "low", info: "note", pass: "passed" };

  function postmark(score) {
    var tone = "tone-" + score.level;
    var waves = s("g", { class: "waves" });
    for (var i = 0; i < 4; i++) {
      var y = 146 + i * 9;
      waves.appendChild(s("path", { d: "M96 " + y + " q 9 -6 18 0 t 18 0 t 18 0 t 18 0" }));
    }
    var svg = s("svg", { viewBox: "0 0 172 172", role: "img", "aria-label": score.label + ", risk score " + score.value + " out of 100" },
      s("defs", {}, s("path", { id: "pm-arc", d: "M 26 86 A 60 60 0 0 1 146 86" })),
      s("circle", { class: "ring", cx: 86, cy: 86, r: 80, "stroke-width": 3.5 }),
      s("circle", { class: "ring", cx: 86, cy: 86, r: 71, "stroke-width": 1.5 }),
      s("text", { class: "arc-text" }, s("textPath", { href: "#pm-arc", startOffset: "50%", "text-anchor": "middle", text: "RISK SCORE" })),
      s("text", { class: "score", x: 86, y: 106, "text-anchor": "middle", text: String(score.value) }),
      s("text", { class: "level", x: 86, y: 132, "text-anchor": "middle", text: score.label }),
      waves);
    return h("div", { class: "postmark stamp " + tone }, svg);
  }

  function resClass(r) {
    r = (r || "").toLowerCase();
    if (r === "pass") return "ok";
    if (/fail|permerror|temperror/.test(r)) return r === "softfail" ? "warn" : "bad";
    if (r === "softfail" || r === "neutral" || r === "unverified") return "warn";
    return "muted";
  }
  function chip(label, res, note) {
    return h("span", { class: "chip " + resClass(res) }, label, h("b", { text: res || "none" }), note ? h("small", { text: note }) : null);
  }
  function mailbox(mb) {
    if (!mb || (!mb.name && !mb.address)) return h("span", { class: "addr", text: "—" });
    return h("span", {}, mb.name ? mb.name + " " : "", h("span", { class: "addr", text: mb.address ? "<" + mb.address + ">" : "" }));
  }
  function list(mbs) {
    if (!mbs || !mbs.length) return null;
    return mbs.map(function (m) { return m.address || m.name; }).join(", ");
  }
  function flag(geo) {
    if (!geo || !geo.iso_code) return null;
    return h("i", { class: "flag flag-" + geo.iso_code.replace(/[^a-z]/g, ""), title: geo.country || "", "aria-hidden": "true" });
  }
  function geoText(geo) {
    if (!geo) return "";
    return [geo.city, geo.country].filter(Boolean).join(", ") + (geo.asn ? "  AS" + geo.asn + (geo.as_org ? " " + geo.as_org : "") : "");
  }

  function verdict(r) {
    var sm = r.summary, a = r.auth;
    var env = h("dl", { class: "envelope" });
    function row(k, v) { if (v) env.append(h("dt", { text: k }), h("dd", {}, v)); }
    row("From", mailbox(sm.from));
    if (sm.reply_to && sm.reply_to.length) row("Reply-To", list(sm.reply_to));
    row("To", list(sm.to));
    row("Cc", list(sm.cc));
    row("Sent", sm.date_utc ? fmtTime(sm.date_utc) : sm.date);
    if (r.origin) row("Origin", h("span", {}, flag(r.origin.geo), h("span", { class: "addr", text: r.origin.ip }), " ", geoText(r.origin.geo)));

    var dmNote = a.dmarc.computed && a.dmarc.result !== "unknown" ? "computed" : (a.dmarc.policy ? "p=" + a.dmarc.policy.toLowerCase() : "");
    var authrow = h("div", { class: "authrow", "aria-label": "Authentication results" },
      chip("SPF", a.spf.result, a.spf.result === "pass" && !a.spf.aligned ? "not aligned" : ""),
      chip("DKIM", a.dkim.result, a.dkim.result === "pass" && !a.dkim.aligned ? "not aligned" : ""),
      chip("DMARC", a.dmarc.result === "unknown" ? "none" : a.dmarc.result, dmNote),
      a.arc.sets ? chip("ARC", a.arc.result, a.arc.sets + (a.arc.sets > 1 ? " sets" : " set")) : null,
      a.compauth ? chip("Composite auth", a.compauth.result, "") : null);

    return h("div", { class: "verdict" }, postmark(r.score),
      h("div", {}, h("h1", { class: "subject", text: sm.subject || "(no subject)" }), env, authrow));
  }

  function findings(r) {
    var important = r.findings.filter(function (f) { return f.severity !== "info"; });
    var notes = r.findings.filter(function (f) { return f.severity === "info"; });
    function item(f) {
      return h("li", { class: "finding " + f.severity }, h("span", { class: "dot", "aria-hidden": "true" }),
        h("div", {}, h("div", { class: "t" }, f.title, h("span", { class: "sev", text: SEV_LABEL[f.severity] })),
          f.detail ? h("div", { class: "d", text: f.detail }) : null));
    }
    var c = r.stats.findings, risky = (c.critical || 0) + (c.high || 0) + (c.medium || 0);
    var note = risky ? risky + " issue" + (risky > 1 ? "s" : "") + " need attention." : "Nothing that needs attention.";
    var ul = h("ul", { class: "findings" }, important.map(item));
    var more = null;
    if (notes.length) {
      var nl = h("ul", { class: "findings" }, notes.map(item));
      more = h("details", { class: "findings-more" }, h("summary", { class: "link", text: notes.length + " more note" + (notes.length > 1 ? "s" : "") }), nl);
    }
    return h("section", { "aria-labelledby": "f-t" }, h("h2", { class: "section-title", id: "f-t", text: "Findings" }),
      h("p", { class: "section-note", text: note }), ul, more);
  }

  function route(r) {
    var hops = r.hops;
    if (!hops.length) return h("section", {}, h("h2", { class: "section-title", text: "Route" }), h("p", { class: "empty", text: "No Received headers, so the relay path can't be traced." }));
    var max = Math.max.apply(null, hops.map(function (x) { return x.delay || 0; }).concat([1]));
    var ol = h("ol", { class: "route" });
    hops.forEach(function (hp, i) {
      var cls = "hop" + (r.origin && r.origin.hop === hp.hop ? " origin" : "") + (i === hops.length - 1 ? " final" : "");
      var meta = h("div", { class: "hop-meta" });
      if (hp.from_ip) meta.append(h("span", {}, flag(hp.geo), h("span", { class: "ip", text: hp.from_ip }), hp.geo ? " " + geoText(hp.geo) : ""));
      if (hp.from_ip && !hp.from_ip_public) meta.append(h("span", { class: "tag priv", text: "internal" }));
      if (hp.with) meta.append(h("span", { text: hp.with }));
      if (hp.from_ip_public) meta.append(h("span", { class: "tag " + (hp.tls ? "tls" : "notls"), text: hp.tls ? "TLS" : "no TLS shown" }));
      else if (hp.tls) meta.append(h("span", { class: "tag tls", text: "TLS" }));
      if (hp.clock_skew) meta.append(h("span", { class: "tag skew", text: "clock " + Math.round(hp.clock_skew) + " s" }));
      if (hp.timestamp) meta.append(h("span", { text: fmtTime(hp.timestamp) + (hp.timestamp_has_tz ? "" : " (assumed)") }));

      var delay = null;
      if (i > 0 && hp.delay != null) {
        var pct = Math.max(1, Math.round((hp.delay / max) * 100));
        delay = h("div", { class: "delay" }, h("div", { class: "delay-bar" + (hp.delay >= 300 ? " slow" : ""), role: "presentation" }, (function () { var sp = h("span"); sp.style.width = pct + "%"; return sp; })()),
          h("span", { class: "delay-val", text: hp.delay === 0 ? "no delay" : "+" + dur(hp.delay) }));
      }
      var fromName = hp.from || (hp.from_ip ? hp.from_ip : "unknown sender");
      ol.append(h("li", { class: cls },
        h("span", { class: "hop-num", "aria-label": "Hop " + hp.hop, text: String(hp.hop) }),
        h("div", { class: "hop-body" },
          h("div", { class: "hop-line" }, h("span", { class: "hop-host", text: fromName }), h("span", { class: "hop-to", text: "to" }), h("span", { class: "hop-host", text: hp.by || "unknown" })),
          meta, delay,
          h("details", { class: "hop-raw" }, h("summary", { text: "Raw header" }), h("pre", { text: "Received: " + hp.raw })))));
    });
    var total = r.timing.total_seconds;
    return h("section", { "aria-labelledby": "r-t" }, h("h2", { class: "section-title", id: "r-t", text: "Route" }),
      h("p", { class: "section-note", text: hops.length + " relay" + (hops.length > 1 ? "s" : "") + ", from the sender's server at the top to your mailbox at the bottom." }),
      ol, h("p", { class: "route-total", text: total ? "Delivered in " + dur(total) + "." : "" }), geoNote(r));
  }

  function geoNote(r) {
    var g = r.meta && r.meta.geoip && r.meta.geoip.country;
    if (!g) return null;
    var built = new Date(g.build_epoch * 1000), ageDays = (Date.now() - built) / 864e5;
    if (ageDays < 120) return null;
    return h("p", { class: "route-total geo-note", text: "Locations come from a GeoLite2 database built " + built.toISOString().slice(0, 7) + ", so some may be out of date. Run scripts/update_geoip.py to refresh it." });
  }

  function authDetails(r) {
    var a = r.auth;
    function cell(title, res, lines) {
      return h("div", { class: "auth-cell" }, h("h3", { text: title }), h("div", { class: "res " + resClass(res), text: res || "none" }),
        lines.filter(Boolean).map(function (l) { return h("p", {}, l); }));
    }
    var dkLines = a.dkim.results.length ? a.dkim.results.map(function (d) {
      return h("span", {}, h("span", { class: "mono", text: "d=" + (d.domain || "?") + (d.selector ? " s=" + d.selector : "") }), " " + d.result + (d.aligned ? ", aligned" : ""));
    }) : a.dkim.signatures.map(function (d) { return h("span", { class: "mono", text: "d=" + d.domain + " s=" + d.selector + " " + d.algorithm }); });
    var grid = h("div", { class: "auth-grid" },
      cell("SPF", a.spf.result, [a.spf.domain ? h("span", {}, "Envelope ", h("span", { class: "mono", text: a.spf.domain })) : null,
        a.spf.domain ? (a.spf.aligned ? "Aligned with From" : "Not aligned with From") : null, a.spf.source ? "Source: " + a.spf.source : null]),
      cell("DKIM", a.dkim.result, dkLines.length ? dkLines : ["No signature"]),
      cell("DMARC", a.dmarc.result === "unknown" ? "none" : a.dmarc.result, [
        a.dmarc.header_from ? h("span", {}, "From domain ", h("span", { class: "mono", text: a.dmarc.header_from })) : null,
        a.dmarc.policy ? "Policy p=" + a.dmarc.policy.toLowerCase() : null,
        a.dmarc.computed ? "Worked out by ESHA from SPF and DKIM; the receiving server recorded no result." : null]),
      cell("ARC", a.arc.result, [a.arc.sets ? a.arc.sets + " seal" + (a.arc.sets > 1 ? "s" : "") + (a.arc.chain_validation.length ? ", cv=" + a.arc.chain_validation.join(", ") : "") : "Not forwarded through an ARC sealer"]));
    var sp = r.spam, bits = [];
    if (sp.microsoft && Object.keys(sp.microsoft).length) bits.push("Microsoft 365: " + Object.keys(sp.microsoft).map(function (k) { return k + " " + sp.microsoft[k]; }).join(", "));
    if (sp.spamassassin && Object.keys(sp.spamassassin).length) bits.push("SpamAssassin: " + (sp.spamassassin.flagged ? "flagged" : "not flagged") + (sp.spamassassin.score != null ? ", score " + sp.spamassassin.score : ""));
    return h("section", { class: "block", "aria-labelledby": "a-t" }, h("h2", { class: "section-title", id: "a-t", text: "Authentication" }),
      h("p", { class: "section-note", text: a.authserv_id ? "As recorded by " + a.authserv_id + ", the server that received the message." : (a.authentication_results.length ? "As recorded by the server that received the message." : "No Authentication-Results header was found; results are taken from other headers where possible.") }),
      grid, bits.length ? h("p", { class: "spamline", text: bits.join("   |   ") }) : null, alignmentTable(r));
  }

  function alignmentTable(r) {
    var rows = (r.auth.alignment || []);
    if (rows.length < 2) return null;
    var ref = rows[0].domain;
    var tb = h("tbody");
    rows.forEach(function (a, i) {
      var state = i === 0 ? "ref" : (a.aligned ? "yes" : "no");
      tb.append(h("tr", { class: "al-" + state },
        h("th", { scope: "row", text: a.label }),
        h("td", { class: "mono", text: a.domain }),
        h("td", { class: "al-state" }, i === 0 ? "Reference" : h("span", {}, h("span", { class: "al-icon", "aria-hidden": "true", text: a.aligned ? "✓" : "✕" }), a.aligned ? "Same organisation" : (a.lookalike ? "Look-alike domain" : "Different organisation"))),
        h("td", { class: "al-note", text: i === 0 ? "" : a.note || "" })));
    });
    var mism = rows.slice(1).filter(function (a) { return !a.aligned; }).length;
    return h("div", { class: "align" },
      h("h3", { class: "sub-title", text: "Domain alignment" }),
      h("p", { class: "section-note", text: mism ? mism + " of " + (rows.length - 1) + " identities point to a different organisation than " + ref + ". Mail services and forwarding cause some mismatches; mismatches in SPF and DKIM matter most when DMARC fails." : "Every identity in the headers belongs to " + ref + "." }),
      h("table", { class: "align-table" }, h("thead", {}, h("tr", {}, h("th", { text: "Identity" }), h("th", { text: "Domain" }), h("th", { text: "Matches From?" }), h("th", { text: "Note" }))), tb));
  }

  function contentSection(r) {
    var c = r.content;
    if (!c) return null;
    var parts = [];
    if (c.attachments.length) {
      var al = h("ul", { class: "att-list" });
      c.attachments.forEach(function (a) {
        var why = [];
        if (a.double_extension) why.push("double extension");
        if (a.content_mismatch) why.push("content is " + a.content_mismatch);
        if (a.kind) why.push(a.kind);
        al.append(h("li", { class: a.risky ? "risky" : "" }, h("span", { class: "att-name", text: a.filename }),
          h("span", { class: "att-meta", text: [a.content_type, fmtSize(a.size)].concat(why).join(", ") })));
      });
      parts.push(h("h3", { class: "sub-title", text: "Attachments" }), al);
    }
    if (c.links.length) {
      var lt = h("tbody");
      c.links.slice(0, 200).forEach(function (lk) {
        lt.append(h("tr", { class: lk.flags.length ? "flagged" : "" },
          h("td", {}, h("div", { class: "lk-host", text: lk.host || lk.href.slice(0, 40) }), lk.text ? h("div", { class: "lk-text", text: "Shown as: " + lk.text }) : null),
          h("td", { class: "mono lk-href", text: lk.href }),
          h("td", {}, h("div", { class: "lk-flags" }, lk.flags.length ? lk.flags.map(function (f) { return h("span", { class: "tag flag-tag", text: f }); }) : h("span", { class: "ok-text", text: lk.same_org_as_sender ? "Sender's domain" : "No issues found" })))));
      });
      parts.push(h("h3", { class: "sub-title", text: "Links" }),
        h("p", { class: "section-note", text: c.link_count + " link" + (c.link_count > 1 ? "s" : "") + " to " + c.domains.length + " domain" + (c.domains.length > 1 ? "s" : "") + ". Links are inspected as text only; none are opened." }),
        h("table", { class: "link-table" }, lt));
    }
    if (!parts.length) parts.push(h("p", { class: "empty", text: "The message body has no links or attachments." }));
    return h("section", { class: "block", "aria-labelledby": "c-t" }, h("h2", { class: "section-title", id: "c-t", text: "Links and attachments" }), parts);
  }
  function fmtSize(n) { return n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB"; }

  function headersTable(r) {
    var cats = [["all", "All"], ["message", "Message"], ["routing", "Routing"], ["authentication", "Authentication"], ["spam", "Spam filter"], ["x-header", "X- headers"], ["other", "Other"]];
    var counts = { all: r.headers.length };
    r.headers.forEach(function (x) { counts[x.category] = (counts[x.category] || 0) + 1; });
    var active = "all", q = "";
    var tbody = h("tbody"), empty = h("p", { class: "empty", text: "No headers match.", hidden: true });
    var search = h("input", { class: "search", type: "search", placeholder: "Search headers", "aria-label": "Search headers" });
    var filters = h("div", { class: "filters", role: "group", "aria-label": "Header category" });
    cats.forEach(function (c) {
      if (!counts[c[0]]) return;
      var b = h("button", { type: "button", class: "filter", "aria-pressed": c[0] === "all" ? "true" : "false" }, c[1], h("span", { class: "n", text: String(counts[c[0]]) }));
      b.addEventListener("click", function () { active = c[0]; filters.querySelectorAll(".filter").forEach(function (x) { x.setAttribute("aria-pressed", x === b ? "true" : "false"); }); draw(); });
      filters.append(b);
    });
    function hl(text) {
      if (!q) return document.createTextNode(text);
      var frag = document.createDocumentFragment(), lower = text.toLowerCase(), i = 0, j;
      while ((j = lower.indexOf(q, i)) >= 0) { frag.append(text.slice(i, j), h("mark", { text: text.slice(j, j + q.length) })); i = j + q.length; }
      frag.append(text.slice(i));
      return frag;
    }
    function draw() {
      tbody.replaceChildren();
      var n = 0;
      r.headers.forEach(function (x) {
        if (active !== "all" && x.category !== active) return;
        var v = (x.value || "").replace(/\r?\n[ \t]+/g, "\n  ");
        if (q && x.name.toLowerCase().indexOf(q) < 0 && v.toLowerCase().indexOf(q) < 0) return;
        n++;
        tbody.append(h("tr", { class: "cat-" + x.category }, h("th", { scope: "row" }, hl(x.name)), h("td", {}, hl(v))));
      });
      empty.hidden = n > 0;
    }
    search.addEventListener("input", function () { q = search.value.trim().toLowerCase(); draw(); });
    draw();
    return h("section", { class: "block", "aria-labelledby": "h-t" }, h("h2", { class: "section-title", id: "h-t", text: "All headers" }),
      h("p", { class: "section-note", text: r.stats.header_count + " headers, in the order they appear in the message." }),
      h("div", { class: "hdr-tools" }, search, filters),
      h("table", { class: "hdr-table" }, tbody), empty);
  }

  function render(r) {
    report.replaceChildren(verdict(r), h("div", { class: "cols" }, findings(r), route(r)), authDetails(r), contentSection(r) || "", headersTable(r));
    intake.hidden = true; report.hidden = false;
    [btnNew, btnExport, btnCopy].forEach(function (b) { b.hidden = false; });
    window.scrollTo(0, 0);
    report.querySelector(".subject").setAttribute("tabindex", "-1");
    report.querySelector(".subject").focus({ preventScroll: true });
  }

  if (ta.value.trim()) analyze(ta.value);
})();
