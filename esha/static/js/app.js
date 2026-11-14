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
  function fmtClock(iso) {
    var d = new Date(iso);
    if (isNaN(d)) return { time: iso, date: "" };
    var t = d.toISOString();
    return { time: t.slice(11, 19) + " UTC", date: t.slice(0, 10) };
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
    setEngineStatus("Loading the analysis engine (first visit only; your browser caches it)…", "loading");
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
      // Samples are whole .eml files, so analyze them as a dropped file (headers and body).
      var name = b.getAttribute("data-sample");
      fetch("static/samples/" + name).then(function (r) { return r.blob(); })
        .then(function (blob) { analyzeFile(new File([blob], name, { type: "message/rfc822" })); });
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
      .forEach(function (f) { lines.push("- [" + f.severity + "] " + (f.rule_id ? f.rule_id + " " : "") + f.title + (f.detail ? ": " + f.detail : "")); });
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
      var attack = (f.attack || []), more = null;
      if (f.description || f.remediation || attack.length) {
        var al = null;
        if (attack.length) {
          al = h("p", { class: "f-attack" }, "MITRE ATT&CK: ");
          attack.forEach(function (a, i) {
            if (i) al.append(", ");
            al.append(h("a", { href: a.url, target: "_blank", rel: "noopener noreferrer", text: a.id + " " + a.name }));
          });
        }
        more = h("details", { class: "f-more" }, h("summary", { text: "Why this matters" }),
          f.description ? h("p", { text: f.description }) : null,
          f.remediation ? h("p", {}, h("b", { text: "What to do: " }), f.remediation) : null, al);
      }
      return h("li", { class: "finding " + f.severity }, h("span", { class: "dot", "aria-hidden": "true" }),
        h("div", {}, h("div", { class: "t" }, f.title, h("span", { class: "sev", text: SEV_LABEL[f.severity] }),
            f.rule_id ? h("span", { class: "rule-id", text: f.rule_id }) : null),
          f.detail ? h("div", { class: "d", text: f.detail }) : null, more));
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
    // Like Microsoft's Message Header Analyzer: each delay gets a red bar sized relative to the
    // longest one, the slowest hop is always marked, and hops of 5 minutes or more are flagged.
    var SLOW = 300;
    var slowest = hops.reduce(function (best, x, i) { return i > 0 && (x.delay || 0) > ((best && best.delay) || 0) ? x : best; }, null);
    var slowHops = hops.filter(function (x, i) { return i > 0 && (x.delay || 0) >= SLOW; });
    var ol = h("ol", { class: "route" });
    hops.forEach(function (hp, i) {
      var d = i > 0 ? hp.delay || 0 : 0;
      var speed = d >= SLOW ? " slow" : "";
      var cls = "hop" + (r.origin && r.origin.hop === hp.hop ? " origin" : "") + (i === hops.length - 1 ? " final" : "") + speed;
      var meta = h("div", { class: "hop-meta" });
      if (hp.from_ip) meta.append(h("span", {}, flag(hp.geo), h("span", { class: "ip", text: hp.from_ip }), hp.geo ? " " + geoText(hp.geo) : ""));
      if (hp.from_ip && !hp.from_ip_public) meta.append(h("span", { class: "tag priv", text: "internal" }));
      if (hp.with) meta.append(h("span", { text: hp.with }));
      if (hp.from_ip_public) meta.append(h("span", { class: "tag " + (hp.tls ? "tls" : "notls"), text: hp.tls ? "TLS" : "no TLS shown" }));
      else if (hp.tls) meta.append(h("span", { class: "tag tls", text: "TLS" }));
      if (hp.clock_skew) meta.append(h("span", { class: "tag skew", text: "clock " + Math.round(hp.clock_skew) + " s" }));
      // Time column: every hop shows how long it took and when it happened.
      var isSlowest = i > 0 && slowest === hp && hp.delay > 0;
      var mark = isSlowest ? "slowest" : d >= SLOW ? "slow" : "";
      var badgeText = i === 0 ? "Start" : hp.delay == null ? "unknown" : hp.delay === 0 ? "0 s" : "+" + dur(hp.delay);
      var label = isSlowest ? (hp.delay >= SLOW ? "Slowest, slow" : "Slowest") : mark === "slow" ? "Slow" : "";
      var time = h("div", { class: "hop-time" + (mark ? " " + mark : "") },
        label ? h("span", { class: "hop-time-label", text: label }) : null,
        h("span", { class: "delay-badge", text: badgeText,
          title: i === 0 ? "First recorded hop" : hp.delay == null ? "No timestamp to compare" : "Time since the previous hop" }),
        hp.timestamp ? h("span", { class: "hop-clock", title: fmtTime(hp.timestamp) },
          h("span", { text: fmtClock(hp.timestamp).time }), h("span", { class: "hop-date", text: fmtClock(hp.timestamp).date +
            (hp.timestamp_has_tz ? "" : " (zone assumed)") })) : h("span", { class: "hop-clock", text: "no timestamp" }));

      var delay = null;
      if (i > 0 && hp.delay != null) {
        var pct = Math.max(1, Math.round((hp.delay / max) * 100));
        delay = h("div", { class: "delay" + (isSlowest ? " slowest" : "") }, h("div", { class: "delay-bar", role: "presentation" },
          (function () { var sp = h("span"); sp.style.width = hp.delay ? pct + "%" : "0"; if (!hp.delay) sp.style.minWidth = "0"; return sp; })()));
      }
      var fromName = hp.from || (hp.from_ip ? hp.from_ip : "unknown sender");
      ol.append(h("li", { class: cls },
        h("span", { class: "hop-num", "aria-label": "Hop " + hp.hop, text: String(hp.hop) }),
        h("div", { class: "hop-body" },
          h("div", { class: "hop-main" },
            h("div", { class: "hop-line" }, h("span", { class: "hop-host", text: fromName }), h("span", { class: "hop-to", text: "to" }), h("span", { class: "hop-host", text: hp.by || "unknown" })),
            meta, delay,
            h("details", { class: "hop-raw" }, h("summary", { text: "Raw header" }), h("pre", { text: "Received: " + hp.raw }))),
          time)));
    });
    var total = r.timing.total_seconds;
    var summary = h("div", { class: "route-summary" },
      h("span", {}, h("span", { class: "rs-k", text: "Total time " }), h("b", { text: total ? dur(total) : "0 s" })),
      slowest && slowest.delay > 0 ? h("span", { class: "rs-slowest" }, h("span", { class: "rs-k", text: "Slowest " }),
        h("b", { text: "hop " + slowest.hop + ", +" + dur(slowest.delay) })) : null,
      h("span", {}, h("span", { class: "rs-k", text: "Hops " }), h("b", { text: String(hops.length) })));
    var alert = null;
    if (slowHops.length) {
      alert = h("p", { class: "route-alert", role: "note" },
        h("b", { text: slowHops.length === 1 ? "1 slow hop. " : slowHops.length + " slow hops. " }),
        slowHops.map(function (x) { return "Hop " + x.hop + " took " + dur(x.delay); }).join("; ") +
        ". Hops of 5 minutes or more are shown in red; long queues often point to spam filtering, greylisting or a server problem.");
    }
    return h("section", { "aria-labelledby": "r-t" }, h("h2", { class: "section-title", id: "r-t", text: "Route" }),
      h("p", { class: "section-note", text: hops.length + " relay" + (hops.length > 1 ? "s" : "") + ", from the sender's server at the top to your mailbox at the bottom." }),
      summary, alert, ol, geoNote(r));
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
        var c = a.container, inner = null;
        if (a.smuggling && a.smuggling.length) why.push("HTML smuggling: " + a.smuggling.join(", "));
        if (c) {
          var risky = {};
          (c.risky || []).forEach(function (x) { risky[x.name] = true; });
          var head = c.format + (c.encrypted ? ", password-protected" : "") + ", " +
            (c.listing === "complete" ? c.entry_count + " file" + (c.entry_count === 1 ? "" : "s") :
             c.listing === "not listed" ? "contents not listed" : c.entry_count + " name" + (c.entry_count === 1 ? "" : "s") + " found in raw data");
          inner = h("div", { class: "att-inner" }, h("span", { class: "att-inner-head", text: head }),
            c.entries.length ? h("ul", {}, c.entries.slice(0, 30).map(function (n) {
              return h("li", { class: risky[n] ? "risky" : "", text: n });
            }), c.entries.length > 30 ? h("li", { class: "more", text: "and " + (c.entry_count - 30) + " more" }) : null) : null);
        }
        var bad = a.risky || (c && (c.encrypted || (c.risky && c.risky.length))) || (a.smuggling && a.smuggling.length);
        al.append(h("li", { class: bad ? "risky" : "" }, h("span", { class: "att-name", text: a.filename }),
          h("span", { class: "att-meta", text: [a.content_type, fmtSize(a.size)].concat(why).join(", ") }), inner));
      });
      parts.push(h("h3", { class: "sub-title", text: "Attachments" }), al);
    }
    if (c.calendar && c.calendar.length) {
      var cl = h("ul", { class: "att-list" });
      c.calendar.forEach(function (ev) {
        cl.append(h("li", {}, h("span", { class: "att-name", text: ev.summary || "(untitled event)" }),
          h("span", { class: "att-meta", text: ["Organiser: " + (ev.organizer || "not given"), ev.method ? "method " + ev.method : "",
            ev.links.length + " link" + (ev.links.length === 1 ? "" : "s") + " (listed below)"].filter(Boolean).join(", ") })));
      });
      parts.push(h("h3", { class: "sub-title", text: "Calendar invites" }), cl);
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

  /* Report sections as an accessible tab set (WAI-ARIA tabs pattern). */
  var tabSeq = 0;
  function tabs(defs) {
    var list = h("div", { class: "tablist", role: "tablist", "aria-label": "Report sections" });
    var wrap = h("div", { class: "tabs" }, list), buttons = [];
    tabSeq++;
    defs.forEach(function (d, i) {
      var tid = "tab-" + tabSeq + "-" + d.id, pid = "panel-" + tabSeq + "-" + d.id;
      var b = h("button", { type: "button", class: "tab", role: "tab", id: tid, "aria-controls": pid,
        "aria-selected": i === 0 ? "true" : "false", tabindex: i === 0 ? "0" : "-1" },
        d.label, d.count != null ? h("span", { class: "n" + (d.alert ? " alert" : ""), text: String(d.count) }) : null);
      // On screen the tab label is the heading; the section's own heading is kept for printing.
      var t = d.el.querySelector(".section-title");
      if (t) { t.classList.add("print-only"); t.removeAttribute("id"); }
      d.el.removeAttribute("aria-labelledby");
      d.el.classList.remove("block");
      var panel = h("div", { class: "tabpanel", role: "tabpanel", id: pid, "aria-labelledby": tid, tabindex: "0", hidden: i !== 0 }, d.el);
      b.addEventListener("click", function () { select(i, false); });
      buttons.push({ b: b, panel: panel });
      list.append(b);
      wrap.append(panel);
    });
    function select(i, focus) {
      buttons.forEach(function (x, j) {
        x.b.setAttribute("aria-selected", j === i ? "true" : "false");
        x.b.tabIndex = j === i ? 0 : -1;
        x.panel.hidden = j !== i;
      });
      if (focus) buttons[i].b.focus();
    }
    list.addEventListener("keydown", function (e) {
      var cur = buttons.findIndex(function (x) { return x.b === document.activeElement; }), n = buttons.length, next = null;
      if (cur < 0) return;
      if (e.key === "ArrowRight") next = (cur + 1) % n;
      else if (e.key === "ArrowLeft") next = (cur - 1 + n) % n;
      else if (e.key === "Home") next = 0;
      else if (e.key === "End") next = n - 1;
      if (next != null) { e.preventDefault(); select(next, true); }
    });
    return wrap;
  }

  function render(r) {
    var c = r.stats.findings, risky = (c.critical || 0) + (c.high || 0) + (c.medium || 0);
    var defs = [
      { id: "findings", label: "Findings", count: risky, alert: (c.critical || 0) + (c.high || 0) > 0, el: findings(r) },
      { id: "route", label: "Route", count: r.hops.length, el: route(r) },
      { id: "auth", label: "Authentication", el: authDetails(r) },
    ];
    var content = contentSection(r);
    if (content) {
      defs.push({ id: "content", label: "Links & attachments",
        count: r.content.link_count + r.content.attachments.length, el: content });
    }
    defs.push({ id: "headers", label: "All headers", count: r.stats.header_count, el: headersTable(r) });
    report.replaceChildren(verdict(r), tabs(defs));
    intake.hidden = true; report.hidden = false;
    [btnNew, btnExport, btnCopy].forEach(function (b) { b.hidden = false; });
    window.scrollTo(0, 0);
    report.querySelector(".subject").setAttribute("tabindex", "-1");
    report.querySelector(".subject").focus({ preventScroll: true });
  }

  if (ta.value.trim()) analyze(ta.value);
})();
