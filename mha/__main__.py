"""Command-line interface.

    python -m mha                      # start the web UI on http://127.0.0.1:8080
    python -m mha serve -b 0.0.0.0 -p 9000
    python -m mha analyze message.eml  # human-readable report
    python -m mha analyze message.eml --json
    cat headers.txt | python -m mha analyze -
"""
from __future__ import annotations

import argparse
import json
import sys
import webbrowser

from . import __version__

SEV_COLOR = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m",
             "low": "\033[36m", "info": "\033[2m", "pass": "\033[32m"}
RESET = "\033[0m"


def _serve(args):
    from .app import app
    url = f"http://{'127.0.0.1' if args.bind in ('0.0.0.0', '::') else args.bind}:{args.port}"
    print(f"MHA {__version__} running at {url}  (Ctrl+C to stop)")
    if args.open:
        webbrowser.open(url)
    app.run(host=args.bind, port=args.port, debug=args.debug)


def _analyze(args):
    from .core import analyze
    if args.file == "-":
        text, from_file = sys.stdin.read(), False
    else:
        with open(args.file, "rb") as fh:
            data = fh.read()
        text = data.decode("utf-8", "replace")
        from_file = args.file.lower().endswith((".eml", ".msg", ".mbox"))
    report = analyze(text, from_file=from_file)
    if args.json:
        json.dump(report, sys.stdout, indent=2, default=str)
        print()
        return 0
    color = sys.stdout.isatty() and not args.no_color
    c = (lambda k: SEV_COLOR.get(k, "")) if color else (lambda k: "")
    r = RESET if color else ""
    s = report["summary"]
    print(f"\n{c('high' if report['score']['level']=='high' else report['score']['level'] if report['score']['level']!='low' else 'pass')}"
          f"■ {report['score']['label']}  ({report['score']['value']}/100){r}\n")
    print(f"  Subject : {s['subject']}")
    print(f"  From    : {s['from']['raw']}")
    print(f"  Date    : {s['date']}")
    a = report["auth"]
    print(f"  Auth    : SPF={a['spf']['result']}  DKIM={a['dkim']['result']}  DMARC={a['dmarc']['result']}"
          f"{' (computed)' if a['dmarc']['computed'] else ''}")
    if report["origin"]:
        o = report["origin"]
        g = o.get("geo") or {}
        print(f"  Origin  : {o['ip']} {g.get('country', '')} {('AS' + str(g['asn'])) if g.get('asn') else ''}")
    print("\n  Findings")
    for f in report["findings"]:
        print(f"   {c(f['severity'])}{f['severity'].upper():8}{r} {f['title']}" + (f" — {f['detail']}" if f["detail"] else ""))
    print(f"\n  Route ({len(report['hops'])} hops)")
    for h in report["hops"]:
        d = "" if h["delay"] is None else f"+{h['delay']:.0f}s"
        print(f"   {h['hop']:>2}. {h['from'] or '?'} [{h['from_ip'] or '-'}] → {h['by'] or '?'}  {h['with']}  {d}")
    print()
    return 2 if report["score"]["level"] == "high" else 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="mha", description="E-Mail Header Analyzer")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd")
    sp = sub.add_parser("serve", help="run the web UI (default)")
    for target in (sp, p):
        target.add_argument("-b", "--bind", default="127.0.0.1")
        target.add_argument("-p", "--port", type=int, default=8080)
        target.add_argument("-d", "--debug", action="store_true")
        target.add_argument("--open", action="store_true", help="open the browser")
    ap = sub.add_parser("analyze", help="analyze an .eml / header file from the command line")
    ap.add_argument("file", help="path to .eml or text file, or - for stdin")
    ap.add_argument("--json", action="store_true", help="print the full JSON report")
    ap.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)
    if args.cmd == "analyze":
        return _analyze(args)
    return _serve(args)


if __name__ == "__main__":
    sys.exit(main() or 0)
