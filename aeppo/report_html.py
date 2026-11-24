"""Self-contained HTML report for ``aeppo check``.

Everything shown comes from a repository nobody has vetted yet, so the page is built to stay
inert even if that content is hostile: every value is HTML-escaped, the page has no JavaScript
at all, and a Content-Security-Policy allows only the page's own inline stylesheet (by hash).
Lines flagged as committed credentials are masked in code excerpts, so the report can be shared.
"""
import base64
import hashlib
import re
from html import escape
from pathlib import PurePosixPath

from aeppo import rules_vulns
from aeppo.findings import SEVERITY_ORDER


CONTEXT_LINES = 3
MAX_LINE_LENGTH = 240
MAX_READ_BYTES = 2 * 1024 * 1024
_SAFE_ADVISORY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MASK = "[hidden by aeppo: this line was flagged as a possible credential]"

_STYLE = """
:root{--bg:#f7f7f5;--panel:#fff;--text:#1d1d1b;--muted:#64645f;--line:#e2e1dc;--code:#fbfbf9;
--red:#b42318;--red-bg:#fdecea;--yellow:#8a5a00;--yellow-bg:#fff4d6;--green:#1f7a3f;--green-bg:#e6f4ea;
--gray:#8a8a85;--gray-bg:#f0f0ed;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--panel:#1f1f1d;--text:#ececea;--muted:#a3a39e;
--line:#34342f;--code:#1a1a18;--red:#ff8a7a;--red-bg:#3a1d19;--yellow:#f2c55c;--yellow-bg:#352b12;
--green:#7fd39a;--green-bg:#16301f;--gray:#8f8f8a;--gray-bg:#262624;color-scheme:dark}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 12px}h3{font-size:15px;margin:0}
.sub{color:var(--muted);font-size:13px;overflow-wrap:anywhere}
code,pre,.mono{font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.banner{margin:20px 0;padding:16px 18px;border-radius:10px;border:1px solid var(--line);border-left-width:6px}
.banner strong{display:block;font-size:18px;margin-bottom:2px}
.danger{background:var(--red-bg);border-left-color:var(--red)}.danger strong{color:var(--red)}
.review{background:var(--yellow-bg);border-left-color:var(--yellow)}.review strong{color:var(--yellow)}
.clear{background:var(--green-bg);border-left-color:var(--green)}.clear strong{color:var(--green)}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:10px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px;border-top:4px solid var(--gray)}
.card.s-high{border-top-color:var(--red)}.card.s-medium{border-top-color:var(--yellow)}.card.s-low{border-top-color:var(--yellow)}
.card.s-none{border-top-color:var(--green)}.card .n{font-size:13px;color:var(--muted);margin-top:4px}
.card p{margin:4px 0 0;font-size:13px}
.layout{display:grid;grid-template-columns:minmax(220px,300px) minmax(0,1fr);gap:16px;align-items:start}
@media (max-width:800px){.layout{grid-template-columns:minmax(0,1fr)}}
.tree{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px;font-size:13px;
position:sticky;top:12px;max-height:calc(100vh - 24px);overflow:auto}
@media (max-width:800px){.tree{position:static;max-height:60vh}}
.tree ul{list-style:none;margin:0;padding-left:14px}.tree>ul{padding-left:0}
.tree summary{cursor:pointer;white-space:nowrap}.tree li{white-space:nowrap}
.tree a{color:inherit;text-decoration:none}.tree a:hover{text-decoration:underline}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:middle;background:var(--gray)}
.t-high>.dot,.t-high>summary>.dot{background:var(--red)}.t-medium>.dot,.t-medium>summary>.dot,.t-low>.dot,.t-low>summary>.dot{background:var(--yellow)}
.t-clean>.dot,.t-clean>summary>.dot{background:var(--green)}
.legend{display:flex;flex-wrap:wrap;gap:12px;font-size:12px;color:var(--muted);margin:0 0 8px}
.file{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin:0 0 14px;overflow:hidden}
.file header{padding:10px 14px;border-bottom:1px solid var(--line);display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.file header .mono{overflow-wrap:anywhere}
.code{background:var(--code);overflow-x:auto;font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.note{font-family:system-ui,-apple-system,"Segoe UI",sans-serif}
.action{font-weight:600}.action.b-high,.action.b-medium{padding:2px 6px;border-radius:5px}
.row{display:grid;grid-template-columns:56px minmax(0,1fr)}
.ln{color:var(--muted);text-align:right;padding:0 10px;user-select:none;border-right:1px solid var(--line)}
.src{padding:0 10px;white-space:pre}
.gap .src,.gap .ln{color:var(--muted)}
.hit-high{background:var(--red-bg)}.hit-high .ln{color:var(--red);font-weight:600}
.hit-medium,.hit-low{background:var(--yellow-bg)}.hit-medium .ln,.hit-low .ln{color:var(--yellow);font-weight:600}
.masked .src{font-style:italic;color:var(--muted)}
.note{margin:0;padding:8px 14px 10px 66px;border-bottom:1px solid var(--line);font-size:13px;background:var(--panel)}
.note p{margin:2px 0}
.badge{display:inline-block;font:600 11px/1 system-ui,sans-serif;padding:3px 6px;border-radius:5px;text-transform:uppercase;letter-spacing:.03em}
.b-high{background:var(--red-bg);color:var(--red)}.b-medium,.b-low{background:var(--yellow-bg);color:var(--yellow)}
.b-sec{background:var(--gray-bg);color:var(--muted)}
.muted{color:var(--muted)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;color:var(--muted)}td a{color:inherit}
.tablewrap{overflow-x:auto}
ul.reasons{margin:8px 0 0;padding-left:18px}ul.reasons a{color:inherit}
footer{margin-top:32px;font-size:13px;color:var(--muted)}
"""


def _style_hash():
    return "sha256-" + base64.b64encode(hashlib.sha256(_STYLE.encode("utf-8")).digest()).decode("ascii")


def _e(value):
    return escape(str(value), quote=True)


def _worst(findings):
    return max((item.severity for item in findings), key=lambda severity: SEVERITY_ORDER.get(severity, 1), default=None)


def _clip(text):
    text = text.rstrip("\r\n").expandtabs(4)
    return text if len(text) <= MAX_LINE_LENGTH else text[:MAX_LINE_LENGTH] + " …[line cut]"


def read_excerpts(root, findings, context=CONTEXT_LINES):
    """Return {path: [(line_number, text, masked)]} around each finding, read from ``root``.

    Call this before the checked-out copy is deleted. Lines flagged by a secrets rule are masked.
    """
    by_path = {}
    for finding in findings:
        by_path.setdefault(finding.path, []).append(finding)
    excerpts = {}
    for path, items in by_path.items():
        try:
            with open(str(root / path), "rb") as handle:
                data = handle.read(MAX_READ_BYTES)
        except (OSError, ValueError):
            continue
        lines = data.decode("utf-8", "replace").splitlines()
        secret_lines = {item.line for item in items if item.rule_id.startswith("SEC")}
        wanted = set()
        for item in items:
            wanted.update(range(max(1, item.line - context), item.line + context + 1))
        excerpts[path] = [(number, _MASK if number in secret_lines else _clip(lines[number - 1]), number in secret_lines)
                          for number in sorted(wanted) if number <= len(lines)]
    return excerpts


def _anchor(index):
    return "f{}".format(index)


def _tree(scanned, by_path, anchors):
    """Render the file tree: every scanned file, coloured by its worst finding."""
    root = {}
    for path in sorted(set(scanned) | set(by_path)):
        node = root
        parts = PurePosixPath(path).parts
        for part in parts[:-1]:
            node = node.setdefault(part + "/", {})
        node[parts[-1]] = path

    def status(node):
        if isinstance(node, str):
            worst = _worst(by_path.get(node, []))
            return worst or "clean"
        found = [status(child) for child in node.values()]
        for level in ("high", "medium", "low"):
            if level in found:
                return level
        return "clean"

    def render(node):
        out = ["<ul>"]
        for name in sorted(node, key=lambda key: (not key.endswith("/"), key.lower())):
            child = node[name]
            level = status(child)
            if isinstance(child, str):
                label = _e(name)
                if child in anchors:
                    count = len(by_path[child])
                    label = '<a href="#{}">{}</a> <span class="muted">({})</span>'.format(anchors[child], label, count)
                out.append('<li class="t-{}"><span class="dot"></span>{}</li>'.format(level, label))
            else:
                opened = " open" if level != "clean" else ""
                out.append('<li><details class="t-{}"{}><summary><span class="dot"></span>{}</summary>{}</details></li>'.format(level, opened, _e(name), render(child)))
        out.append("</ul>")
        return "".join(out)

    return render(root)


def _note(finding):
    return ('<div class="note"><p><span class="badge b-{sev}">{sev}</span> <code>{rule}</code> {msg}</p>'
            '<p class="muted">{rec}</p></div>').format(sev=_e(finding.severity), rule=_e(finding.rule_id), msg=_e(finding.message), rec=_e(finding.recommendation))


def _file_block(path, items, excerpt, anchor, section_label):
    by_line = {}
    for item in sorted(items, key=lambda item: (item.line, -SEVERITY_ORDER.get(item.severity, 1))):
        by_line.setdefault(item.line, []).append(item)
    worst = _worst(items)
    head = '<header><span class="badge b-{w}">{w}</span><span class="mono">{p}</span><span class="muted">{n} finding(s) · {s}</span></header>'.format(
        w=_e(worst), p=_e(path), n=len(items), s=_e(section_label))
    rows = []
    shown = set()
    previous = None
    for number, text, masked in excerpt:
        if previous is not None and number != previous + 1:
            rows.append('<div class="row gap"><span class="ln">…</span><span class="src"></span></div>')
        previous = number
        hits = by_line.get(number)
        classes = ["row"]
        if hits:
            classes.append("hit-" + _worst(hits))
        if masked:
            classes.append("masked")
        rows.append('<div class="{}"><span class="ln">{}</span><span class="src">{}</span></div>'.format(" ".join(classes), number, _e(text)))
        for hit in hits or []:
            rows.append(_note(hit))
            shown.add(id(hit))
    # Findings whose line could not be shown (unreadable file, line past the end).
    rest = [item for item in items if id(item) not in shown]
    if rest:
        rows.append('<div class="note"><p class="muted">Line not shown:</p></div>')
        rows.extend(_note(item).replace('<div class="note">', '<div class="note"><p class="mono muted">line {}</p>'.format(item.line), 1) for item in rest)
    return '<section class="file" id="{}">{}<div class="code">{}</div></section>'.format(anchor, head, "".join(rows))


def _dependency_table(findings, details):
    rows = rules_vulns.package_rows(findings, details)
    if not rows:
        return ""
    body = []
    for row in rows:
        advisories = []
        for detail in sorted(row["advisories"], key=lambda detail: detail.advisory)[:8]:
            label = _e(detail.advisory)
            if _SAFE_ADVISORY.match(detail.advisory):
                label = '<a href="https://osv.dev/vulnerability/{0}" rel="noopener noreferrer">{0}</a>'.format(label)
            advisories.append(label)
        if len(row["advisories"]) > 8:
            advisories.append("and {} more".format(len(row["advisories"]) - 8))
        action_class = "b-high" if row["malware"] else ("b-medium" if row["action"].startswith("no fixed") else "")
        body.append("<tr><td class=\"mono\">{} {}</td><td>{}</td><td>{}</td><td><span class=\"action {}\">{}</span></td><td class=\"mono\">{}</td><td>{}</td></tr>".format(
            _e(row["name"]), _e(row["version"]), _e(row["ecosystem"]), _e(row["counts"]), action_class, _e(row["action"]),
            "<br>".join(_e(location) for location in row["locations"][:3]) + (" …" if len(row["locations"]) > 3 else ""), ", ".join(advisories)))
    return ('<h2 id="deps">Vulnerable and malicious dependencies</h2><div class="tablewrap"><table><thead><tr><th>Package</th><th>Ecosystem</th>'
            '<th>Advisories</th><th>What to do</th><th>Where</th><th>IDs</th></tr></thead><tbody>{}</tbody></table></div>').format("".join(body))


def render(source, commit, findings, level, reasons, details, osv_status, sections, section_of, verdict_text, scanned, excerpts):
    """Return the HTML report as a string."""
    by_path = {}
    for finding in findings:
        by_path.setdefault(finding.path, []).append(finding)
    ordered_paths = sorted(by_path, key=lambda path: (-SEVERITY_ORDER.get(_worst(by_path[path]), 1), path))
    code_paths = [path for path in ordered_paths if any(section_of(item) != "deps" for item in by_path[path])]
    anchors = {path: _anchor(index) for index, path in enumerate(code_paths)}
    for path in ordered_paths:
        anchors.setdefault(path, "deps")  # lockfiles link to the dependency table

    parts = []
    title = "aeppo check: " + source
    parts.append("<header><h1>aeppo check</h1><div class=\"sub mono\">{}{}</div></header>".format(
        _e(source), _e(" · commit " + commit[:12]) if commit else ""))

    label = {"danger": "DANGER", "review": "REVIEW", "clear": "NO KNOWN ISSUES"}[level]
    explanation = verdict_text.split(". ", 1)[1] if level != "clear" else verdict_text
    banner = ['<div class="banner {}"><strong>{}</strong>{}'.format(level, label, _e(explanation))]
    if reasons:
        banner.append('<ul class="reasons">')
        # Dependency advisories are listed in their own table; malware stays visible here.
        listed = [finding for finding in reasons if finding.rule_id != "VULN001"]
        advisories = len(reasons) - len(listed)
        for finding in listed[:10]:
            where = _e("{}:{}".format(finding.path, finding.line))
            if finding.path in anchors:
                where = '<a href="#{}">{}</a>'.format(anchors[finding.path], where)
            banner.append("<li><span class=\"mono\">{}</span> <code>{}</code> {}</li>".format(where, _e(finding.rule_id), _e(finding.message)))
        if len(listed) > 10:
            banner.append("<li>and {} more</li>".format(len(listed) - 10))
        if advisories:
            banner.append('<li><a href="#deps">{} known vulnerabilit{} in dependencies</a></li>'.format(advisories, "y" if advisories == 1 else "ies"))
        banner.append("</ul>")
    banner.append("</div>")
    parts.append("".join(banner))

    parts.append("<h2>When would something run?</h2><div class=\"cards\">")
    for key, heading, _affects in sections:
        items = [finding for finding in findings if section_of(finding) == key]
        worst = _worst(items)
        if items:
            counts = ", ".join("{} {}".format(sum(1 for item in items if item.severity == severity), severity) for severity in ("high", "medium", "low") if any(item.severity == severity for item in items))
            status = "{} finding(s): {}".format(len(items), counts)
        else:
            status = "nothing found"
        if key == "deps" and osv_status:
            status += " · " + osv_status
        unchecked = key == "deps" and osv_status.lower().startswith("not checked")
        state = "s-" + worst if worst else ("s-unknown" if unchecked else "s-none")
        parts.append('<div class="card {}"><h3>{}</h3><div class="n">{}</div></div>'.format(state, _e(heading), _e(status)))
    parts.append("</div>")

    parts.append(_dependency_table(findings, details))

    parts.append("<h2>Files</h2>")
    parts.append('<div class="legend"><span class="t-high"><span class="dot"></span>high</span><span class="t-medium"><span class="dot"></span>medium or low</span>'
                 '<span class="t-clean"><span class="dot"></span>scanned, nothing found</span><span>{} file(s) scanned · {} with findings in the code</span></div>'.format(len(scanned), len(code_paths)))
    blocks = []
    section_labels = dict((key, heading.split(" (")[0]) for key, heading, _affects in sections)
    for path in code_paths:
        items = [item for item in by_path[path] if section_of(item) != "deps"]
        blocks.append(_file_block(path, items, excerpts.get(path, []), anchors[path], section_labels[section_of(items[0])]))
    if not blocks:
        blocks.append('<p class="muted">No findings in the code.</p>')
    parts.append('<div class="layout"><nav class="tree" aria-label="Scanned files">{}</nav><div>{}</div></div>'.format(_tree(scanned, by_path, anchors), "".join(blocks)))

    parts.append("<footer><p>aeppo read the files as text and ran nothing from the repository. Its rules find known risky patterns; "
                 "they can miss new or obfuscated malware, so treat a clean result as “nothing known”, not “safe”. "
                 "Install and run untrusted code in a disposable VM or container.</p>"
                 "<p>Lines flagged as possible credentials are hidden in this report.</p></footer>")

    csp = "default-src 'none'; style-src '{}'; img-src 'none'; form-action 'none'; base-uri 'none'".format(_style_hash())
    return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta http-equiv=\"Content-Security-Policy\" content=\"{csp}\">"
            "<meta name=\"referrer\" content=\"no-referrer\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<title>{title}</title><style>{style}</style></head><body><main>{body}</main></body></html>\n").format(
        csp=_e(csp), title=_e(title), style=_STYLE, body="".join(parts))
