"""AntPwn report: bilingual HTML report generator (guaidao2)"""
import html
import time

TPL = """<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>AntPwn Report — {name}</title>
<style>
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e1e4ec;margin:0;padding:24px}}
h1{{color:#7ec8ff}} h2{{color:#9ae6b4;border-bottom:1px solid #2a2f3d;padding-bottom:6px}}
.card{{background:#171a23;border:1px solid #2a2f3d;border-radius:10px;padding:16px;margin:14px 0}}
.badge{{display:inline-block;padding:2px 10px;border-radius:12px;font-size:13px;margin:2px}}
.on{{background:#5c2b2b;color:#ff9c9c}} .off{{background:#1e3a2a;color:#8ce8a4}}
.tag{{background:#2b3a5c;color:#9fc3ff}}
.finding{{padding:8px 12px;border-left:3px solid #f6c85f;background:#1c2030;margin:6px 0;border-radius:4px}}
.ok{{border-left-color:#8ce8a4}} .note{{color:#f6c85f}}
code,pre{{background:#0c0e14;padding:2px 6px;border-radius:4px;font-size:13px}}
pre{{padding:12px;overflow-x:auto}}
table{{border-collapse:collapse;width:100%}} td,th{{border:1px solid #2a2f3d;padding:6px 10px;text-align:left}}
footer{{color:#5a6172;margin-top:30px;font-size:12px}}
</style></head><body>
<h1>AntPwn — {name}</h1>
<p class="note">generated {ts} · author: guaidao2 · AntPwn 蚁刃</p>

<h2>1. {t_miti}</h2>
<div class="card">{mitis}</div>

<h2>2. {t_funcs}</h2>
<div class="card"><table><tr><th>function</th><th>address</th><th>calls</th></tr>{funcs}</table></div>

<h2>3. {t_find}</h2>
<div class="card">{findings}</div>

<h2>4. {t_strat}</h2>
<div class="card">{strategies}</div>

<h2>5. ACO</h2>
<div class="card"><pre>{aco}</pre></div>

<h2>6. {t_notes}</h2>
<div class="card"><ul>{notes}</ul></div>

<h2>7. {t_result}</h2>
<div class="card"><b class="{rescls}">{result}</b></div>

<footer>AntPwn v1.0 — native static analysis · pseudo-code · vuln scan · ptrace debugger ·
ACO · FSM · bilingual · developed by guaidao2</footer>
</body></html>"""


def save_report(fsm, path):
    d = fsm.report_data
    zh = i18n_lang(fsm)
    mitis = ""
    for k, v in d["mitigations"].items():
        cls = "off" if not v else "on"
        mitis += f'<span class="badge {cls}">{k}: {html.escape(str(v))}</span> '

    funcs = ""
    for f in d["functions"][:40]:
        funcs += (f"<tr><td><code>{html.escape(f['name'])}</code></td>"
                  f"<td>{f['addr']:#x}</td><td>{html.escape(', '.join(f['calls'])[:80])}</td></tr>")

    findings = ""
    for f in d["findings"]:
        cls = "finding" + (" ok" if f["kind"] in ("backdoor", "flag") else "")
        findings += (f'<div class="{cls}"><b>[{f["kind"]}]</b> '
                     f'{html.escape(f["func"])} @ {f["addr"]:#x} — '
                     f'{html.escape(f["detail"])} <i>(score {f["score"]})</i></div>')

    strategies = html.escape(", ".join(d.get("strategies", [])) or "-")
    aco = "\n".join(f"iter {i}: best={s:.2f}" for i, s in enumerate(d.get("aco", []))) or "-"

    notes = ""
    lang_zh = zh
    for zh_t, en_t in d.get("notes", []):
        notes += f'<li class="note">{html.escape(zh_t if lang_zh else en_t)}</li>'
    if not notes:
        notes = "<li>-</li>"

    result = d.get("result", "-")
    if d.get("flag"):
        result = f"{result}  |  flag: {d['flag']}"
    if d.get("remote"):
        result = f"{result}  |  remote: {d['remote']}"
    rescls = "off" if result.startswith("pwned") else "on"

    page = TPL.format(
        name=html.escape(d["path"]), ts=time.strftime("%Y-%m-%d %H:%M:%S"),
        t_miti="安全保护 / Mitigations", t_funcs="函数 / Functions",
        t_find="漏洞发现 / Findings", t_strat="利用策略 / Strategies",
        t_notes="人话解释 / Plain-words explanation", t_result="结果 / Result",
        mitis=mitis, funcs=funcs, findings=findings, strategies=strategies,
        aco=aco, notes=notes, result=html.escape(result), rescls=rescls)
    with open(path, "w", encoding="utf-8") as fp:
        fp.write(page)
    return path


def i18n_lang(fsm):
    from . import i18n as _i
    return _i.LANG == "zh"
