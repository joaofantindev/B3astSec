#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""⛧ B3AST RECON SUITE v4.0 — DEFINITIVE ⛧  Uso: sudo python3 main.py"""
import os, sys, re, shutil, subprocess, importlib.util
from b3ast_core import C, banner, log_ok, log_fail, log_warn, log_info, BRAND

DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = {
    "1": ("b3ast_nmap.py",  "🛡  NMAP — recon de rede"),
    "2": ("b3ast_sql.py",   "💉 SQL INJECTION — .NET/MSSQL/CQRS"),
    "3": ("b3ast_xss.py",   "⚡ XSS — Angular/DOM/JSON"),
    "5": ("b3ast_dirs.py",  "📁 DIRS — endpoints e arquivos sensíveis"),
    "6": ("b3ast_subs.py",  "🌐 SUBS — subdomínios"),
    "7": ("b3ast_api.py",   "🔌 API — Swagger/GraphQL expostos"),
}
WEB_PORTS = {80: "http", 443: "https", 8080: "http", 8443: "https", 5000: "http", 5001: "https"}

def check_deps():
    log_info("Verificando dependências...")
    faltam = [t for t in ("nmap", "sqlmap") if not shutil.which(t)]
    faltam += [f"pip:{m}" for m in ("requests", "bs4") if importlib.util.find_spec(m) is None]
    faltam += [s for s in SCRIPTS.values() if not os.path.exists(os.path.join(DIR, s[0]))]
    if faltam:
        log_fail(f"Faltando: {', '.join(str(f) for f in faltam)}")
        log_warn("→ sudo apt install nmap sqlmap && pip3 install requests beautifulsoup4")
        return False
    log_ok("Tudo OK."); return True

def rodar(script, alvo):
    path = os.path.join(DIR, script)
    if not os.path.exists(path):
        log_fail(f"Script ausente: {script}"); return False
    if not alvo:
        log_fail("Alvo vazio — pulando fase."); return False
    try:
        return subprocess.run([sys.executable, path, alvo]).returncode == 0
    except KeyboardInterrupt:
        log_warn("Fase interrompida."); return False
    except OSError as e:
        log_fail(f"Execução falhou: {e}"); return False

def descobrir_urls(alvo):
    urls = []
    try:
        rels = sorted(f for f in os.listdir(DIR) if f.startswith("b3ast_nmap_") and f.endswith(".txt"))
        if not rels:
            return urls
        txt = open(os.path.join(DIR, rels[-1]), encoding="utf-8", errors="replace").read()
        for porta, proto in WEB_PORTS.items():
            if re.search(rf"^{porta}/tcp\s+open", txt, re.MULTILINE):
                urls.append(f"{proto}://{alvo}" + (f":{porta}" if porta not in (80, 443) else "") + "/")
    except OSError as e:
        log_warn(f"Leitura do relatório falhou: {e}")
    return urls

def pipeline(alvo, url_manual):
    print(f"\n{C.RED2}{C.BOLD}  ⛧ PIPELINE B3AST ⛧{C.END}")
    log_info(f"Alvo: {C.BOLD}{alvo}{C.END}")
    fases = [("1", "NMAP"), None, None]  # placeholder
    rodar(SCRIPTS["1"][0], alvo)                          # FASE 1: recon

    urls = descobrir_urls(alvo)
    if url_manual: urls.insert(0, url_manual)
    if not urls:
        log_warn("Nenhuma porta web detectada automaticamente.")
        u = input(f"  {C.CY}URL manual (ENTER pula web): {C.END}").strip()
        if u: urls.append(u)

    for u in urls:
        rodar(SCRIPTS["5"][0], u)                         # FASE 2: dirs
        rodar(SCRIPTS["7"][0], u)                         # FASE 3: API docs
        rodar(SCRIPTS["2"][0], u)                         # FASE 4: SQL
        rodar(SCRIPTS["3"][0], u)                         # FASE 5: XSS

    # Subs sempre no final (domínio raiz)
    dominio = re.sub(r"https?://", "", alvo).split("/")[0].split(":")[0]
    rodar(SCRIPTS["6"][0], dominio)                       # FASE 6: subs

    print(f"\n{C.RED2}{C.BOLD}  ⛧ PIPELINE CONCLUÍDO — relatórios b3ast_*.txt ⛧{C.END}")

def menu():
    banner(); check_deps()
    print(f"""
  {C.WHITE}{C.BOLD}┌───────────── ⛧ {BRAND} OPERATIONS v4.0 ⛧ ─────────────┐{C.END}
{C.WHITE}   [1] 🛡  NMAP            — recon de rede
   [2] 💉 SQL INJECTION   — .NET/MSSQL/CQRS
   [3] ⚡  XSS             — Angular/DOM/JSON API
   [5] 📁 DIRS            — paths, backups, web.config, .env
   [6] 🌐 SUBS            — subdomínios
   [7] 🔌 API             — Swagger/GraphQL expostos
   [4] ⛧ PIPELINE BRUTAL  — tudo, em sequência inteligente
   [0] ❌  Sair{C.END}
  {C.WHITE}{C.BOLD}└──────────────────────────────────────────────┘{C.END}""")
    try:
        esc = input(f"  {C.RED}{C.BOLD}⛧ Escolha: {C.END}").strip()
    except (KeyboardInterrupt, EOFError):
        print(); sys.exit(0)

    if esc == "0":
        log_ok("Hail B3AST."); sys.exit(0)
    if esc == "4":
        alvo = input(f"  {C.CY}Alvo IP/host: {C.END}").strip()
        url = input(f"  {C.CY}URL web opcional: {C.END}").strip() or None
        pipeline(alvo, url); return
    if esc in SCRIPTS:
        alvo = input(f"  {C.CY}Alvo: {C.END}").strip()
        rodar(SCRIPTS[esc][0], alvo); return
    log_warn("Opção inválida.")

def main():
    while True:
        try:
            menu()
            again = input(f"\n  {C.CY}Menu novamente? (S/n): {C.END}").strip().lower()
            if again in ("n", "nao", "não"):
                break
        except KeyboardInterrupt:
            if input(f"\n  {C.CY}Sair? (S/n): {C.END}").strip().lower() in ("s", "", "sim"):
                break
    log_ok("Suite encerrada.")

if __name__ == "__main__":
    main()