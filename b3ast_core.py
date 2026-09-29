#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
B3AST CORE — Utilitários compartilhados da suite
Cores: vermelho dominante. Erros: sempre tratados.
"""
import os, sys, re, json, time, socket, traceback
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("[!] pip3 install requests")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

# ── PALETA: VERMELHO DOMINANTE ──
class C:
    RED    = "\033[91m"
    RED2   = "\033[38;5;196m"
    RED3   = "\033[38;5;124m"
    DARK   = "\033[38;5;52m"
    WHITE  = "\033[97m"
    GRAY   = "\033[90m"
    GREEN  = "\033[38;5;46m"
    YELLOW = "\033[38;5;220m"
    CYAN   = "\033[38;5;51m"
    CY     = CYAN
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    END    = "\033[0m"

BRAND = "B3AST"
ACCENT = C.RED

def banner():
    limpar = "cls" if os.name == "nt" else "clear"
    os.system(limpar)
    print(f"""{C.RED2}{C.BOLD}
  ██████╗ ███████╗ █████╗ ███████╗████████╗
  ██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝
  ██████╔╝█████╗  ███████║███████╗   ██║
  ██╔══██╗██╔══╝  ██╔══██║╚════██║   ██║
  ██████╔╝███████╗██║  ██║███████║   ██║
  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝{C.END}
{C.RED}  ╔══════════════════════════════════════════════════╗
  ║   ⛧  {C.WHITE}B3AST RECON SUITE v3.0{C.RED}  ⛧                  ║
  ║   {C.WHITE}.NET / CQRS / Angular / API — MODO BRUTAL{C.RED}       ║
  ╚══════════════════════════════════════════════════╝{C.END}""")

def log_info(msg):   print(f"  {C.WHITE}[{ACCENT}*{C.WHITE}] {msg}{C.END}")
def log_ok(msg):     print(f"  {C.GREEN}[+] {msg}{C.END}")
def log_vuln(msg):   print(f"  {C.RED2}{C.BOLD}[☠ VULN] {msg}{C.END}")
def log_fail(msg):   print(f"  {C.RED}[✖] {msg}{C.END}")
def log_warn(msg):   print(f"  {C.YELLOW}[!] {msg}{C.END}")
def log_dim(msg):    print(f"  {C.GRAY}{msg}{C.END}")

def titulo_fase(txt):
    print(f"\n{C.RED2}{C.BOLD}{'━'*64}")
    print(f"  ⛧ {txt}")
    print(f"{'━'*64}{C.END}")

class B3astError(Exception):
    """Erro customizado da suite."""
    pass

def safe_exec(fn, *args, default=None, contexto=""):
    """Wrapper: executa fn, captura QUALQUER exceção e retorna default."""
    try:
        return fn(*args)
    except KeyboardInterrupt:
        raise
    except Exception as e:
        log_fail(f"{contexto}: {type(e).__name__}: {e}")
        log_dim(f"    └─ {traceback.format_exc().splitlines()[-1]}")
        return default

def salvar_relatorio(prefixo, host, conteudo_blocos):
    """Salva TXT com tratamento de erro de disco/permissão."""
    try:
        arq = f"{prefixo}_{re.sub(r'[^a-zA-Z0-9]', '_', host)}_{datetime.now():%Y%m%d_%H%M%S}.txt"
        with open(arq, "w", encoding="utf-8", errors="replace") as f:
            f.write(f"{BRAND} SUITE v3.0 — {datetime.now()}\n{'='*70}\n")
            for titulo, corpo in conteudo_blocos:
                f.write(f"\n{'='*70}\n[{titulo}]\n{'-'*70}\n{corpo}\n")
        log_ok(f"Relatório salvo: {C.BOLD}{arq}{C.END}")
        return arq
    except PermissionError:
        log_fail("Sem permissão para salvar relatório no diretório atual.")
    except OSError as e:
        log_fail(f"Erro de disco ao salvar relatório: {e}")
    return None

def http_request(url, method="GET", **kwargs):
    """Request parametrizada com retries, timeout e tratamento total."""
    defaults = dict(timeout=15, verify=False, allow_redirects=True,
                    headers={"User-Agent": f"{BRAND}/3.0 (SecurityScanner)"})
    defaults.update(kwargs)
    for tentativa in range(3):
        try:
            r = requests.request(method, url, **defaults)
            return r
        except requests.exceptions.Timeout:
            if tentativa == 2: return None
            time.sleep(1)
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.RequestException as e:
            log_fail(f"HTTP {method} {url}: {e}")
            return None
    return None

def resolver_host(host):
    """Valida se o alvo resolve antes de qualquer scan."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None

# ── DETECÇÃO .NET / ANGULAR ──
FINGERPRINTS_NET = {
    "X-Powered-By: ASP.NET":   "ASP.NET",
    "X-AspNet-Version":        "ASP.NET (versão exposta)",
    "X-AspNetMvc-Version":     "ASP.NET MVC (versão exposta)",
    ".aspx":                   "WebForms",
    "__VIEWSTATE":             "WebForms ViewState",
    "X-Powered-By: arrakis":   "IIS/Azure",
    "Microsoft-IIS":           "IIS",
    "ARRSSL":                  "Azure App Service",
}

FINGERPRINTS_ANGULAR = {
    "ng-app":                   "AngularJS",
    "ng-version":               "Angular (versão no atributo)",
    "angular.min.js":           "AngularJS CDN",
    "main.js" + "ng":           "Angular Bundle",
    "_nghost":                  "Angular ViewEncapsulation",
    "ng-star-inserted":         "Angular Components",
    "runtime.js":               "Angular CLI build",
    "<app-root":                "Angular bootstrap",
}

def fingerprint_tecnologia(html, headers):
    """Retorna lista de tecnologias detectadas (.NET, Angular, etc)."""
    achados = []
    texto_headers = " ".join(f"{k}: {v}" for k, v in (headers or {}).items())
    for sig, tech in {**FINGERPRINTS_NET, **FINGERPRINTS_ANGULAR}.items():
        alvo = texto_headers if sig.startswith(("X-", "Microsoft", "ARR")) else (html or "")
        if sig.lower() in alvo.lower():
            achados.append(tech)
    return list(set(achados))

def menu_niveis():
    print(f"""
  {C.WHITE}{C.BOLD}NÍVEIS DE AGRESSÃO:{C.END}
  {C.GREEN}  [1]{C.END} BÁSICO     — rápido e discreto
  {C.YELLOW}  [2]{C.END} AVANÇADO   — completo e ruidoso
  {C.RED}  [3]{C.END} EXTREMO    — tudo, todas as portas, todos os payloads
  {C.RED2}  [4]{C.END} {C.RED2}{C.BOLD}B3AST MODE  — brutalidade máxima, sem dó{C.END}
""")
    while True:
        try:
            esc = input(f"  {C.CYAN}Nível (1/2/3/4): {C.END}").strip()
            if esc in ("1", "2", "3", "4"):
                return esc
            log_warn("Opção inválida, digite 1, 2, 3 ou 4.")
        except (KeyboardInterrupt, EOFError):
            return "1"
