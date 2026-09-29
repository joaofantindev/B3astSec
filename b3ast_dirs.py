#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
B3AST DIRS v3.0 — Bruteforce de paths/endpoints
Foco: .NET (aspx, ashx, axd, svc), CQRS, Angular, APIs REST
Uso: python3 b3ast_dirs.py http://alvo.com
"""
import sys, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from b3ast_core import C, banner, log_ok, log_vuln, log_fail, log_warn, log_info, log_dim, \
    titulo_fase, safe_exec, salvar_relatorio, menu_niveis, http_request, fingerprint_tecnologia

# Wordlists por tecnologia
WORDLIST_NET = [
    # ASP.NET WebForms
    "default.aspx", "login.aspx", "admin.aspx", "web.config", "trace.axd",
    "elmah.axd", "glimpse.axd", "telerik.webresource.axd", "scriptresource.axd",
    "webresource.axd", "service.asmx", "api.asmx", "services.asmx",
    # WCF Services
    "service.svc", "services.svc", "api.svc", "odata.svc",
    # MVC Areas
    "area", "areas", "app_data", "app_code", "bin", "content", "scripts",
    # Configurações sensíveis
    "web.config.bak", "web.config.old", "web.config.txt", "connectionstrings.config",
    "appsettings.json", "appsettings.development.json", "package.json",
    # Erros e debug
    "errorlog.aspx", "debug.aspx", "test.aspx", "tests.aspx",
]

WORDLIST_CQRS = [
    # CQRS / MediatR patterns
    "api/command", "api/commands", "api/query", "api/queries",
    "api/commandhandler", "api/queryhandler", "api/mediator",
    "api/bus", "api/dispatch", "api/handler", "api/handlers",
    "api/v1/command", "api/v1/commands", "api/v1/query", "api/v1/queries",
    "api/v2/command", "api/v2/commands", "api/v2/query", "api/v2/queries",
    "api/cqrs", "cqrs", "commands", "queries",
    # Event sourcing
    "api/events", "api/event", "api/eventstore", "api/projections",
    "api/snapshots", "api/aggregates", "api/repositories",
    # Message brokers
    "api/messages", "api/notifications", "api/webhooks",
    "api/subscribers", "api/publishers",
]

WORDLIST_ANGULAR = [
    # Angular CLI build
    "main.js", "polyfills.js", "runtime.js", "styles.js", "vendor.js",
    "index.html", "favicon.ico", "manifest.json", "ngsw.json",
    "ngsw-worker.js", "safety-worker.js", "worker-basic.min.js",
    # Angular routes
    "app", "home", "dashboard", "admin", "login", "register",
    "profile", "settings", "api", "assets", "environments",
    "environment.ts", "environment.prod.ts", "angular.json",
    # Source maps (vazamento de código)
    "main.js.map", "polyfills.js.map", "runtime.js.map",
    "styles.js.map", "vendor.js.map",
]

WORDLIST_API = [
    # REST API patterns
    "api", "api/v1", "api/v2", "api/v3", "api/latest",
    "swagger", "swagger/ui", "swagger/index.html", "swagger/v1/swagger.json",
    "api-docs", "openapi.json", "openapi.yaml", "api/swagger",
    "graphql", "graphiql", "playground", "api/graphql",
    "health", "healthcheck", "status", "ping", "version",
    "metrics", "env", "actuator", "actuator/health", "actuator/env",
    "actuator/configprops", "actuator/mappings", "actuator/beans",
    "actuator/dump", "actuator/trace", "actuator/loggers",
]

WORDLIST_ADMIN = [
    "admin", "administrator", "admin/login", "admin/dashboard",
    "adminpanel", "adminarea", "admincp", "adminconsole",
    "manager", "management", "manage", "backend", "backoffice",
    "console", "dashboard", "panel", "cpanel", "control",
    "phpmyadmin", "adminer", "dbadmin", "sqladmin",
    "wp-admin", "wp-login.php", "administrator", "moderator",
]

WORDLIST_FILES = [
    # Arquivos sensíveis comuns
    ".env", ".env.local", ".env.production", ".env.development",
    ".git/config", ".git/HEAD", ".git/index", ".gitignore",
    ".svn/entries", ".svn/wc.db", ".hg/store",
    "backup.zip", "backup.tar.gz", "backup.sql", "backup.db",
    "dump.sql", "dump.zip", "dump.tar.gz", "db.sql", "database.sql",
    "config.php", "config.php.bak", "config.php.old", "config.php.txt",
    "configuration.php", "settings.php", "database.php",
    "web.config", "web.config.bak", "web.config.old",
    "composer.json", "composer.lock", "package.json", "package-lock.json",
    "yarn.lock", "Gemfile", "Gemfile.lock", "requirements.txt",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".dockerignore", ".editorconfig", ".eslintrc", ".babelrc",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    "security.txt", ".well-known/security.txt",
    "phpinfo.php", "info.php", "test.php", "debug.php",
    "server-status", "server-info", "status.php",
]

def carregar_wordlist(nivel):
    """Retorna wordlist combinada baseada no nível."""
    base = WORDLIST_API + WORDLIST_ADMIN + WORDLIST_FILES
    if nivel in ("2", "3", "4"):
        base += WORDLIST_NET
    if nivel in ("3", "4"):
        base += WORDLIST_CQRS + WORDLIST_ANGULAR
    if nivel == "4":
        # Adiciona variações comuns
        base += [f"api/{p}" for p in WORDLIST_CQRS if not p.startswith("api/")]
        base += [f"v1/{p}" for p in WORDLIST_API if not p.startswith("api/")]
    return list(dict.fromkeys(base))  # remove duplicatas preservando ordem

def testar_path(base, path):
    """Testa um único path e retorna resultado se encontrado."""
    url = f"{base.rstrip('/')}/{path}"
    r = http_request(url, method="GET")
    if r and r.status_code not in (404, 403, 500, 502, 503):
        return (path, r.status_code, len(r.content), url, r.headers.get("Content-Type", ""))
    return None

def main():
    if len(sys.argv) < 2:
        log_fail(f'Uso: python3 {sys.argv[0]} http://alvo.com')
        sys.exit(1)
    base = sys.argv[1]

    banner()
    nivel = menu_niveis()

    # Fingerprint inicial
    titulo_fase("FINGERPRINT INICIAL")
    r = safe_exec(http_request, base, default=None, contexto="fingerprint")
    techs = []
    if r:
        techs = fingerprint_tecnologia(r.text, r.headers)
        for t in techs:
            log_ok(f"Detectado: {C.BOLD}{t}{C.END}")
        if any("Angular" in t for t in techs):
            log_warn("Angular detectado — wordlist Angular incluída.")
        if any("ASP.NET" in t or "IIS" in t for t in techs):
            log_warn(".NET detectado — wordlist .NET incluída.")

    # Carregar wordlist
    wordlist = carregar_wordlist(nivel)
    titulo_fase(f"B3AST DIRS — NÍVEL {nivel} ({len(wordlist)} paths)")

    achados = []
    total = len(wordlist)

    # Executar bruteforce com threads
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(testar_path, base, path): path for path in wordlist}
        for i, future in enumerate(as_completed(futures), 1):
            resultado = safe_exec(lambda: future.result(), default=None, contexto="bruteforce")
            if resultado:
                path, status, size, url, ctype = resultado
                achados.append(resultado)
                log_vuln(f"[{status}] {path} ({size} bytes) — {ctype}")
                log_dim(f"    {url}")
            if i % 50 == 0:
                log_info(f"Progresso: {i}/{total} testados, {len(achados)} encontrados")

    # Sumário
    print(f"\n{C.RED2}{C.BOLD}{'━'*64}")
    if achados:
        print(f"  ☠ {len(achados)} PATHS/ENDPOINTS ENCONTRADOS")
        print(f"{'━'*64}{C.END}")
        for path, status, size, url, ctype in sorted(achados, key=lambda x: x[1]):
            print(f"  {C.GREEN}[{status}]{C.END} {C.BOLD}{path}{C.END} ({size}b)")
            print(f"    {C.GRAY}{url}{C.END}")
    else:
        print(f"{'━'*64}{C.END}")
        log_ok("Nenhum path/endpoint encontrado.")

    salvar_relatorio("b3ast_dirs", base.split("//")[-1].split("/")[0],
                     [(f"[{status}] {path}", f"url: {url}\nsize: {size}\ntype: {ctype}")
                      for path, status, size, url, ctype in achados]
                     or [("sem achados", "nenhum path encontrado")])

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log_warn("Interrompido."); sys.exit(130)
