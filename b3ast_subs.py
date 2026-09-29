#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
B3AST SUBS v3.0 — Enumeração de subdomínios
Métodos: DNS brute force, Certificate Transparency, DNS records
Uso: python3 b3ast_subs.py alvo.com
"""
import sys, re, socket, json
from concurrent.futures import ThreadPoolExecutor, as_completed
from b3ast_core import C, banner, log_ok, log_vuln, log_fail, log_warn, log_info, log_dim, \
    titulo_fase, safe_exec, salvar_relatorio, menu_niveis, http_request, resolver_host

# Wordlist de subdomínios comuns
WORDLIST_SUBS = [
    # Infraestrutura
    "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "ns3", "ns4",
    "dns", "dns1", "dns2", "cdn", "static", "media", "img", "images",
    "api", "api1", "api2", "rest", "graphql", "ws", "websocket",
    # Desenvolvimento/Staging
    "dev", "develop", "development", "staging", "stage", "test", "testing",
    "qa", "uat", "preprod", "preview", "beta", "alpha", "sandbox",
    "demo", "trial", "lab", "labs", "experimental", "canary",
    # Administração
    "admin", "administrator", "admin1", "admin2", "panel", "cpanel",
    "dashboard", "manage", "management", "backend", "backoffice",
    "console", "portal", "control", "monitor", "monitoring",
    # Segurança
    "secure", "security", "vpn", "firewall", "proxy", "waf",
    "auth", "sso", "oauth", "login", "signin", "account",
    # Serviços
    "blog", "forum", "community", "support", "help", "docs", "wiki",
    "kb", "knowledgebase", "faq", "status", "statuspage",
    "shop", "store", "cart", "checkout", "payment", "pay", "billing",
    "crm", "erp", "hr", "intranet", "extranet", "internal",
    # Cloud/Containers
    "aws", "azure", "gcp", "cloud", "k8s", "kubernetes", "docker",
    "registry", "harbor", "rancher", "openshift", "ocp",
    # Dados
    "db", "database", "mysql", "postgres", "mongodb", "redis",
    "elastic", "elasticsearch", "kibana", "log", "logs", "logging",
    "metrics", "grafana", "prometheus", "kibana", "splunk",
    # Comunicação
    "chat", "slack", "teams", "discord", "irc", "xmpp",
    "video", "meet", "zoom", "webex", "conference", "meeting",
    # Arquivos/Storage
    "files", "file", "storage", "s3", "bucket", "oss", "cdn",
    "backup", "backups", "archive", "old", "legacy",
    # Mobile
    "m", "mobile", "app", "android", "ios", "apk", "ipa",
    # Específicos .NET/Azure
    "azure", "azurewebsites", "cloudapp", "scm", "git", "deploy",
    "ci", "cd", "jenkins", "build", "artifacts", "nuget",
]

def dns_brute_force(dominio, wordlist, threads=50):
    """Força bruta de subdomínios via DNS resolution."""
    encontrados = []
    total = len(wordlist)

    def testar_sub(sub):
        hostname = f"{sub}.{dominio}"
        try:
            ip = socket.gethostbyname(hostname)
            return (hostname, ip, "A")
        except socket.gaierror:
            pass
        try:
            # Tenta obter CNAME
            import dns.resolver
            answers = dns.resolver.resolve(hostname, "CNAME")
            for rdata in answers:
                return (hostname, str(rdata.target), "CNAME")
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(testar_sub, sub): sub for sub in wordlist}
        for i, future in enumerate(as_completed(futures), 1):
            resultado = safe_exec(lambda: future.result(), default=None, contexto="dns")
            if resultado:
                hostname, ip, tipo = resultado
                encontrados.append(resultado)
                log_vuln(f"{hostname} → {ip} ({tipo})")
            if i % 20 == 0:
                log_info(f"Progresso: {i}/{total} testados, {len(encontrados)} encontrados")

    return encontrados

def certificate_transparency(dominio):
    """Consulta Certificate Transparency logs via crt.sh."""
    encontrados = set()
    try:
        url = f"https://crt.sh/?q=%25.{dominio}&output=json"
        r = http_request(url, timeout=30)
        if r and r.status_code == 200:
            data = r.json()
            for entry in data:
                name = entry.get("name_value", "").lower()
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(dominio) and sub != dominio:
                        encontrados.add(sub)
            log_ok(f"Certificate Transparency: {len(encontrados)} subdomínios únicos")
    except Exception as e:
        log_fail(f"Certificate Transparency falhou: {e}")
    return sorted(encontrados)

def dns_records(dominio):
    """Obtém registros DNS comuns."""
    registros = []
    tipos = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    try:
        import dns.resolver
        for tipo in tipos:
            try:
                answers = dns.resolver.resolve(dominio, tipo)
                for rdata in answers:
                    registros.append((tipo, str(rdata)))
                    log_ok(f"DNS {tipo}: {rdata}")
            except Exception:
                pass
    except ImportError:
        log_warn("dnspython não instalado — pip3 install dnspython")
        # Fallback para dig
        for tipo in tipos:
            try:
                import subprocess
                r = subprocess.run(["dig", "+short", dominio, tipo], 
                                   capture_output=True, text=True, timeout=10)
                if r.stdout.strip():
                    for line in r.stdout.strip().splitlines():
                        registros.append((tipo, line))
                        log_ok(f"DNS {tipo}: {line}")
            except Exception:
                pass
    return registros

def verificar_subdominio(hostname):
    """Verifica se subdomínio está ativo via HTTP/HTTPS."""
    for proto in ("https", "http"):
        url = f"{proto}://{hostname}"
        r = http_request(url, timeout=10)
        if r:
            return (url, r.status_code, r.headers.get("Server", ""))
    return None

def main():
    if len(sys.argv) < 2:
        log_fail(f'Uso: python3 {sys.argv[0]} alvo.com')
        sys.exit(1)
    dominio = sys.argv[1].lower().strip()

    banner()
    nivel = menu_niveis()

    # Validar domínio
    if not re.match(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$', dominio):
        log_fail(f"Domínio inválido: {dominio}")
        sys.exit(1)

    # Verificar se domínio principal resolve
    ip_main = safe_exec(resolver_host, dominio, default=None, contexto="DNS")
    if not ip_main:
        log_fail(f"Domínio '{dominio}' não resolve.")
        sys.exit(1)
    log_ok(f"Domínio principal: {dominio} → {ip_main}")

    relatorio = []

    # ── Fase 1: Certificate Transparency ──
    titulo_fase("CERTIFICATE TRANSPARENCY")
    subs_ct = safe_exec(certificate_transparency, dominio, default=[], contexto="ct")
    for sub in subs_ct:
        log_ok(f"CT: {sub}")
    relatorio.append(("Certificate Transparency", "\n".join(subs_ct)))

    # ── Fase 2: DNS Records ──
    titulo_fase("DNS RECORDS")
    registros = safe_exec(dns_records, dominio, default=[], contexto="dns")
    relatorio.append(("DNS Records", "\n".join(f"{t}: {v}" for t, v in registros)))

    # ── Fase 3: DNS Brute Force ──
    titulo_fase(f"DNS BRUTE FORCE — NÍVEL {nivel}")
    wordlist = WORDLIST_SUBS
    if nivel in ("3", "4"):
        # Adiciona mais subdomínios para níveis avançados
        wordlist += [
            "v1", "v2", "v3", "v4", "v5",
            "api-v1", "api-v2", "api-v3",
            "old", "new", "temp", "temporary",
            "staging1", "staging2", "dev1", "dev2",
            "test1", "test2", "qa1", "qa2",
            "mail1", "mail2", "smtp1", "smtp2",
            "cdn1", "cdn2", "static1", "static2",
            "img1", "img2", "image1", "image2",
            "db1", "db2", "mysql1", "mysql2",
            "redis1", "redis2", "cache1", "cache2",
            "worker1", "worker2", "job1", "job2",
            "queue1", "queue2", "mq1", "mq2",
            "kafka1", "kafka2", "rabbitmq1", "rabbitmq2",
            "elastic1", "elastic2", "es1", "es2",
            "kibana1", "kibana2", "log1", "log2",
            "monitor1", "monitor2", "nagios1", "nagios2",
            "zabbix1", "zabbix2", "grafana1", "grafana2",
            "prometheus1", "prometheus2", "alert1", "alert2",
            "backup1", "backup2", "bak1", "bak2",
            "archive1", "archive2", "old1", "old2",
            "legacy1", "legacy2", "deprecated1", "deprecated2",
            "internal1", "internal2", "intranet1", "intranet2",
            "extranet1", "extranet2", "partner1", "partner2",
            "vendor1", "vendor2", "client1", "client2",
            "customer1", "customer2", "user1", "user2",
            "member1", "member2", "account1", "account2",
            "profile1", "profile2", "my1", "my2",
            "portal1", "portal2", "gateway1", "gateway2",
            "proxy1", "proxy2", "lb1", "lb2",
            "loadbalancer1", "loadbalancer2", "nginx1", "nginx2",
            "apache1", "apache2", "iis1", "iis2",
            "tomcat1", "tomcat2", "jboss1", "jboss2",
            "weblogic1", "weblogic2", "websphere1", "websphere2",
        ]
    wordlist = list(dict.fromkeys(wordlist))  # remove duplicatas

    subs_brute = safe_exec(dns_brute_force, dominio, wordlist, default=[], contexto="brute")
    relatorio.append(("DNS Brute Force", "\n".join(f"{h} → {i} ({t})" for h, i, t in subs_brute)))

    # ── Fase 4: Verificação HTTP (níveis avançados) ──
    if nivel in ("2", "3", "4"):
        titulo_fase("VERIFICAÇÃO HTTP/HTTPS")
        todos_subs = sorted(set([s for s, _, _ in subs_brute] + subs_ct))
        ativos = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(verificar_subdominio, sub): sub for sub in todos_subs}
            for future in as_completed(futures):
                resultado = safe_exec(lambda: future.result(), default=None, contexto="http")
                if resultado:
                    url, status, server = resultado
                    ativos.append(resultado)
                    log_vuln(f"{url} [{status}] Server: {server}")
        relatorio.append(("HTTP Ativos", "\n".join(f"{u} [{s}] {sv}" for u, s, sv in ativos)))

    # ── Sumário ──
    print(f"\n{C.RED2}{C.BOLD}{'━'*64}")
    total_subs = len(set([s for s, _, _ in subs_brute] + subs_ct))
    print(f"  ☠ {total_subs} SUBDOMÍNIOS DESCOBERTOS")
    print(f"{'━'*64}{C.END}")

    salvar_relatorio("b3ast_subs", dominio, relatorio)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log_warn("Interrompido."); sys.exit(130)
