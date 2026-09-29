#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
B3AST NMAP v3.0 — Recon brutal com foco em infra .NET
Uso: sudo python3 b3ast_nmap.py <alvo>
"""
import subprocess, shutil, sys, re
from b3ast_core import C, banner, log_ok, log_vuln, log_fail, log_warn, log_info, log_dim, \
    titulo_fase, safe_exec, salvar_relatorio, menu_niveis, resolver_host, BRAND

try:
    import netaddr
except ImportError:
    netaddr = None  # opcional, degrada graciosamente

def parse_portas(saida):
    """Extrai portas abertas: [('80','tcp','http'), ...]"""
    portas = []
    for l in saida.splitlines():
        m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S*)", l.strip())
        if m:
            portas.append((m.group(1), m.group(2), m.group(3) or "?"))
    return portas

def classificar_net(portas):
    """Marca portas típicas de stack .NET/Azure."""
    net_sig = {80:"HTTP/IIS", 443:"HTTPS/IIS", 1433:"MSSQL", 1434:"MSSQL-Browser",
               8080:"Kestrel/HTTP-Alt", 5000:"ASP.NET Core (dev)", 5001:"ASP.NET Core (https dev)",
               8443:"HTTPS-Alt", 5985:"WinRM-HTTP", 5986:"WinRM-HTTPS", 445:"SMB", 3389:"RDP",
               3306:"MySQL", 5432:"PostgreSQL", 6379:"Redis", 5672:"RabbitMQ(.NET msgs)"}
    return [(p, proto, svc, net_sig.get(int(p), None)) for p, proto, svc in portas]

SCANS = {
    "1": [("Top 1000 TCP", ["nmap", "-sS", "--top-ports", "1000", "-T4"]),
          ("Top 100 versões", ["nmap", "-sV", "--top-ports", "100"])],
    "2": [("Todas portas TCP", ["nmap", "-p-", "-sS", "-T4"]),
          ("UDP top 1000", ["nmap", "-sU", "--top-ports", "1000", "-T4"]),
          ("Versões + Scripts", ["nmap", "-sS", "-sV", "-sC", "-T4"]),
          ("NSE vuln", ["nmap", "-sV", "--script", "vuln", "-T4"]),
          ("SMB/RDP scripts (.NET infra)", ["nmap", "-p", "445,3389,5985,5986,1433",
              "--script", "smb-vuln-ms17-010,rdp-vuln-ms12-020,ssl-enum-ciphers", "-T4"]),
          ("FIN/Xmas/Null", ["nmap", "-sF", "-T4"]),
          ("ACK firewall", ["nmap", "-sA", "-T4"]),
          ("Decoys + fragmentação", ["nmap", "-sS", "-f", "-D", "RND:5", "-T4"]),
          ("Traceroute", ["nmap", "-sn", "--traceroute"])],
    "3": [("AGRESSIVO TOTAL", ["nmap", "-p-", "-A", "-T5"]),
          ("NSE ALL", ["nmap", "-p-", "-sV", "--script", "all", "-T5"]),
          ("UDP ALL", ["nmap", "-sU", "-p-", "-T5", "--max-retries", "1"]),
          ("TCP+UDP ALL", ["nmap", "-sS", "-sU", "-p-", "-T5", "--max-retries", "1"]),
          ("Brute auth", ["nmap", "-p-", "--script", "auth,brute", "-T5"]),
          ("Banner grab all", ["nmap", "-p-", "-sV", "--version-all", "-T5"]),
          ("MSSQL scripts (1433)", ["nmap", "-p", "1433", "--script", "ms-sql-info,ms-sql-empty-password,ms-sql-brute", "-T5"])],
    "4": SCANS["3"] + [
          ("T0 Paranoid (evasão)", ["nmap", "-p-", "-sS", "-T0"]),
          ("Idle scan", ["nmap", "-sS", "-sI", "-T4"]),
          ("Source port 53/88/445 (Kerberos/DNS bypass)", ["nmap", "-sS", "--source-port", "88", "-T5"]),
          ("Windows vuln sweep (MS17-010, SMB, RDP)", ["nmap", "-p-", "--script",
              "smb-vuln*,rdp-vuln*,ms-sql-vuln*,ssl-heartbleed", "-T5", "--max-retries", "1"])],
}

def main():
    if len(sys.argv) < 2:
        log_fail(f'Uso: sudo python3 {sys.argv[0]} <alvo>')
        sys.exit(1)
    alvo = sys.argv[1]

    if not shutil.which("nmap"):
        log_fail("nmap não instalado → apt install nmap"); sys.exit(1)

    ip = safe_exec(resolver_host, alvo, default=None, contexto="DNS")
    if not ip:
        log_fail(f"Host '{alvo}' não resolve. Verifique o alvo."); sys.exit(1)
    log_ok(f"Alvo resolve para: {C.BOLD}{ip}{C.END}")

    banner()
    nivel = menu_niveis()
    relatorio = []

    titulo_fase(f"B3AST NMAP — NÍVEL {nivel}")
    for nome, args in SCANS[nivel]:
        cmd = args + [alvo]
        log_info(f"{nome}")
        log_dim(f"    {' '.join(cmd)}")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
            saida = r.stdout.strip() or r.stderr.strip() or "(sem saída)"
        except subprocess.TimeoutExpired:
            log_fail(f"{nome}: TIMEOUT 2h — abortado")
            saida = "TIMEOUT"
        except FileNotFoundError:
            log_fail("nmap desapareceu do PATH mid-run?!"); saida = "ERRO"

        # Resumo colorido no terminal
        portas = safe_exec(parse_portas, saida, default=[], contexto="parse")
        if portas:
            for p, proto, svc in portas:
                tag = classificar_net([(p, proto, svc)])
                extra = f" {C.RED}← {tag[0][3]}{C.END}" if tag[0][3] else ""
                log_ok(f"{p}/{proto} {svc}{extra}")
        else:
            log_dim("    └─ sem portas abertas nessa varredura")
        relatorio.append((nome, saida))

    salvar_relatorio("b3ast_nmap", alvo, relatorio)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log_warn("Interrompido pelo usuário.")
        sys.exit(130)
