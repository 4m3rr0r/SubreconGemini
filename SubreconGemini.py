#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Subrecon (async)
Focused, fast subdomain discovery with CT logs, DNS/HTTP verification,
soft-404 detection, TLS SPKI fingerprinting, tech hints, and tidy outputs.

Requirements:
  pip install aiohttp aiodns rich cryptography

Usage examples:
  python subrecon.py -d google.com --scan normal --web-only --json
  python subrecon.py -l domains.txt --scan full --ports 80,443,8080,8443
  python subrecon.py -d example.com --dns-only
"""

import os
import re
import csv
import ssl
import json
import time
import html
import random
import socket
import argparse
import asyncio
from hashlib import sha256
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urljoin

import aiohttp
import aiodns
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import hashes

from rich.console import Console
from rich.progress import Progress, BarColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

console = Console()

# ----------------------------- Config & Defaults ------------------------------

DNS_TIMEOUT = 2.0
HTTP_TOTAL_TIMEOUT = 14.0
CONNECT_TIMEOUT = 4.0
MAX_REDIRECTS = 8

PRESETS = {
    "fast":   [80, 443],
    "normal": [80, 443, 8080, 8443, 8000],
    "full":   [80, 443, 8080, 8443, 8000, 3000, 9000, 9443, 10443],
}

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (Windows NT 10.0; rv:130.0) Gecko/20100101 Firefox/130.0",
]

TECH_SIGS = {
    "Cloudflare": [("server", r"cloudflare"), ("cf-ray", r".+")],
    "Akamai":     [("server", r"akamai"), ("x-akamai", r".+")],
    "nginx":      [("server", r"nginx")],
    "IIS":        [("server", r"microsoft-iis")],
    "Apache":     [("server", r"apache")],
    "OpenResty":  [("server", r"openresty")],
    "GWS":        [("server", r"gws")],
}

WORDLIST_URLS = [
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
    "https://raw.githubusercontent.com/initstring/cloud_enum/master/enum_tools/fuzz.txt",
]

SUB_RX_TEMPLATE = r'([a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)*\.{dom})'

# --------------------------------- Utilities ---------------------------------

def now_utc() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def detect_tech(headers: Dict[str, str]) -> List[str]:
    h = {k.lower(): v for k, v in headers.items()}
    found = []
    for name, rules in TECH_SIGS.items():
        ok = True
        for k, rx in rules:
            if not re.search(rx, h.get(k, ""), re.I):
                ok = False
                break
        if ok:
            found.append(name)
    return found

def spki_sha256_from_der(cert_der: bytes) -> str:
    cert = x509.load_der_x509_certificate(cert_der)
    spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return sha256(spki).hexdigest()

def extract_title_bytes(body: bytes) -> str:
    m = re.search(rb'<title>(.*?)</title>', body, re.I | re.S)
    if not m:
        return "No Title"
    try:
        return html.unescape(m.group(1).decode('utf-8', 'ignore')).strip()
    except Exception:
        return "No Title"

def normalize_html_for_404(s: bytes) -> str:
    t = re.sub(rb'<!--.*?-->', b'', s, flags=re.S)
    t = re.sub(rb'<script.*?>.*?</script>', b'', t, flags=re.S | re.I)
    t = re.sub(rb'<style.*?>.*?</style>', b'', t, flags=re.S | re.I)
    t = re.sub(rb'<[^>]+>', b' ', t)
    t = re.sub(rb'\s+', b' ', t).strip()
    return t[:16000].decode('utf-8', 'ignore')

def looks_soft404(base_body: bytes, bogus_body: bytes, base_title: str, bogus_title: str, base_status: int, bogus_status: int) -> bool:
    if base_status != bogus_status:
        return False
    if base_title[:90] == bogus_title[:90]:
        return True
    n1, n2 = normalize_html_for_404(base_body), normalize_html_for_404(bogus_body)
    h1, h2 = sha256(n1.encode()).hexdigest()[:12], sha256(n2.encode()).hexdigest()[:12]
    if h1 == h2:
        return True
    # quick similarity without external libs
    shorter = min(len(n1), len(n2))
    if shorter == 0:
        return False
    # sample windows to avoid O(n^2) work
    win = min(2000, shorter)
    same = sum(1 for i in range(win) if n1[i] == n2[i])
    return (same / win) > 0.92

def mutate_labels(seed: str) -> Set[str]:
    SUFFIXES = ["", "-dev", "-test", "-stage", "-int", "-beta", "-old", "-backup"]
    PREFIXES = ["dev", "test", "stage", "int", "beta", "old", "backup", "cdn", "api", "admin"]
    out: Set[str] = set()
    s = seed.replace(".", "-")
    for p in PREFIXES:
        out.add(f"{p}-{s}")
        out.add(f"{p}{s}")
    for suf in SUFFIXES:
        out.add(f"{s}{suf}")
    for n in (1, 2, 3, 5, 10, 100):
        out.add(f"{s}-{n}")
    return out

# ------------------------------ DNS Components --------------------------------

class DnsCache:
    def __init__(self) -> None:
        self._store: Dict[Tuple[str, str], Any] = {}

    def get(self, name: str, rtype: str):
        return self._store.get((name, rtype))

    def put(self, name: str, rtype: str, value: Any):
        self._store[(name, rtype)] = value

class DnsClient:
    def __init__(self, nameservers: Optional[List[str]] = None, timeout: float = DNS_TIMEOUT):
        self.resolver = aiodns.DNSResolver(
            nameservers=nameservers or ['1.1.1.1', '8.8.8.8', '9.9.9.9'],
            timeout=timeout, tries=1
        )
        self.cache = DnsCache()
        self.sem = asyncio.Semaphore(800)

    async def resolve_rr(self, fqdn: str, rtype: str) -> List[str]:
        cached = self.cache.get(fqdn, rtype)
        if cached is not None:
            return cached
        async with self.sem:
            try:
                ans = await self.resolver.query(fqdn, rtype)
                if rtype == "CNAME":
                    val = [getattr(ans, "cname", "").rstrip(".")] if ans else []
                else:
                    val = [getattr(a, "host") for a in ans]
                self.cache.put(fqdn, rtype, val)
                return val
            except Exception:
                self.cache.put(fqdn, rtype, [])
                return []

    async def resolve_all(self, fqdn: str) -> Dict[str, Any]:
        cname = await self.resolve_rr(fqdn, "CNAME")
        a = await self.resolve_rr(fqdn, "A")
        aaaa = await self.resolve_rr(fqdn, "AAAA")
        return {"A": a, "AAAA": aaaa, "CNAME": cname[0] if cname else None}

    @staticmethod
    def sig(rr: Dict[str, Any]) -> Tuple[Tuple[str, ...], Tuple[str, ...], Optional[str]]:
        return (tuple(sorted(rr.get("A") or [])), tuple(sorted(rr.get("AAAA") or [])), rr.get("CNAME"))

    async def detect_wildcard(self, domain: str) -> Dict[str, Any]:
        signatures: Set[Tuple[Tuple[str, ...], Tuple[str, ...], Optional[str]]] = set()
        for _ in range(5):
            label = f"nope-{random.randrange(10**9)}"
            rr = await self.resolve_all(f"{label}.{domain}")
            s = self.sig(rr)
            if s != ((), (), None):
                signatures.add(s)
        is_wild = len(signatures) == 1 and len(signatures) > 0
        signature = list(signatures)[0] if is_wild else None
        return {"is_wildcard": is_wild, "signature": signature}

# ------------------------------ HTTP Components --------------------------------

class HttpClient:
    def __init__(self, proxy: Optional[str] = None, verify_tls: bool = True, max_conc: int = 200):
        self.sem = asyncio.Semaphore(max_conc)
        self.verify_tls = verify_tls
        self.proxy = proxy
        self.timeout = aiohttp.ClientTimeout(total=HTTP_TOTAL_TIMEOUT, connect=CONNECT_TIMEOUT)
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        headers = {"User-Agent": random.choice(UA_POOL)}
        self.session = aiohttp.ClientSession(timeout=self.timeout, headers=headers, trust_env=True)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()

    async def get(self, url: str, allow_redirects=True) -> Tuple[aiohttp.ClientResponse, bytes]:
        if self.session is None:
            raise RuntimeError("HttpClient not started")
        async with self.sem:
            async with self.session.get(url, allow_redirects=allow_redirects, proxy=self.proxy, ssl=self.verify_tls) as r:
                body = await r.read()
                return r, body

    async def probe_host(self, host: str, domain: str, ports: List[int]) -> Dict[str, Any]:
        out = {"ports": [], "tls": None, "harvest": set()}
        # Prioritize 443/80 first
        order = [p for p in (443, 80) if p in ports] + [p for p in ports if p not in (80, 443)]
        for port in order:
            schemes = ("https", "http") if port in (443, 8443, 9443, 10443) else ("http", "https")
            for scheme in schemes:
                url = f"{scheme}://{host}" if (scheme == "https" and port == 443) or (scheme == "http" and port == 80) \
                    else f"{scheme}://{host}:{port}"
                try:
                    r, body = await self.get(url, allow_redirects=True)
                    if len(r.history) > MAX_REDIRECTS:
                        continue
                    title = extract_title_bytes(body)
                    # Soft-404 test
                    bogus = urljoin(url + "/", f"__not-real-{random.randrange(10**9)}")
                    try:
                        rb, bbody = await self.get(bogus, allow_redirects=True)
                        bogus_title = extract_title_bytes(bbody)
                        s404 = looks_soft404(body, bbody, title, bogus_title, r.status, rb.status)
                    except Exception:
                        s404 = False

                    rec = {
                        "scheme": scheme,
                        "port": port,
                        "status": r.status,
                        "title": title[:140],
                        "redirects": len(r.history),
                        "soft404": bool(s404),
                        "tech": detect_tech(dict(r.headers)),
                    }
                    out["ports"].append(rec)

                    # Harvest additional names from body
                    out["harvest"].update(harvest_hostnames(body, domain))

                    # Opportunistic TLS SPKI
                    if out["tls"] is None and scheme == "https":
                        try:
                            sslobj = r.connection.transport.get_extra_info("ssl_object")
                            if sslobj:
                                cert_der = sslobj.getpeercert(True)
                                out["tls"] = {
                                    "spki_sha256": spki_sha256_from_der(cert_der)
                                }
                        except Exception:
                            pass

                    if not s404 and 200 <= r.status < 500:
                        return out
                except Exception:
                    continue
        return out

# ------------------------------ CT Logs ----------------------------------------

async def fetch_ct_candidates(domain: str, client: HttpClient) -> Set[str]:
    """
    Pull subdomains from crt.sh (JSON). Keep only FQDNs ending with the target domain.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    candidates: Set[str] = set()
    try:
        r, body = await client.get(url)
        if r.status != 200:
            return candidates
        try:
            rows = json.loads(body.decode("utf-8", "ignore"))
        except Exception:
            return candidates
        for row in rows:
            name_val = str(row.get("name_value", "")).lower()
            for name in name_val.splitlines():
                name = name.strip().rstrip(".")
                if not name or name.startswith("*."):
                    name = name[2:] if name.startswith("*.") else name
                if not name:
                    continue
                if name.endswith("." + domain):
                    left = name[:-(len(domain) + 1)]
                    if left and re.fullmatch(r"[a-z0-9][a-z0-9\-\.]{0,253}", left):
                        candidates.add(left)
    except Exception:
        pass
    return candidates

# ------------------------------ Harvesting -------------------------------------

def harvest_hostnames(body: bytes, domain: str) -> Set[str]:
    rx = re.compile(SUB_RX_TEMPLATE.format(dom=re.escape(domain)).encode(), re.I)
    out: Set[str] = set()
    for m in rx.finditer(body):
        name = m.group(1).decode().lower().strip(".")
        if name.endswith("." + domain):
            left = name[:-(len(domain) + 1)]
            if left:
                out.add(left)
    return out

# ------------------------------ Wordlists --------------------------------------

async def load_wordlists() -> Set[str]:
    words: Set[str] = set()
    async with HttpClient(verify_tls=True, max_conc=8) as http:
        for url in WORDLIST_URLS:
            try:
                r, body = await http.get(url)
                if r.status == 200:
                    for line in body.decode("utf-8", "ignore").splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            words.add(line)
            except Exception:
                continue
    if not words:
        words = {"www", "mail", "ftp", "admin", "api", "dev", "test", "stage", "cdn"}
    return words

# ------------------------------- Output ----------------------------------------

class OutputManager:
    def __init__(self, outdir: str):
        self.outdir = outdir
        os.makedirs(outdir, exist_ok=True)

    def write_txt(self, domain: str, results: Dict[str, Any]):
        path = os.path.join(self.outdir, f"{domain}_subdomains.txt")
        with open(path, "w", encoding="utf-8") as f:
            for sub in sorted(results.keys()):
                f.write(sub + "\n")
        console.print(f"[green]✓[/] TXT saved: [cyan]{path}[/]")

    def write_csv(self, domain: str, results: Dict[str, Any]):
        path = os.path.join(self.outdir, f"{domain}_summary.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Subdomain", "IPs", "AAAA", "CNAME", "Scheme", "Port", "HTTP Status", "Title", "Redirects", "Soft404", "Tech", "TLS SPKI"])
            for sub, info in sorted(results.items()):
                rr = info.get("rrset", {})
                ips = ",".join(rr.get("A", []))
                aaaa = ",".join(rr.get("AAAA", []))
                cname = rr.get("CNAME") or ""
                primary = OutputManager._select_primary(info.get("ports", []))
                scheme = port = status = title = redirects = soft404 = tech = spki = ""
                if primary:
                    scheme = primary.get("scheme", "")
                    port = primary.get("port", "")
                    status = primary.get("status", "")
                    title = primary.get("title", "")[:120]
                    redirects = primary.get("redirects", 0)
                    soft404 = "yes" if primary.get("soft404") else "no"
                    tech = "|".join(primary.get("tech") or [])
                tls = info.get("tls") or {}
                spki = tls.get("spki_sha256", "")
                w.writerow([sub, ips, aaaa, cname, scheme, port, status, title, redirects, soft404, tech, spki])
        console.print(f"[green]✓[/] CSV saved: [cyan]{path}[/]")

    def write_json(self, domain: str, results: Dict[str, Any], meta: Dict[str, Any]):
        path = os.path.join(self.outdir, f"{domain}_results.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"meta": meta, "results": results}, f, ensure_ascii=False, indent=2)
        console.print(f"[green]✓[/] JSON saved: [cyan]{path}[/]")

    def write_html(self, domain: str, results: Dict[str, Any]):
        path = os.path.join(self.outdir, f"{domain}_report.html")
        rows = []
        for sub, info in sorted(results.items()):
            rr = info.get("rrset", {})
            a = ", ".join(rr.get("A", []))
            aaaa = ", ".join(rr.get("AAAA", []))
            primary = OutputManager._select_primary(info.get("ports", []))
            if primary:
                http_col = f'{primary.get("scheme")}:{primary.get("port")} {primary.get("status")}'
                title = primary.get("title", "")
                s404 = "yes" if primary.get("soft404") else "no"
                tech = ", ".join(primary.get("tech") or [])
            else:
                http_col, title, s404, tech = "—", "No HTTP", "no", ""
            rows.append(f"<tr><td>{sub}</td><td>{a}</td><td>{aaaa}</td><td>{http_col}</td><td>{title}</td><td>{s404}</td><td>{tech}</td></tr>")
        html_doc = f"""<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Subrecon – {domain}</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,'Helvetica Neue',Arial,sans-serif;background:#0b0f17;color:#e8f1ff;margin:32px}}
h1{{margin:0 0 12px 0}} table{{border-collapse:collapse;width:100%;font-size:14px}}
th,td{{border-bottom:1px solid #1b2433;padding:8px 10px;vertical-align:top}}
th{{text-align:left;color:#9fc2ff;background:#0f1520;position:sticky;top:0}}
tr:hover td{{background:#0f1726}}
.small{{color:#88a3c6}}
</style>
<h1>Live Subdomains for {domain}</h1>
<p class="small">Generated {now_utc()}</p>
<table><thead><tr>
<th>Subdomain</th><th>A</th><th>AAAA</th><th>HTTP</th><th>Title</th><th>Soft404</th><th>Tech</th>
</tr></thead><tbody>
{''.join(rows)}
</tbody></table>
</html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_doc)
        console.print(f"[green]✓[/] HTML saved: [cyan]{path}[/]")

    @staticmethod
    def _select_primary(portrecs: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not portrecs:
            return None
        non_soft = [r for r in portrecs if not r.get("soft404")]
        return non_soft[0] if non_soft else portrecs[0]

# --------------------------------- Runner --------------------------------------

class Subrecon:
    def __init__(self, ports: List[int], verify_tls: bool, proxy: Optional[str], dns_only: bool, web_only: bool,
                 max_http: int, max_dns: int):
        self.ports = ports
        self.verify_tls = verify_tls
        self.proxy = proxy
        self.dns_only = dns_only
        self.web_only = web_only
        self.http_max = max_http
        self.dns = DnsClient(timeout=DNS_TIMEOUT)
        self.dns.sem = asyncio.Semaphore(max_dns)

    async def discover(self, domain: str, seeds: Set[str]) -> Dict[str, Any]:
        console.print(Panel.fit(f"[bold]Recon: [cyan]{domain}[/]", border_style="blue"))

        # Wildcard detection
        wildcard = await self.dns.detect_wildcard(domain)
        # Build initial candidate set (dedupe)
        candidates: Set[str] = set(seeds)

        results: Dict[str, Any] = {}
        verified: Set[str] = set()

        # Phase 1: DNS verify candidates
        with Progress(
            "[progress.description]{task.description}",
            BarColumn(bar_width=None),
            "•",
            TimeElapsedColumn(),
            "•",
            TimeRemainingColumn(),
            transient=True,
        ) as prog:
            t_dns = prog.add_task("[cyan]Resolving DNS...", total=len(candidates) or 1)
            # Resolve concurrently but with bounded sem in DnsClient
            async def resolve_one(sub: str):
                fqdn = f"{sub}.{domain}"
                rr = await self.dns.resolve_all(fqdn)
                sig = self.dns.sig(rr)
                if rr == {"A": [], "AAAA": [], "CNAME": None}:
                    return None
                if wildcard.get("is_wildcard") and sig == wildcard.get("signature"):
                    return None
                return fqdn, rr

            coros = [resolve_one(s) for s in sorted(candidates)]
            for fut in asyncio.as_completed(coros):
                res = await fut
                if res:
                    fqdn, rr = res
                    results[fqdn] = {"rrset": rr, "ports": [], "tls": None}
                    verified.add(fqdn)
                prog.update(t_dns, advance=1)

        if self.dns_only or not verified:
            return results

        # Phase 2: HTTP probing for live surface + harvesting
        async with HttpClient(proxy=self.proxy, verify_tls=self.verify_tls, max_conc=self.http_max) as http:
            with Progress(
                "[progress.description]{task.description}",
                BarColumn(bar_width=None),
                "•",
                TimeElapsedColumn(),
                "•",
                TimeRemainingColumn(),
                transient=True,
            ) as prog:
                # initial HTTP pass
                live_targets = list(verified)
                t_http = prog.add_task("[green]HTTP probing...", total=len(live_targets))
                async def probe_one(fqdn: str):
                    info = await http.probe_host(fqdn, domain, self.ports)
                    results[fqdn].update(info)
                    prog.update(t_http, advance=1)

                await asyncio.gather(*(probe_one(h) for h in live_targets))

                # Harvested names -> limited breadth second pass
                harvest: Set[str] = set()
                for fqdn in live_targets:
                    harvest.update(results[fqdn].get("harvest", set()))
                # Mutate a bit
                for h in list(harvest)[:200]:
                    harvest.update(mutate_labels(h))

                # DNS verify harvested
                new_candidates = {h for h in harvest if h and f"{h}.{domain}" not in results}
                if new_candidates:
                    t_hdns = prog.add_task("[cyan]Resolving harvested...", total=len(new_candidates))
                    async def resolve_h(sub: str):
                        fqdn = f"{sub}.{domain}"
                        rr = await self.dns.resolve_all(fqdn)
                        sig = self.dns.sig(rr)
                        if rr == {"A": [], "AAAA": [], "CNAME": None}:
                            return None
                        if wildcard.get("is_wildcard") and sig == wildcard.get("signature"):
                            return None
                        return fqdn, rr

                    newly_verified: List[str] = []
                    coros2 = [resolve_h(s) for s in sorted(new_candidates)]
                    for fut in asyncio.as_completed(coros2):
                        res = await fut
                        if res:
                            fqdn, rr = res
                            results[fqdn] = {"rrset": rr, "ports": [], "tls": None}
                            newly_verified.append(fqdn)
                        prog.update(t_hdns, advance=1)

                    if newly_verified and not self.dns_only:
                        t_http2 = prog.add_task("[green]HTTP probing (harvest)...", total=len(newly_verified))
                        async def probe_two(fqdn: str):
                            info = await http.probe_host(fqdn, domain, self.ports)
                            results[fqdn].update(info)
                            prog.update(t_http2, advance=1)
                        await asyncio.gather(*(probe_two(h) for h in newly_verified))

        # Optional filter: web-only (keep only those with HTTP results)
        if self.web_only:
            results = {
                k: v for k, v in results.items()
                if v.get("ports") and any(p.get("status") for p in v.get("ports", []))
            }

        return results

# --------------------------------- Printing ------------------------------------

def print_summary(domain: str, results: Dict[str, Any]):
    if not results:
        console.print(f"[bold yellow]No verified subdomains found for {domain}.[/]")
        return
    table = Table(title=f"Live Subdomains for {domain}")
    table.add_column("Subdomain", style="cyan", no_wrap=True)
    table.add_column("IPs (A)", style="magenta")
    table.add_column("AAAA", style="magenta")
    table.add_column("HTTP", style="green")
    table.add_column("Title", style="white")
    table.add_column("Soft404", style="yellow")
    for sub, info in sorted(results.items()):
        rr = info.get("rrset", {})
        ips_a = ",".join(rr.get("A", []))
        ips_aaaa = ",".join(rr.get("AAAA", []))
        recs = info.get("ports", [])
        if recs:
            primary = OutputManager._select_primary(recs)
            status_str = str(primary.get("status", ""))
            color = "green" if status_str.startswith("2") else "yellow" if status_str.startswith("3") else "red"
            http_col = f"{primary.get('scheme')}:{primary.get('port')} [bold {color}]{status_str}[/]"
            title = primary.get("title", "")[:60]
            s404 = "yes" if primary.get("soft404") else "no"
        else:
            http_col, title, s404 = "—", "No HTTP", "no"
        table.add_row(sub, ips_a, ips_aaaa, http_col, title, s404)
    console.print(table)
    console.print(f"\n[bold]Total verified subdomains found:[/] {len(results)}")

# ----------------------------------- CLI ---------------------------------------

async def main():
    parser = argparse.ArgumentParser(
        description="Subrecon (async) – Focused Subdomain Discovery",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    tgt = parser.add_mutually_exclusive_group(required=True)
    tgt.add_argument("-d", "--domain", help="Target domain (e.g., example.com)")
    tgt.add_argument("-l", "--list", help="Path to a file with target domains")

    parser.add_argument("--scan", choices=list(PRESETS.keys()), default="normal", help="Port scan preset {fast | normal | full}")
    parser.add_argument("--ports", help="Comma-separated ports to override preset (e.g., 80,443,8080)")
    parser.add_argument("--dns-only", action="store_true", help="Only perform DNS enumeration/verification")
    parser.add_argument("--web-only", action="store_true", help="Keep only hosts with web responses")
    parser.add_argument("--verify-tls", action="store_true", default=True, help="Verify TLS certificates (default on)")
    parser.add_argument("--no-verify-tls", dest="verify_tls", action="store_false", help="Do not verify TLS certificates")
    parser.add_argument("--proxy", help="HTTP/S proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--output-dir", default="recon_results", help="Output directory")
    parser.add_argument("--json", action="store_true", help="Also write JSON results")
    parser.add_argument("--html", action="store_true", help="Also write HTML report")
    parser.add_argument("--max-http", type=int, default=220, help="Max concurrent HTTP requests")
    parser.add_argument("--max-dns", type=int, default=800, help="Max concurrent DNS queries")

    args = parser.parse_args()

    # Ports selection
    ports = PRESETS[args.scan]
    if args.ports:
        try:
            p = [int(x.strip()) for x in args.ports.split(",") if x.strip()]
            if p:
                ports = p
        except ValueError:
            pass

    # Load wordlists (seed)
    console.print(Panel.fit("[bold green]Subrecon[/] [yellow]async[/]\n[white]Focused Subdomain Discovery[/]", border_style="blue"))
    console.print(Markdown("*Loading wordlists & passive sources…*"))
    words = await load_wordlists()

    # Targets
    targets: List[str] = []
    if args.domain:
        targets.append(args.domain.strip())
    else:
        try:
            with open(args.list, "r", encoding="utf-8") as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            console.print(f"[red]Error: target file not found: {args.list}[/]")
            return

    recon = Subrecon(
        ports=ports,
        verify_tls=args.verify_tls,
        proxy=args.proxy,
        dns_only=args.dns_only,
        web_only=args.web_only,
        max_http=args.max_http,
        max_dns=args.max_dns
    )
    out = OutputManager(args.output_dir)

    overall_start = time.time()
    for domain in targets:
        start = time.time()
        # Passive CT seeds
        ct_seeds = set()
        try:
            async with HttpClient(proxy=args.proxy, verify_tls=args.verify_tls, max_conc=8) as http:
                ct_seeds = await fetch_ct_candidates(domain, http)
        except Exception:
            pass

        # Combine seeds (wordlist top slice + CT + common)
        # Keep it reasonable to start; mutations/harvest add more.
        base_seeds = set(list(words)[:2000])
        seeds = set()
        for s in base_seeds:
            if s and re.fullmatch(r"[a-z0-9][a-z0-9\-\.]{0,253}", s):
                seeds.add(s)
        seeds |= set(list(ct_seeds)[:4000])

        results = await recon.discover(domain, seeds)
        if results:
            print_summary(domain, results)
            out.write_txt(domain, results)
            out.write_csv(domain, results)
            if args.json:
                meta = {
                    "domain": domain,
                    "generated_at": now_utc(),
                    "ports": ports,
                    "dns_timeout": DNS_TIMEOUT,
                    "http_timeout_total": HTTP_TOTAL_TIMEOUT,
                    "verify_tls": args.verify_tls,
                    "dns_only": args.dns_only,
                    "web_only": args.web_only,
                }
                out.write_json(domain, results, meta)
            if args.html:
                out.write_html(domain, results)
        else:
            console.print(f"[bold red]No verifiable subdomains discovered for {domain}.[/]")
        end = time.time()
        console.print(f"\n[bold]Scan for {domain} finished in {end - start:.2f} seconds.[/]\n")

    console.print(f"[bold green]All scans finished in {time.time() - overall_start:.2f} seconds.[/]")


if __name__ == "__main__":
    # Silence aiohttp SSL hostname verification warnings if user disables verify (their choice).
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/]")
