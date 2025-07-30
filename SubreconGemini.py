#!/usr/bin/env python3
import os
import re
import json
import time
import random
import asyncio
import argparse
import dns.resolver
import requests
from typing import List, Dict, Set, Optional
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from rich.console import Console
from rich.progress import Progress
from rich.panel import Panel
from rich.table import Table

# Configuration
MAX_WORKERS = 50
DNS_TIMEOUT = 2
REQUEST_TIMEOUT = 10
WORDLIST_URLS = {
    'common': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt',
    'cloud': 'https://gist.githubusercontent.com/six2dez/ffc2b14d283e8f8f6dde2a657e925ef4/raw/cloud-providers.txt',
}

console = Console()

class SubreconGemini:
    def __init__(self, gemini_key: str = None, bing_cookies: dict = None):
        """Initialize the hunter with multiple engines"""
        self.gemini = self._init_gemini(gemini_key) if gemini_key else None
        self.bing_cookies = bing_cookies
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'SubreconGemini/2.0'})
        self.wordlists = self._load_wordlists()
        self.dns_resolver = self._init_dns()
        
        console.print(Panel.fit(
            "[bold green]SubreconGemini[/] [yellow]v2.0 (Lite)[/]\n"
            "[white]Focused Subdomain Discovery[/]",
            border_style="blue"
        ))

    def _init_gemini(self, api_key: str) -> Optional[dict]:
        """Initialize Google Gemini API"""
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            return {
                'pro': genai.GenerativeModel("gemini-2.5-pro"),
                'flash': genai.GenerativeModel("gemini-1.5-flash-latest")
            }
        except ImportError:
            console.print("[red]Gemini API not available - install google-generativeai[/]")
            return None

    def _load_wordlists(self) -> Dict[str, List[str]]:
        """Load wordlists from multiple sources"""
        wordlists = {}
        with Progress() as progress:
            task = progress.add_task("[cyan]Loading wordlists...", total=len(WORDLIST_URLS))
            
            for name, url in WORDLIST_URLS.items():
                try:
                    response = self.session.get(url, timeout=REQUEST_TIMEOUT)
                    wordlists[name] = list(set(response.text.splitlines()))
                    progress.update(task, advance=1, description=f"[green]Loaded {name} wordlist")
                except Exception as e:
                    console.print(f"[yellow]Failed to load {name} wordlist: {str(e)}[/]")
                    wordlists[name] = []
        
        if not any(wordlists.values()):
            wordlists = {
                'common': ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test'],
                'cloud': ['aws', 'azure', 'gcp', 's3', 'cdn']
            }
        return wordlists

    def _init_dns(self) -> dns.resolver.Resolver:
        """Configure high-performance DNS resolver"""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['1.1.1.1', '8.8.8.8', '9.9.9.9']
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        return resolver

    async def discover(self, domain: str, max_subs: int = 200) -> Dict[str, dict]:
        """Main discovery workflow with hybrid approach"""
        console.print(Panel.fit(
            f"[bold]Starting reconnaissance on [cyan]{domain}[/]",
            border_style="blue"
        ))
        
        subdomains = set()
        
        if self.gemini:
            with console.status("[bold green]Running Gemini discovery..."):
                gemini_subs = await self._ai_discovery(domain, max_subs//2)
                subdomains.update(gemini_subs)
                console.print(f"[green]✓[/] Gemini found {len(gemini_subs)} candidates")
        
        with console.status("[bold green]Running wordlist brute-force..."):
            wordlist_subs = self._wordlist_bruteforce(domain, max_subs//2)
            subdomains.update(wordlist_subs)
            console.print(f"[green]✓[/] Wordlists found {len(wordlist_subs)} candidates")
        
        with console.status("[bold green]Checking certificate logs..."):
            ct_subs = self._check_ct_logs(domain)
            subdomains.update(ct_subs)
            console.print(f"[green]✓[/] CT logs found {len(ct_subs)} candidates")
        
        verified_subs = {}
        if subdomains:
            with console.status("[bold green]Verifying subdomains..."):
                verified_subs = self._verify_subdomains(subdomains, domain)
        
        return verified_subs

    async def _ai_discovery(self, domain: str, count: int) -> List[str]:
        """Generate subdomains using AI"""
        if not self.gemini: return []
        subs_full = []
        prompt = f"As a cybersecurity expert, suggest {count} likely subdomains for {domain}. Respond with ONLY comma-separated values."
        
        try:
            # Use Flash model for speed
            response = self.gemini['flash'].generate_content(prompt)
            subs_full.extend(self._clean_subs(response.text.split(','), domain))
        except Exception as e:
            console.print(f"[yellow]Gemini Flash failed: {str(e)}[/]")

        return list({sub.replace(f'.{domain}', '') for sub in set(subs_full)})

    def _clean_subs(self, subs: List[str], domain: str) -> List[str]:
        """Clean and format subdomain candidates from AI output."""
        cleaned = []
        for sub in subs:
            s = sub.strip()
            if s and not s.endswith(domain):
                cleaned.append(f"{s}.{domain}")
            elif s:
                cleaned.append(s)
        return cleaned

    def _wordlist_bruteforce(self, domain: str, count: int) -> List[str]:
        candidates = []
        for wordlist in self.wordlists.values():
            candidates.extend(word for word in wordlist[:count//2])
        return list(set(candidates))

    def _check_ct_logs(self, domain: str) -> List[str]:
        """Check Certificate Transparency logs for subdomains."""
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = self.session.get(url, timeout=REQUEST_TIMEOUT)

            if response.status_code != 200:
                return []
            
            data = response.json()
            return list({
                entry['name_value'].lower().replace(f'.{domain}', '').split('.')[-1]
                for entry in data
                if f'.{domain}' in entry['name_value'].lower() and entry['name_value'] != f"*.{domain}"
            })
        except Exception:
            return []

    def _detect_wildcard(self, domain: str) -> List[str]:
        try:
            test_sub = f"nonexistent-{random.randint(10000,99999)}.{domain}"
            answers = self.dns_resolver.resolve(test_sub, 'A')
            return [r.to_text() for r in answers]
        except:
            return []

    def _verify_subdomains(self, subdomains: Set[str], domain: str) -> Dict[str, dict]:
        results = {}
        wildcard_ips = self._detect_wildcard(domain)
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Verifying subdomains...", total=len(subdomains))
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {
                    executor.submit(self._inspect_subdomain, f"{sub}.{domain}", wildcard_ips): sub
                    for sub in subdomains if sub
                }
                for future in futures:
                    sub_prefix = futures[future]
                    full_subdomain = f"{sub_prefix}.{domain}"
                    try:
                        result = future.result()
                        if result:
                            results[full_subdomain] = result
                    except Exception:
                        pass # Ignore errors for individual subdomains
                    progress.update(task, advance=1)
        return results

    def _inspect_subdomain(self, subdomain: str, wildcard_ips: List[str]) -> Optional[dict]:
        """Verifies if subdomain is live via DNS and checks HTTP status/title."""
        try:
            answers = self.dns_resolver.resolve(subdomain, 'A')
            ips = [r.to_text() for r in answers]
            # If the resolved IPs match the wildcard IPs, it's not a unique, live subdomain.
            if any(ip in wildcard_ips for ip in ips):
                return None
        except Exception:
            # If DNS resolution fails for any reason (NXDOMAIN, timeout, etc.), it's not live.
            return None
        
        # If we get here, the subdomain is live via DNS. Now check HTTP.
        http_data = self._check_http(subdomain)
        
        return {
            'ips': ips,
            'http_status': http_data.get('status', 'N/A'),
            'title': http_data.get('title', 'N/A'),
        }

    def _check_http(self, subdomain: str) -> dict:
        for scheme in ['https', 'http']:
            try:
                url = f"{scheme}://{subdomain}"
                response = self.session.get(url, allow_redirects=True, timeout=REQUEST_TIMEOUT, verify=False)
                return {
                    'status': response.status_code, 
                    'title': self._extract_title(response.text)
                }
            except requests.RequestException:
                continue
        return {'error': 'No HTTP response'}

    def _extract_title(self, html: str) -> str:
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else "No Title"

    def generate_report(self, results: Dict[str, dict], domain: str, output_dir: str = "recon_results"):
        """Generate simplified reports"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Simple TXT list of live subdomains
        txt_path = os.path.join(output_dir, f"{domain}_subdomains.txt")
        self._generate_txt(results, txt_path)
        console.print(f"[green]✓[/] TXT subdomain list saved to [cyan]{txt_path}[/]")
        
        # Simplified CSV report
        csv_path = os.path.join(output_dir, f"{domain}_summary.csv")
        self._generate_csv(results, csv_path)
        console.print(f"[green]✓[/] CSV summary saved to [cyan]{csv_path}[/]")
        
        # Print summary table to console
        self._print_summary(results, domain)

    def _generate_txt(self, results: Dict[str, dict], output_path: str):
        """Generate a simple text file with one subdomain per line."""
        with open(output_path, 'w', encoding='utf-8') as f:
            for sub in sorted(results.keys()):
                f.write(f"{sub}\n")

    def _generate_csv(self, results: Dict[str, dict], output_path: str):
        import csv
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Subdomain', 'IPs', 'HTTP Status', 'Title'])
            for sub, info in sorted(results.items()):
                writer.writerow([
                    sub, 
                    ','.join(info.get('ips', [])), 
                    info.get('http_status', 'N/A'),
                    info.get('title', 'N/A')
                ])

    def _print_summary(self, results: Dict[str, dict], domain: str):
        if not results:
            console.print(f"\n[bold yellow]No verified subdomains found for {domain}.[/]")
            return
            
        table = Table(title=f"Live Subdomains for {domain}")
        table.add_column("Subdomain", style="cyan", no_wrap=True)
        table.add_column("IPs", style="magenta")
        table.add_column("HTTP Status", style="green")
        table.add_column("Title", style="white")

        # Sort results alphabetically for the summary table
        sorted_results = sorted(results.items())

        for sub, info in sorted_results:
            status_str = str(info.get('http_status', 'N/A'))
            status_color = "green" if status_str.startswith('2') else "yellow" if status_str.startswith('3') else "red"
            
            table.add_row(
                sub, 
                ','.join(info.get('ips', [])), 
                f"[{status_color}]{status_str}[/]",
                info.get('title', 'N/A')[:60]
            )
        console.print(table)
        console.print(f"\n[bold]Total verified subdomains found:[/] {len(results)}")


async def main():
    parser = argparse.ArgumentParser(description="SubreconGemini (Lite) - Focused Subdomain Discovery", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Target domain (e.g., example.com)")
    group.add_argument("-l", "--list", help="Path to a file containing a list of target domains")
    
    parser.add_argument(
        "-k", "--key",
        dest="gemini_key",
        help="Google Gemini API key",
        default=os.getenv("GEMINI_API_KEY")
    )
    
    parser.add_argument("-o", "--output-dir", help="Output directory", default="recon_results")
    args = parser.parse_args()

    targets = []
    if args.domain:
        targets.append(args.domain)
    elif args.list:
        try:
            with open(args.list, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            console.print(f"[red]Error: Target file not found at {args.list}[/]")
            return

    if not args.gemini_key:
        console.print("[yellow]Warning: Gemini API key not provided. AI discovery will be limited.[/]")

    hunter = SubreconGemini(gemini_key=args.gemini_key)
    
    overall_start_time = time.time()
    for domain in targets:
        domain_start_time = time.time()
        results = await hunter.discover(domain)
        
        if results:
            hunter.generate_report(results, domain, args.output_dir)
        else:
            console.print(f"\n[bold red]Scan completed for {domain}. No verifiable subdomains were discovered.[/]")
        
        domain_end_time = time.time()
        console.print(f"\n[bold]Scan for {domain} finished in {domain_end_time - domain_start_time:.2f} seconds.[/]\n")
    
    overall_end_time = time.time()
    console.print(f"[bold green]All scans finished in {overall_end_time - overall_start_time:.2f} seconds.[/]")

if __name__ == "__main__":
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    
    asyncio.run(main())