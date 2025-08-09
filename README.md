# SubreconGemini 🛡️🔍

**SubreconGemini** is a high-performance subdomain discovery tool that combines **Google Gemini AI**, **certificate transparency logs**, and **wordlist brute-forcing** to uncover and verify live subdomains.

---

## 🚀 Features

- **Hybrid Discovery Methods**  
  - 🤖 **AI-Powered** — Uses Google Gemini API to suggest likely subdomains based on context.  
  - 📜 **Certificate Transparency** — Queries `crt.sh` for subdomains from SSL/TLS certificates.  
  - 📖 **Wordlist Brute-force** — Enumerates using customizable wordlists.  

- **Smart Validation**  
  - DNS resolution with wildcard detection to reduce false positives.  
  - Optional HTTP probing to detect live services and fetch status codes + page titles.  

- **High Speed**  
  - Fully asynchronous (`asyncio` + `aiohttp`) for maximum concurrency.  

- **Rich Output**  
  - Color-coded console output via `rich`.  
  - Generates `.txt` (raw list) and `.csv` (detailed) reports.  

- **Flexible Input**  
  - Scan a single domain (`-d`) or multiple from a file (`-l`).  

---

## 📦 Requirements

- **Python 3.7+**
- Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

```bash
usage: SubreconGemini.py [-h] (-d DOMAIN | -l LIST) [--scan {fast,normal,full}] [--ports PORTS] [--dns-only] [--web-only] [--verify-tls] [--no-verify-tls] [--proxy PROXY] [--output-dir OUTPUT_DIR] [--json] [--html] [--max-http MAX_HTTP] [--max-dns MAX_DNS] [--ai] [--ai-count AI_COUNT] [--gemini-key GEMINI_KEY] [--gemini-model GEMINI_MODEL]

Subrecon (async) – Focused Subdomain Discovery

options:
  -h, --help            show this help message and exit
  -d, --domain DOMAIN   Target domain (e.g., example.com) (default: None)
  -l, --list LIST       Path to a file with target domains (default: None)
  --scan {fast,normal,full}
                        Port scan preset {fast | normal | full} (default: normal)
  --ports PORTS         Comma-separated ports to override preset (e.g., 80,443,8080) (default: None)
  --dns-only            Only perform DNS enumeration/verification (default: False)
  --web-only            Keep only hosts with web responses (default: False)
  --verify-tls          Verify TLS certificates (default on) (default: True)
  --no-verify-tls       Do not verify TLS certificates (default: True)
  --proxy PROXY         HTTP/S proxy (e.g., http://127.0.0.1:8080) (default: None)
  --output-dir OUTPUT_DIR
                        Output directory (default: recon_results)
  --json                Also write JSON results (default: False)
  --html                Also write HTML report (default: False)
  --max-http MAX_HTTP   Max concurrent HTTP requests (default: 220)
  --max-dns MAX_DNS     Max concurrent DNS queries (default: 800)
  --ai                  Enable Gemini AI seeding for additional candidates (default: False)
  --ai-count AI_COUNT   How many AI labels to request (default: 150)
  --gemini-key GEMINI_KEY
                        Gemini API key (or set GEMINI_API_KEY) (default: None)
  --gemini-model GEMINI_MODEL
                        Gemini model name (default: gemini-1.5-flash)
```
## Example Usage
```bash
python SubreconGemini.py -d google.com --scan full --ai --gemini-key API_KEY --proxy http://127.0.0.1:8080 --html
```

![Databases ](./Images/Screenshot%20from%202025-07-30%2016-57-02.png) 
<img width="2999" height="1297" alt="new-code-subrecon" src="https://github.com/user-attachments/assets/9b01669e-c350-4806-8699-13eda4ef353d" />


