# Web Recon Pipeline → Burp Suite Ready  
**subfinder → dnsx → naabu → httpx → katana**  
One-click reconnaissance chain that populates Burp Suite for manual testing.

Perfect for bug bounty, pentest prep, red teaming, and classrooms.

### Features
- Discover subdomains → resolve → port scan → probe live web services → deep crawl
- All traffic from **httpx** and **katana** goes through Burp Suite proxy (optional)
- Generates `urls_for_burp.txt` → import directly into Burp Site Map
- Clean colored output + intermediate files for debugging
- Dry-run mode
- Bonus: LLM prioritization (OpenAI / Gemini) of juicy endpoints
- Works on single domain or list of domains

### Installation

#### 1. Install ProjectDiscovery tools (required)
```bash
# Recommended (always latest)
go install github.com/projectdiscovery/pdtm/cmd/pdtm@latest
~/go/bin/pdtm -ia

# OR classic one-liner
curl -sSfL https://install.projectdiscovery.io | bash
```

#### 2. Install Python dependencies (only for LLM bonus)
```
pip install -r requirements.txt
```

3. Make script executable
```
Bashchmod +x recon_pipeline_fixed_v2.py
Usage
Bash# Basic run
./recon_pipeline_fixed_v2.py -d tesla.com
```

# With Burp Suite proxy (recommended)
```
./recon_pipeline_fixed_v2.py -d tesla.com --proxy 127.0.0.1:8080
```

# Multiple targets
```
./recon_pipeline_fixed_v2.py -f targets.txt --proxy 127.0.0.1:8080
```

# With LLM prioritization (high-value endpoint suggestions)
```
export OPENAI_API_KEY=sk-...    # or GEMINI_API_KEY=...
./recon_pipeline_fixed_v2.py -d hackerone.com --proxy 127.0.0.1:8080 --llm
```

# Dry-run (see commands only)
```
./recon_pipeline_fixed_v2.py -d example.com --dry-run
Output
Everything is saved in a timestamped folder:
textrecon_20251121_123456/
├── subfinder.txt
├── dnsx.txt
├── naabu.txt
├── httpx.txt
├── katana.txt
├── urls_for_burp.txt         ← Import this into Burp!
├── summary.json (future)
└── llm_analysis.md (if --llm used)
```

Tips

Never test katana on scanme.nmap.org → it blocks crawlers intentionally
Good test targets: hackerone.com, bugcrowd.com, tesla.com, github.com
For Akamai/Cloudflare-heavy targets, add --random-agent manually or wait for v3