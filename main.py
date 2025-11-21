#!/usr/bin/env python3

import argparse
import subprocess
import sys
import os
import json
import textwrap
from pathlib import Path
from datetime import datetime
from typing import List, Optional

# ----------------------------- Config & Colors -----------------------------
class Colors:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_banner():
    banner = f"""
{Colors.PURPLE}╔══════════════════════════════════════════════════════════════╗
║                  Web Recon Pipeline for Burp Suite           ║
║        subfinder → dnsx → naabu → httpx → katana             ║
╚══════════════════════════════════════════════════════════════╝{Colors.END}
    """
    print(banner)

# ----------------------------- Helper Functions -----------------------------
def run_command(cmd: List[str], dry_run: bool = False, desc: str = "", use_stdin: Optional[str] = None) -> subprocess.CompletedProcess:
    if desc:
        print(f"{Colors.CYAN}[+] Running: {desc}{Colors.END}")
        print(f"{Colors.YELLOW}    {' '.join(cmd)}{Colors.END}\n")

    if dry_run:
        return subprocess.CompletedProcess(cmd, 0, "", "")

    try:
        if use_stdin:
            result = subprocess.run(cmd, input=use_stdin, capture_output=True, text=True, check=False)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            print(f"{Colors.RED}[-] Error running: {' '.join(cmd)}\n{result.stderr.strip()}{Colors.END}")
        return result
    except FileNotFoundError:
        print(f"{Colors.RED}[-] Command not found: {cmd[0]}. Run: export PATH=~/go/bin:$PATH{Colors.END}")
        sys.exit(1)

def check_tool(tool: str, min_version: str = ""):
    try:
        result = subprocess.run([tool, "-version"], capture_output=True, text=True)
        if result.returncode != 0:
            raise FileNotFoundError
        
        output = result.stdout.strip().lower()
        if "version v" in output:
            version = output.split("version v")[-1].split()[0]
        else:
            version = "unknown"
        print(f"{Colors.GREEN}[+] {tool}: v{version}{Colors.END}")
        if min_version and "unknown" not in version and version < min_version:
            print(f"{Colors.YELLOW}[!] {tool} outdated. Update via pdtm -ia{Colors.END}")
    except:
        print(f"{Colors.RED}[-] {tool} not found/broken. Install: go install github.com/projectdiscovery/pdtm/cmd/pdtm@latest && ~/go/bin/pdtm -ia{Colors.END}")
        

# ----------------------------- Main Pipeline Class -----------------------------
class ReconPipeline:
    def __init__(self, args):
        self.target = args.target
        self.input_file = args.input_file
        self.output_dir = Path(args.output_dir or f"recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.proxy = args.proxy
        self.dry_run = args.dry_run
        self.llm = args.llm
        self.output_dir.mkdir(exist_ok=True)

        
        if self.proxy:
            os.environ["HTTP_PROXY"] = self.proxy
            os.environ["HTTPS_PROXY"] = self.proxy
            print(f"{Colors.GREEN}[+] BurpSuite proxy set: {self.proxy}{Colors.END}")

        
        self.files = {
            "subfinder": self.output_dir / "subfinder.txt",
            "dnsx": self.output_dir / "dnsx.txt",
            "naabu": self.output_dir / "naabu.txt",
            "httpx": self.output_dir / "httpx.txt",
            "katana": self.output_dir / "katana.txt",
            "urls_for_burp": self.output_dir / "urls_for_burp.txt",
            "summary": self.output_dir / "summary.json",
            "llm_analysis": self.output_dir / "llm_analysis.md"
        }

    def run(self):
        print_banner()
        print(f"{Colors.BOLD}Target(s): {self.target or self.input_file}{Colors.END}")
        print(f"{Colors.BOLD}Output Directory: {self.output_dir}{Colors.END}\n")

        targets = []
        if self.input_file:
            targets = [line.strip() for line in open(self.input_file) if line.strip()]
        else:
            targets = [self.target]

        all_live_urls = set()

        for target in targets:
            print(f"{Colors.PURPLE}┌── Starting reconnaissance on: {target}{Colors.END}")
            live_urls = self.recon_single_target(target.strip())
            all_live_urls.update(live_urls)
            print(f"{Colors.PURPLE}└── Finished {target} ({len(live_urls)} URLs)\n{Colors.END}")

        
        with open(self.files["urls_for_burp"], "w") as f:
            for url in sorted(all_live_urls):
                f.write(url + "\n")
        print(f"{Colors.GREEN}[+] All discovered URLs saved to: {self.files['urls_for_burp']} ({len(all_live_urls)} total){Colors.END}")

        if self.llm and all_live_urls:
            self.llm_analysis(list(all_live_urls))

        print(f"\n{Colors.BOLD}{Colors.GREEN}Recon complete! Load '{self.files['urls_for_burp']}' into Burp Suite Site Map → 'Add to scope'.{Colors.END}")

    def recon_single_target(self, domain: str) -> List[str]:
        live_urls = set()

        
        if not self.files["subfinder"].exists() or self.dry_run:
            cmd = ["subfinder", "-d", domain, "-silent", "-o", str(self.files["subfinder"]), "-es", "digitorus"]
            run_command(cmd, self.dry_run, f"subfinder on {domain} (bug-fixed)")
        else:
            print(f"{Colors.YELLOW}[*] Reusing existing subdomains: {self.files['subfinder']}{Colors.END}")

        
        if not self.files["subfinder"].exists() or os.path.getsize(self.files["subfinder"]) == 0:
            print(f"{Colors.RED}[-] Subfinder failed (empty). Skipping for {domain}.{Colors.END}")
            return list(live_urls)

        
        with open(self.files["subfinder"], "r") as f:
            subdomains = f.read()
        cmd = ["dnsx", "-silent", "-resp-only", "-o", str(self.files["dnsx"])]
        run_command(cmd, self.dry_run, "dnsx - resolving A records", use_stdin=subdomains)

        if not self.files["dnsx"].exists() or os.path.getsize(self.files["dnsx"]) == 0:
            print(f"{Colors.YELLOW}[-] No resolved hosts. Skipping for {domain}.{Colors.END}")
            return list(live_urls)

        
        with open(self.files["dnsx"], "r") as f:
            ips = f.read()
        cmd = [
            "naabu", "-p", "80,443,8080,8443,8000,3000,5000,9000",
            "-silent", "-no-color", "-o", str(self.files["naabu"])
        ]
        run_command(cmd, self.dry_run, "naabu - scanning common web ports", use_stdin=ips)

        if not self.files["naabu"].exists() or os.path.getsize(self.files["naabu"]) == 0:
            print(f"{Colors.YELLOW}[-] No open ports. Skipping for {domain}.{Colors.END}")
            return list(live_urls)

        
        with open(self.files["naabu"], "r") as f:
            hosts_ports = f.read()
        proxy_flag = ["-http-proxy", self.proxy] if self.proxy else []
        cmd = [
            "httpx", "-u", "-silent", "-title", "-status-code",
            "-timeout", "15", "-threads", "100", "-retries", "2", "-o", str(self.files["httpx"])
        ] + proxy_flag
        run_command(cmd, self.dry_run, "httpx - probing live web services (Akamai-tuned)", use_stdin=hosts_ports)

       
        httpx_urls = []
        if self.files["httpx"].exists():
            with open(self.files["httpx"]) as f:
                for line in f:
                    parts = line.strip().split()
                    if parts and parts[0].startswith("http"):
                        url = parts[0]
                        httpx_urls.append(url)
                        live_urls.add(url)

        print(f"{Colors.GREEN}[+] Found {len(httpx_urls)} live hosts for {domain}{Colors.END}")

        
        if httpx_urls:
            input_file = self.output_dir / f"httpx_input_{domain.replace('.','_')}.txt"
            with open(input_file, "w") as f:
                f.write("\n".join(httpx_urls))

            katana_proxy = ["-proxy", self.proxy] if self.proxy else []
            cmd = [
                "katana", "-list", str(input_file), "-d", "5", "-jc", "-silent",
                "-o", str(self.files["katana"]), "-ef", "jpg,png,gif,css,js,svg,woff,woff2,pdf"
            ] + katana_proxy
            run_command(cmd, self.dry_run, f"katana - crawling {len(httpx_urls)} base URLs")

            if self.files["katana"].exists():
                with open(self.files["katana"]) as f:
                    for url in f:
                        url = url.strip()
                        if url:
                            live_urls.add(url)
                print(f"{Colors.GREEN}[+] Katana added {len([l for l in self.files['katana'].read_text().strip().splitlines() if l])} new paths{Colors.END}")

        return list(live_urls)

    def llm_analysis(self, urls: List[str]):
        
        try:
            import google.generativeai as genai
            genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
            model = genai.GenerativeModel('gemini-1.5-flash')
        except:
            try:
                from openai import OpenAI
                client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            except:
                print(f"{Colors.RED}[-] LLM requested but no API key found.{Colors.END}")
                return

        sample = urls[:50]
        prompt = f"""
You are a senior web application security expert.
Here are up to 50 discovered endpoints from a target:

{chr(10).join(sample)}

Highlight any endpoints that are particularly interesting for manual testing (e.g. admin panels, login, upload, API, backup files, etc.).
Return in Markdown format with brief reasoning.
        """

        print(f"{Colors.CYAN}[+] Sending {len(sample)} URLs to LLM...{Colors.END}")

        try:
            if 'genai' in locals():
                response = model.generate_content(prompt)
                analysis = response.text
            else:
                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.3
                )
                analysis = response.choices[0].message.content

            with open(self.files["llm_analysis"], "w") as f:
                f.write(f"# LLM Prioritization Analysis\n\nGenerated: {datetime.now()}\n\n")
                f.write(analysis)
            print(f"{Colors.GREEN}[+] LLM analysis saved: {self.files['llm_analysis']}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[-] LLM failed: {e}{Colors.END}")

# ----------------------------- Argument Parser -----------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Automated recon pipeline → ready for Burp Suite (Fixed v2)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
Examples:
  %(prog)s -d example.com
  %(prog)s -d tesla.com --proxy 127.0.0.1:8080
  %(prog)s -f targets.txt -o myrecon --llm
  %(prog)s -d tesla.com --dry-run
        """)
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--target", help="Single domain (e.g. example.com)")
    group.add_argument("-f", "--input-file", help="File with one domain per line")
    parser.add_argument("-o", "--output-dir", help="Output directory (default: timestamped)")
    parser.add_argument("--proxy", help="BurpSuite proxy (e.g. 127.0.0.1:8080)", default=None)
    parser.add_argument("--dry-run", action="store_true", help="Show commands without executing")
    parser.add_argument("--llm", action="store_true", help="Bonus: Run LLM prioritization")
    return parser.parse_args()

# ----------------------------- Main -----------------------------
def main():
    args = parse_args()

    required_tools = [
        ("subfinder", "2.6.7"),
        ("dnsx", "1.2.0"),
        ("naabu", "2.3.0"),
        ("httpx", "1.7.0"),
        ("katana", "1.2.0")
    ]
    print(f"{Colors.CYAN}[*] Checking required tools (latest Nov 2025)...{Colors.END}")
    for tool, min_ver in required_tools:
        check_tool(tool, min_ver)
    print(f"{Colors.YELLOW}[*] Tip: If issues, run 'export PATH=~/go/bin:$PATH'{Colors.END}\n")

    pipeline = ReconPipeline(args)
    pipeline.run()

if __name__ == "__main__":
    main()