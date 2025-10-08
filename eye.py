#!/usr/bin/env python3
# acill_eye_tool.py
# Requires: requests beautifulsoup4 colorama
# Usage: python3 acill_eye_tool.py

import socket
import ssl
import sys
import re
import time
from urllib.parse import urlparse, urljoin

try:
    import requests
    from bs4 import BeautifulSoup
    from colorama import Fore, Style, init as color_init
except Exception:
    print("Missing dependency. Run: pip install requests beautifulsoup4 colorama")
    sys.exit(1)

color_init(autoreset=True)

MAG = Fore.MAGENTA
CYA = Fore.CYAN
GRN = Fore.GREEN
YEL = Fore.YELLOW
RED = Fore.RED
WHT = Fore.WHITE
BOLD = Style.BRIGHT
RST = Style.RESET_ALL
CREATED_BY = "PhishAware-MM"

LOGO = rf"""{MAG}{BOLD}
/$$$$$$$$ /$$     /$$ /$$$$$$$$
| $$_____/|  $$   /$$/| $$_____/
| $$       \  $$ /$$/ | $$      
| $$$$$     \  $$$$/  | $$$$$   
| $$__/      \  $$/   | $$__/   
| $$          | $$    | $$      
| $$$$$$$$    | $$    | $$$$$$$$
|________/    |__/    |________/

{CYA}  👁WebsiteScanner👁                           
"""

COMMON_PORTS = [
    (21, "FTP"), (22, "SSH"), (23, "TELNET"), (25, "SMTP"),
    (53, "DNS"), (80, "HTTP"), (110, "POP3"), (143, "IMAP"),
    (443, "HTTPS"), (3306, "MySQL"), (3389, "RDP"), (8080, "HTTP-alt")
]

SECURITY_HEADERS = {
    "Content-Security-Policy": "Mitigates XSS and data injection.",
    "Strict-Transport-Security": "Enforces HTTPS and prevents downgrade.",
    "X-Content-Type-Options": "Prevents MIME sniffing.",
    "X-Frame-Options": "Prevents clickjacking.",
    "Referrer-Policy": "Controls Referer header.",
    "Permissions-Policy": "Restricts powerful browser features.",
    "X-XSS-Protection": "Legacy XSS protection header."
}

SENSITIVE_PATHS = [
    "/.git/", "/.env", "/.env.local", "/wp-login.php", "/admin",
    "/phpinfo.php", "/config.php", "/.htaccess", "/backup.zip", "/.DS_Store"
]

DEFAULT_TIMEOUT = 6

def print_logo():
    print(MAG + BOLD + LOGO + RST)
    print(CYA + CREATED_BY.center(44) + RST)
    print()

def normalize_host(raw):
    raw = raw.strip()
    raw = re.sub(r"^https?://", "", raw, flags=re.I)
    raw = raw.split("/")[0]
    return raw

def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def whois_basic(domain, timeout=8):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(("whois.iana.org", 43))
        s.sendall((domain + "\r\n").encode())
        resp = b""
        while True:
            d = s.recv(4096)
            if not d:
                break
            resp += d
        s.close()
        txt = resp.decode(errors="replace")
        m = re.search(r"whois:\s*(\S+)", txt, flags=re.I)
        server = m.group(1) if m else None
        if server:
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.settimeout(timeout)
            s2.connect((server, 43))
            s2.sendall((domain + "\r\n").encode())
            resp2 = b""
            while True:
                d = s2.recv(4096)
                if not d:
                    break
                resp2 += d
            s2.close()
            return resp2.decode(errors="replace")
        return txt
    except Exception:
        return None

def extract_creation_date(whois_text):
    if not whois_text:
        return None
    patterns = [r"Creation Date:\s*(.+)", r"Created On:\s*(.+)", r"created:\s*(.+)"]
    for p in patterns:
        m = re.search(p, whois_text, flags=re.I)
        if m:
            return m.group(1).strip()
    return None

def get_cert_info(host):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(6)
            s.connect((host, 443))
            cert = s.getpeercert()
            notAfter = cert.get("notAfter")
            issuer = cert.get("issuer")
            subj = cert.get("subject")
            san = cert.get("subjectAltName", ())
            return {"notAfter": notAfter, "issuer": issuer, "subject": subj, "san": san}
    except Exception:
        return None

def scan_ports(ip, ports=COMMON_PORTS, timeout=0.6):
    res = []
    for port, name in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            res.append((port, name, "open"))
            s.close()
        except socket.timeout:
            res.append((port, name, "filtered/timeout"))
        except ConnectionRefusedError:
            res.append((port, name, "closed"))
        except Exception:
            res.append((port, name, "error"))
        finally:
            try:
                s.close()
            except:
                pass
    return res

def http_get(url):
    try:
        r = requests.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        return r
    except Exception:
        return None

def geo_lookup(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=6)
        if r.status_code == 200:
            return r.json()
        return None
    except Exception:
        return None

def parse_cms_and_meta(html):
    soup = BeautifulSoup(html, "html.parser")
    info = {"cms": None, "version": None, "meta_generator": None}
    gen = soup.find("meta", attrs={"name": "generator"})
    if gen and gen.get("content"):
        info["meta_generator"] = gen.get("content").strip()
        if "wordpress" in gen.get("content", "").lower():
            info["cms"] = "WordPress"
            parts = gen.get("content").split()
            if len(parts) > 1:
                info["version"] = parts[-1]
    body = html.lower()
    if "wp-content" in body or "/wp-includes/" in body:
        info["cms"] = info.get("cms") or "WordPress"
    return info

def check_security_headers(headers):
    missing = []
    for h in SECURITY_HEADERS:
        if h not in headers:
            missing.append(h)
    present = [h for h in SECURITY_HEADERS if h in headers]
    return missing, present

def check_cookies_from_headers(headers):
    sc = headers.get("Set-Cookie", "")
    lacks = []
    if sc:
        parts = sc.split(",")
        for p in parts:
            if "httponly" not in p.lower() or "secure" not in p.lower():
                lacks.append(p.strip()[:120])
    return lacks

def passive_weaknesses(base_url, final_html, headers):
    findings = []
    missing, present = check_security_headers(headers)
    if missing:
        findings.append({"id": "missing_headers", "title": "Missing security headers", "items": missing})
    sc_lacks = check_cookies_from_headers(headers)
    if sc_lacks:
        findings.append({"id": "cookie_flags", "title": "Cookies may lack flags", "items": sc_lacks})
    exposed = []
    for p in SENSITIVE_PATHS:
        try:
            t = urljoin(base_url, p)
            r = requests.get(t, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            if r.status_code == 200:
                txt = r.text.lower()
                if "index of /" in txt or "directory listing for" in txt:
                    exposed.append({"path": p, "reason": "directory listing"})
                else:
                    exposed.append({"path": p, "reason": "200 OK (verify)"})
            elif r.status_code in (401, 403):
                exposed.append({"path": p, "reason": f"{r.status_code} protected"})
        except Exception:
            continue
    if exposed:
        findings.append({"id": "exposed_paths", "title": "Potentially exposed sensitive paths", "items": exposed})
    if "index of /" in final_html.lower() or re.search(r"directory listing for", final_html.lower()):
        findings.append({"id": "directory_listing", "title": "Directory listing detected", "items": []})
    cms = parse_cms_and_meta(final_html)
    if cms.get("cms"):
        findings.append({"id": "cms", "title": "CMS/Tech fingerprint", "items": [cms]})
    try:
        rob = requests.get(urljoin(base_url, "/robots.txt"), timeout=5)
        if rob and rob.status_code == 200:
            sitemaps = re.findall(r"(?im)^sitemap:\s*(\S+)", rob.text)
            findings.append({"id": "robots", "title": "robots.txt found", "items": {"robots": rob.text[:2000], "sitemaps": sitemaps}})
    except Exception:
        pass
    return findings

def compute_security_score(info, findings, ports):
    score = 100
    deductions = 0
    if info.get("cert") is None:
        deductions += 20
    else:
        notAfter = info["cert"].get("notAfter")
        if notAfter:
            try:
                from datetime import datetime
                expires = datetime.strptime(notAfter, "%b %d %H:%M:%S %Y %Z")
                days = (expires - datetime.utcnow()).days
                if days < 30:
                    deductions += 20
                elif days < 90:
                    deductions += 10
            except Exception:
                pass
    missing_headers = [f for f in findings if f["id"] == "missing_headers"]
    if missing_headers:
        miss = len(missing_headers[0]["items"])
        deductions += min(25, miss * 5)
    exposed = [f for f in findings if f["id"] == "exposed_paths"]
    if exposed:
        deductions += min(30, len(exposed[0]["items"]) * 8)
    cookie_issues = [f for f in findings if f["id"] == "cookie_flags"]
    if cookie_issues:
        deductions += 10
    dirlist = [f for f in findings if f["id"] == "directory_listing"]
    if dirlist:
        deductions += 15
    open_ports = sum(1 for p in ports if p[2] == "open")
    if open_ports > 0:
        deductions += min(15, open_ports * 3)
    score -= deductions
    if score < 1:
        score = 1
    if score > 100:
        score = 100
    return int(score)

def print_findings(findings):
    for f in findings:
        print(MAG + BOLD + f"\n== {f['title']} ==" + RST)
        if isinstance(f["items"], dict):
            keys = list(f["items"].keys())
            for k in keys:
                print(YEL + f"{k}:" + RST)
                val = f["items"][k]
                if isinstance(val, str):
                    print(val[:1000])
                else:
                    print(str(val))
        else:
            for it in f["items"]:
                print(WHT + "- " + RST + str(it))

def pause_for_enter():
    try:
        input(CYA + "\nPress Enter to return to menu..." + RST)
    except Exception:
        pass

def menu():
    print_logo()
    target_raw = input(GRN + "Enter a URL or Website Link: " + RST).strip()
    if not target_raw:
        print(RED + "No input. Exiting." + RST)
        return
    host = normalize_host(target_raw)
    ip = resolve_ip(host)
    if ip:
        print(GRN + f"Resolved: {host} -> {ip}" + RST)
    else:
        print(RED + "Could not resolve host." + RST)

    while True:
        print()
        print(MAG + "╔════════════════════════════════════╗" + RST)
        print(CYA + "║             EYE.Webscanner         ║" + RST)
        print(MAG + "╠════════════════════════════════════╣" + RST)
        print(YEL + " 1." + RST + " IP Address")
        print(YEL + " 2." + RST + " Opening ports (lightweight)")
        print(YEL + " 3." + RST + " Website Starting Time (WHOIS)")
        print(YEL + " 4." + RST + " Website location (IP geolocation)")
        print(YEL + " 5." + RST + " Website Owner (WHOIS)")
        print(YEL + " 6." + RST + " Firewall heuristic")
        print(YEL + " 7." + RST + " SSL/TLS Certificate info")
        print(YEL + " 8." + RST + " HTTP headers & Security headers check")
        print(YEL + " 9." + RST + " Website Weakness Analyzer (passive)")
        print(YEL + "10." + RST + " Website Security Level (1% — 100%)")
        print(YEL + " C." + RST + " Change website link")
        print(MAG + "╠════════════════════════════════════╣" + RST)
        print(RED + " Q." + RST + " Quit")
        choice = input(GRN + "Select [1-10,C,Q]: " + RST).strip().lower()

        if choice == "1":
            print(MAG + "\n[IP Address]" + RST)
            if ip:
                print(GRN + f"{host} -> {ip}" + RST)
            else:
                print(RED + "No IP available." + RST)
            pause_for_enter()

        elif choice == "2":
            print(MAG + "\n[Opening ports]" + RST)
            if not ip:
                print(RED + "No IP to scan." + RST)
                pause_for_enter()
                continue
            conf = input(YEL + "Only scan hosts you own. Proceed? (y/N): " + RST).strip().lower()
            if conf != "y":
                print(RED + "Cancelled." + RST)
                pause_for_enter()
                continue
            print(CYA + "Scanning  ports..." + RST)
            ports = scan_ports(ip)
            for p, name, state in ports:
                col = GRN if state == "open" else (YEL if "filtered" in state else RED)
                print(col + f" {p:5} {name:10} -> {state}" + RST)
            pause_for_enter()

        elif choice == "3":
            print(MAG + "\n[Website Starting Time]" + RST)
            who = whois_basic(host)
            if not who:
                print(RED + "WHOIS failed." + RST)
            else:
                cd = extract_creation_date(who)
                if cd:
                    print(GRN + f"Creation/Registration: {cd}" + RST)
                else:
                    print(YEL + "Creation date not found. WHOIS snippet:" + RST)
                    print(who[:600])
            pause_for_enter()

        elif choice == "4":
            print(MAG + "\n[Website location]" + RST)
            if not ip:
                print(RED + "No IP available." + RST)
                pause_for_enter()
                continue
            geo = geo_lookup(ip)
            if not geo:
                print(RED + "Geolocation failed." + RST)
            else:
                if geo.get("status") == "success":
                    out = f"{geo.get('country','?')} / {geo.get('regionName','?')} / {geo.get('city','?')}"
                    out += f"\nISP: {geo.get('isp','?')}\nOrg: {geo.get('org','?')}\nLat/Lon: {geo.get('lat','?')}/{geo.get('lon','?')}"
                    print(GRN + out + RST)
                else:
                    print(YEL + str(geo) + RST)
            pause_for_enter()

        elif choice == "5":
            print(MAG + "\n[Website Owner]" + RST)
            who = whois_basic(host)
            if not who:
                print(RED + "WHOIS failed." + RST)
            else:
                m = re.search(r"(Registrant Organization:|Registrant:|OrgName:|Registrar:).{0,120}", who, flags=re.I)
                if m:
                    print(GRN + m.group(0) + RST)
                else:
                    print(YEL + who[:600] + RST)
            pause_for_enter()

        elif choice == "6":
            print(MAG + "\n[Firewall heuristic]" + RST)
            if not ip:
                print(RED + "No IP available." + RST)
                pause_for_enter()
                continue
            ports_check = [(80, "HTTP"), (443, "HTTPS"), (22, "SSH"), (3389, "RDP")]
            res = scan_ports(ip, ports_check, timeout=0.6)
            open_count = sum(1 for r in res if r[2] == "open")
            timeout_count = sum(1 for r in res if "filtered" in r[2] or r[2] == "error")
            if open_count >= 1 and timeout_count >= 1:
                msg = "Possibly firewall/filters (mixed open & filtered)"
            elif open_count == 0 and timeout_count >= 1:
                msg = "Many ports appear filtered or host down"
            elif open_count >= 1 and timeout_count == 0:
                msg = "No obvious filtering on these common ports"
            else:
                msg = "Inconclusive"
            print(GRN + msg + RST)
            for p, name, state in res:
                col = GRN if state == "open" else (YEL if "filtered" in state else RED)
                print(col + f" {p:5} {name:10} -> {state}" + RST)
            pause_for_enter()

        elif choice == "7":
            print(MAG + "\n[SSL/TLS Certificate]" + RST)
            cert = get_cert_info(host)
            if not cert:
                print(RED + "Certificate info unavailable or no HTTPS." + RST)
            else:
                print(GRN + f"Issuer: {cert.get('issuer')}" + RST)
                print(GRN + f"Subject: {cert.get('subject')}" + RST)
                print(GRN + f"NotAfter: {cert.get('notAfter')}" + RST)
                print(GRN + f"SANs: {cert.get('san')}" + RST)
            pause_for_enter()

        elif choice == "8":
            print(MAG + "\n[HTTP Headers & Security Headers]" + RST)
            url_try = "https://" + host
            r = http_get(url_try) or http_get("http://" + host)
            if not r:
                print(RED + "Failed to fetch site." + RST)
                pause_for_enter()
                continue
            headers = {k: v for k, v in r.headers.items()}
            for k, v in headers.items():
                keycol = CYA if k in SECURITY_HEADERS else WHT
                print(keycol + f"{k}: " + RST + f"{v}")
            missing, present = check_security_headers(headers)
            if missing:
                print(YEL + "\nMissing security headers:" + RST)
                for h in missing:
                    print(RED + "- " + h + RST)
            else:
                print(GRN + "\nAll common security headers present (basic check)." + RST)
            pause_for_enter()

        elif choice == "9":
            print(MAG + "\n[Website Weakness Analyzer - Passive]" + RST)
            base = "https://" + host
            r = http_get(base) or http_get("http://" + host)
            if not r:
                print(RED + "Failed to fetch homepage." + RST)
                pause_for_enter()
                continue
            html = r.text[:200000]
            headers = {k: v for k, v in r.headers.items()}
            findings = passive_weaknesses(base, html, headers)
            if not findings:
                print(GRN + "No obvious passive weaknesses found." + RST)
            else:
                print_findings(findings)
            print(YEL + "\nRemediation suggestions: Keep software updated, set security headers, avoid storing secrets in webroot, secure cookies." + RST)
            pause_for_enter()

        elif choice == "10":
            print(MAG + "\n[Website Security Level]" + RST)
            base = "https://" + host
            r = http_get(base) or http_get("http://" + host)
            if not r:
                print(RED + "Failed to fetch homepage. Cannot compute score." + RST)
                pause_for_enter()
                continue
            html = r.text[:200000]
            headers = {k: v for k, v in r.headers.items()}
            cert = get_cert_info(host)
            findings = passive_weaknesses(base, html, headers)
            ports = []
            if ip:
                ports = scan_ports(ip)
            info = {"cert": cert}
            score = compute_security_score(info, findings, ports)
            band = "Low"
            col = RED
            if score >= 75:
                band = "Good"
                col = GRN
            elif score >= 40:
                band = "Medium"
                col = YEL
            print(col + BOLD + f"Security Score: {score}%  ({band})" + RST)
            print(WHT + "Summary:" + RST)
            if findings:
                print(YEL + f" - Issues found: {len(findings)}" + RST)
                for f in findings:
                    print(RED + f"   * {f['title']}" + RST)
            else:
                print(GRN + " - No passive issues detected." + RST)
            if cert is None:
                print(YEL + " - No valid TLS certificate detected." + RST)
            else:
                print(GRN + " - TLS certificate present." + RST)
            pause_for_enter()

        elif choice == "c":
            new = input(CYA + "Enter new URL or Website Link: " + RST).strip()
            if new:
                host = normalize_host(new)
                ip = resolve_ip(host)
                if ip:
                    print(GRN + f"Now targeting: {host} -> {ip}" + RST)
                else:
                    print(RED + "Could not resolve new host. Host variable updated anyway." + RST)
            else:
                print(YEL + "No change." + RST)
            pause_for_enter()

        elif choice == "q":
            print(MAG + "\nQuitting. Stay Respectful Other. ✌️" + RST)
            break

        else:
            print(RED + "Invalid choice." + RST)
            pause_for_enter()

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\n" + RED + "Interrupted. Bye." + RST)
        sys.exit(0)

