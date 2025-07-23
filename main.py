import requests
import json
import argparse
import sys
import os
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import uuid
import time
import datetime
import configparser

# --- Configuration File Name ---
SESSION_FILE = ".acunetix_session.json"
SECRET_FILE = "secret.ini"

# --- Suppress Warnings ---
try:
    from urllib3.exceptions import NotOpenSSLWarning
    warnings.filterwarnings("ignore", category=NotOpenSSLWarning)
except ImportError:
    pass
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# --- Banner ---
BANNER = """
\033[94m
    ___    __    ____  _  _  __  __  ____  __  __  ____ 
   / __)  /__\  (  _ \( \/ )(  )(  )(_  _)(  \/  )( ___)
  ( (_-. /(__)\  )   / \  /  )(__)(   )(   )    (  )__) 
   \___/(__)(__)(_)\_)  \/  (______) (__) (_/\/\_)(____)
\033[0m
   Acunetix Batch Scanner - by Bruno Menozzi
   Automates adding, scanning, and monitoring multiple targets.
"""

# --- Helper Functions ---
def print_verbose(response):
    """Prints the full HTTP request and response objects for debugging."""
    req = response.request
    print(f"\n\033[1;33m{'REQUEST':-^30}\033[0m")
    print(f"{req.method} {req.url}")
    print("\n".join(f"{k}: {v}" for k, v in req.headers.items()))
    if req.body:
        try: print(json.dumps(json.loads(req.body), indent=2))
        except (json.JSONDecodeError, TypeError): print(req.body)
    print(f"\n\033[1;33m{'RESPONSE':-^30}\033[0m")
    print(f"Status: {response.status_code} {response.reason}")
    print("\n".join(f"{k}: {v}" for k, v in response.headers.items()))
    if response.text:
        try: print(json.dumps(response.json(), indent=2))
        except json.JSONDecodeError: print(response.text)
    print(f"\033[1;33m{'-'*30}\033[0m\n")


# --- Core Session Management Class ---
class AcunetixSession:
    def __init__(self, user, password, url, proxies, verbose):
        self.user = user
        self.password = password
        self.url = url
        self.proxies = proxies
        self.verbose = verbose
        self.api_key = None
        self.cookie = None
        self._load_session()

    def _save_session(self):
        """Saves the current token and cookie to the session file."""
        if self.api_key and self.cookie:
            with open(SESSION_FILE, 'w') as f:
                json.dump({"x_auth": self.api_key, "cookie": self.cookie}, f)
            if self.verbose: print(f"\033[96m[SESSION]\033[0m Session data saved to {SESSION_FILE}")

    def _load_session(self):
        """Loads token and cookie from the session file if it exists."""
        try:
            with open(SESSION_FILE, 'r') as f:
                session_data = json.load(f)
                self.api_key = session_data.get('x_auth')
                self.cookie = session_data.get('cookie')
            if self.api_key and self.cookie and self.verbose:
                print(f"\033[96m[SESSION]\033[0m Loaded session from {SESSION_FILE}")
        except (FileNotFoundError, json.JSONDecodeError):
            if self.verbose: print(f"\033[96m[SESSION]\033[0m No valid session file found.")

    def login(self):
        """Performs GraphQL login and updates session state."""
        print("\033[96m[AUTH]\033[0m Attempting to log in via GraphQL...")
        login_url = f"{self.url.rstrip('/')}/graphql/"
        graphql_query = {"operationName": "loginUser", "variables": {"data": {"email": self.user, "password": self.password, "rememberMe": False}}, "query": "mutation loginUser($data: UserLoginInput) { login(data: $data) { status token details __typename } }"}
        try:
            response = requests.post(login_url, json=graphql_query, verify=False, proxies=self.proxies, timeout=20)
            if self.verbose: print_verbose(response)
            response.raise_for_status()
            self.api_key = response.headers.get("X-Auth")
            ui_session_cookie = response.cookies.get('ui_session')
            if self.api_key and ui_session_cookie:
                self.cookie = f"ui_session={ui_session_cookie}"
                print("\033[92m[SUCCESS]\033[0m Login successful. Token and Cookie obtained.")
                self._save_session()
                return True
            else:
                error_details = response.json().get('data', {}).get('login', {}).get('details')
                print(f"\033[91m[FATAL]\033[0m Login failed. Token or Cookie missing. Server message: {error_details or 'Unknown error'}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"\033[91m[FATAL]\033[0m Login request failed: {e}")
            return False

    def _make_request(self, method, endpoint, **kwargs):
        """Makes a request, automatically re-authenticating on 401 Unauthorized."""
        if not self.api_key or not self.cookie:
            if not self.login(): return None

        headers = {"X-Auth": self.api_key, "Content-Type": "application/json", "Cookie": self.cookie}
        url = f"{self.url.rstrip('/')}{endpoint}"
        
        try:
            response = requests.request(method, url, headers=headers, proxies=self.proxies, verify=False, **kwargs)
            if self.verbose: print_verbose(response)

            if response.status_code == 401:
                print("\033[93m[AUTH]\033[0m Session token expired or invalid. Re-authenticating...")
                if self.login():
                    headers["X-Auth"] = self.api_key
                    headers["Cookie"] = self.cookie
                    response = requests.request(method, url, headers=headers, proxies=self.proxies, verify=False, **kwargs)
                    if self.verbose: print_verbose(response)
                else: return None
            
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            print(f"\033[91m[ERROR]\033[0m Request to {endpoint} failed: {e}")
            return None

    def add_targets(self, urls):
        """Adds targets in batches of 10 to respect API limits."""
        chunk_size = 10
        url_chunks = [urls[i:i + chunk_size] for i in range(0, len(urls), chunk_size)]
        all_added_targets_map = {}
        
        print(f"\033[96m[PROCESS]\033[0m Total targets to add: {len(urls)}. Preparing {len(url_chunks)} batch(es) of {chunk_size}.")

        for i, chunk in enumerate(url_chunks):
            print(f"\033[96m[PROCESS]\033[0m Submitting batch {i + 1}/{len(url_chunks)} ({len(chunk)} targets)...")
            data = {"targets": [{"address": url, "description": "", "addressValue": "", "web_asset_id": ""} for url in chunk], "groups": []}
            response = self._make_request('POST', "/api/v1/targets/add", data=json.dumps(data))
            
            if response:
                json_response = response.json()
                if isinstance(json_response, dict) and 'targets' in json_response and isinstance(json_response['targets'], list):
                    added_targets_list = json_response['targets']
                    newly_added = {t['address']: t['target_id'] for t in added_targets_list if 'address' in t and 'target_id' in t}
                    all_added_targets_map.update(newly_added)
                    print(f"\033[92m[SUCCESS]\033[0m Batch {i+1} processed. Added {len(newly_added)} new target(s).")
                else:
                    print(f"\033[91m[ERROR]\033[0m Batch {i+1} failed: Unexpected response format.")
            else:
                 print(f"\033[91m[ERROR]\033[0m Batch {i+1} failed: No response from server.")
        
        return all_added_targets_map

    def start_scan(self, target_id, url):
        """Starts a scan for a given target ID."""
        print(f"\033[96m[PROCESS]\033[0m Starting scan for: {url}...")
        data = {"profile_id": "11111111-1111-1111-1111-111111111111", "ui_session_id": uuid.uuid4().hex, "incremental": False, "schedule": {"disable": False, "start_date": None, "time_sensitive": False}, "target_id": target_id}
        response = self._make_request('POST', "/api/v1/scans", data=json.dumps(data))
        if response:
            scan_id = response.json().get('scan_id')
            if scan_id:
                print(f"\033[92m[SUCCESS]\033[0m Scan started for {url} (Scan ID: {scan_id})")
            else:
                print(f"\033[91m[ERROR]\033[0m Scan started for {url}, but could not find scan_id in response.")

    def get_running_scans(self):
        """Fetches the list of currently processing scans."""
        response = self._make_request('GET', "/api/v1/scans?l=20&q=status:processing;")
        if response:
            return response.json().get('scans', [])
        return []

    def run_dashboard(self):
        """Runs the main loop for the live statistics dashboard."""
        try:
            while True:
                stats_response = self._make_request('GET', "/api/v1/me/stats")
                running_scans = self.get_running_scans()
                if stats_response:
                    display_dashboard(stats_response.json(), running_scans)
                else:
                    print("\033[91m[ERROR]\033[0m Could not fetch stats for dashboard. Retrying in 5 seconds...")
                time.sleep(5)
        except KeyboardInterrupt:
            print("\n\n\033[93m[INFO]\033[0m Dashboard stopped by user. Exiting.")

def display_dashboard(stats, running_scans):
    """Clears the screen and prints a formatted dashboard."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print(BANNER)
    
    scans_running = stats.get('scans_running_count', 0)
    scans_waiting = stats.get('scans_waiting_count', 0)
    open_vulns = stats.get('vulnerabilities_open_count', 0)
    targets_count = stats.get('targets_count', 0)
    print("\033[1;96m" + "--- OVERALL STATUS " + "-"*60)
    print(f"  \033[92mTargets:\033[0m {targets_count:<5} | \033[93mRunning:\033[0m {scans_running:<5} | \033[94mWaiting:\033[0m {scans_waiting:<5} | \033[91mOpen Vulns:\033[0m {open_vulns:<5}")
    print("\033[1;96m" + "-"*79 + "\n")

    vuln_totals = stats.get('vuln_count', {})
    crit = vuln_totals.get('crit', 0); high = vuln_totals.get('high', 0); med = vuln_totals.get('med', 0); low = vuln_totals.get('low', 0)
    print("\033[1;96m" + "--- VULNERABILITY TOTALS " + "-"*54)
    print(f"  \033[1;91mCrit:\033[0m {crit:<5} | \033[91mHigh:\033[0m {high:<5} | \033[93mMed:\033[0m {med:<5} | \033[92mLow:\033[0m {low:<5}")
    print("\033[1;96m" + "-"*79 + "\n")
    
    print("\033[1;96m" + "--- ONGOING SCANS " + "-"*62)
    print(f"  \033[4m{'Address':<45} | {'Profile':<15} | {'Status':<12} | {'Progress':>8}\033[0m")
    if not running_scans:
        print("  " + "No scans are currently running.".ljust(88))
    for scan in running_scans:
        addr = scan.get('target', {}).get('address', 'N/A')
        addr_short = (addr[:42] + '...') if len(addr) > 45 else addr
        profile = scan.get('profile_name', 'N/A')
        profile_short = (profile[:13] + '..') if len(profile) > 15 else profile
        status = scan.get('current_session', {}).get('status', 'N/A')
        progress = scan.get('current_session', {}).get('progress', 0)
        print(f"  {addr_short:<45} | {profile_short:<15} | \033[93m{status:<12}\033[0m | {f'{progress}%':>8}")
    print("\033[1;96m" + "-"*79 + "\n")

    targets = stats.get('most_vulnerable_targets', [])
    print("\033[1;96m" + "--- MOST VULNERABLE TARGETS " + "-"*53)
    print(f"  \033[4m{'Address':<45} | {'Crit':^6} | {'High':^6} | {'Med':^6} | {'Low':^6}\033[0m")
    for target in targets[:5]:
        addr = target.get('address', 'N/A')
        addr_short = (addr[:42] + '...') if len(addr) > 45 else addr
        c = target.get('crit_vuln_count', 0); h = target.get('high_vuln_count', 0); m = target.get('med_vuln_count', 0); l = target.get('low_vuln_count', 0)
        print(f"  {addr_short:<45} | \033[1;91m{c:^6}\033[0m | \033[91m{h:^6}\033[0m | \033[93m{m:^6}\033[0m | \033[92m{l:^6}\033[0m")
    print("\033[1;96m" + "-"*79 + "\n")
    print(f"\033[2mLast updated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}. Press Ctrl+C to exit.\033[0m")

def main():
    parser = argparse.ArgumentParser(description="A script to bulk-add, scan, and monitor targets using the Acunetix UI's API.", epilog=BANNER, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-l", "--list", help="File containing a list of target URLs. (Required if not in --dashboard mode)")
    parser.add_argument("-c", "--concurrency", type=int, default=5, help="Number of concurrent scan-starting threads.")
    parser.add_argument("-s", "--scope", help="Optional. Filter by a comma-separated string or a file path.")
    parser.add_argument("-u", "--user", default="admin@admin.com", help="Acunetix login email.")
    parser.add_argument("-p", "--proxy", help="Optional. HTTP/HTTPS proxy (e.g., http://127.0.0.1:8080).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for HTTP requests/responses.")
    parser.add_argument("--start-scans", action="store_true", help="Automatically start scans for newly added targets.")
    parser.add_argument("--dashboard", action="store_true", help="Display a live dashboard of scan statistics instead of adding targets.")
    args = parser.parse_args()

    if not args.dashboard and not args.list:
        parser.error("The --list argument is required unless --dashboard is specified.")
    
    config = configparser.ConfigParser()
    if not os.path.exists(SECRET_FILE):
        print(f"\033[91m[FATAL]\033[0m Configuration file '{SECRET_FILE}' not found.")
        print("\033[93m[INFO]\033[0m Please create it with the following content:")
        print("    [Acunetix]\n    url = https://your_acunetix_url:13443\n    password = your_password_or_hash")
        sys.exit(1)

    config.read(SECRET_FILE)
    try:
        acunetix_url = config.get('Acunetix', 'url')
        acunetix_password = config.get('Acunetix', 'password')
        if not acunetix_url or not acunetix_password:
            raise configparser.NoOptionError("url or password", "Acunetix")
    except (configparser.NoSectionError, configparser.NoOptionError):
        print(f"\033[91m[FATAL]\033[0m '{SECRET_FILE}' is not configured correctly.")
        print("\033[93m[INFO]\033[0m Ensure it contains the '[Acunetix]' section with non-empty 'url' and 'password' keys.")
        sys.exit(1)
    
    print(BANNER)
    proxies_dict = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    if proxies_dict: print(f"\033[93m[CONFIG]\033[0m Using proxy: {args.proxy}")
    print(f"\033[93m[CONFIG]\033[0m Loaded settings from {SECRET_FILE}")

    session = AcunetixSession(args.user, acunetix_password, acunetix_url, proxies_dict, args.verbose)
    if not session.api_key:
        if not session.login(): sys.exit(1)

    if args.dashboard:
        session.run_dashboard()
    else:
        try:
            with open(args.list, 'r') as f: urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"\033[91m[FATAL] Input file not found: {args.list}\033[0m"); sys.exit(1)

        if args.scope:
            print(f"\033[96m[SCOPE]\033[0m Applying scope filter...")
            if os.path.isfile(args.scope):
                with open(args.scope, 'r') as f: scope_patterns = [line.strip() for line in f if line.strip()]
            else:
                scope_patterns = [p.strip() for p in args.scope.split(',') if p.strip()]
            original_count = len(urls)
            urls = [url for url in urls if any(p in url for p in scope_patterns)]
            print(f"\033[96m[SCOPE]\033[0m Filter applied. Kept {len(urls)} of {original_count} targets.")

        if not urls:
            print("\033[91m[FATAL] No targets left to scan.\033[0m"); sys.exit(1)
        
        added_targets_map = session.add_targets(urls)

        if args.start_scans:
            if not added_targets_map:
                print("\033[93m[INFO]\033[0m No new targets were added, so no scans will be started.")
            else:
                print(f"\n\033[1m[INIT] Starting scans for {len(added_targets_map)} targets with {args.concurrency} threads.\033[0m\n")
                with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
                    futures = [executor.submit(session.start_scan, target_id, url) for url, target_id in added_targets_map.items()]
                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception as e:
                            print(f"\033[91m[THREAD ERROR]\033[0m An error occurred: {e}")
        else:
            if added_targets_map:
                print("\033[93m[INFO]\033[0m Targets added successfully. Scans were not started as --start-scans flag was not provided.")
            else:
                print("\033[93m[INFO]\033[0m No new targets were added. This may be because they already exist.")

    print("\n\033[1m[DONE] All processes have been completed.\033[0m")

if __name__ == "__main__":
    main()
