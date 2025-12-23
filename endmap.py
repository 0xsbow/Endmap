#!/usr/bin/env python3
"""
EndMap - Hidden Endpoint Discovery and Fuzzing Tool
A comprehensive tool for discovering and fuzzing hidden endpoints in web applications.
"""

import argparse
import sys
import os
import re
import time
import signal
import requests
from urllib.parse import urljoin, urlparse
from typing import List, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

VERSION = "1.0.0"
SHUTDOWN_EVENT = None

def signal_handler(sig, frame):
    """Handle Ctrl+C signal."""
    global SHUTDOWN_EVENT
    print(f"\n\n[-] Scan interrupted by user (Ctrl+C)")
    print(f"[-] Terminating EndMap .......")
    os._exit(0)

def print_banner():
    """Print the tool banner with ASCII art."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    RESET = '\033[0m'
    banner = f"""{RED}
   ██████╗ ██████╗  ██████╗ ██╗    ██╗
  ██╔════╝ ██╔══██╗██╔═══██╗██║    ██║
  ███████╗ ██████╔╝██║   ██║██║ █╗ ██║
  ╚════██║ ██╔══██╗██║   ██║██║███╗██║
  ███████║ ██████╔╝╚██████╔╝╚███╔███╔╝
  ╚══════╝ ╚═════╝  ╚═════╝  ╚══╝╚══╝{RESET}
"""
    print(banner)
    print(f"\t\t\t{GREEN}EndMap v{VERSION}{RESET}")
    print()

class EndpointDiscovery:
    """Discover hidden endpoints from various sources."""
    
    IMPORTANT_FILES = {
        'robots.txt', 'sitemap.xml', '.env', '.env.local', '.env.production',
        '.git/config', '.gitconfig', '.htaccess', 'web.config', 'package.json',
        'composer.json', 'requirements.txt', 'config.php', 'wp-config.php',
        '.DS_Store', 'error_log', 'debug.log', 'access.log'
    }
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 10
    
    def normalize_url(self, url: str) -> str:
        """Normalize URL by adding https:// if not present."""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def log(self, msg: str):
        """Print log message if verbose mode is enabled."""
        if self.verbose:
            print(f"[*] {msg}")
    
    def discover_from_robots(self, base_url: str) -> Set[str]:
        """Extract endpoints from robots.txt."""
        endpoints = set()
        try:
            url = urljoin(base_url, '/robots.txt')
            resp = self.session.get(url)
            if resp.status_code == 200:
                for line in resp.text.split('\n'):
                    if line.startswith(('Disallow:', 'Allow:', 'Sitemap:')):
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            path = parts[1].strip()
                            if path and path.startswith('/'):
                                endpoints.add(path)
                self.log(f"Found {len(endpoints)} endpoints in robots.txt")
        except Exception as e:
            self.log(f"Error fetching robots.txt: {e}")
        return endpoints
    
    def discover_from_sitemap(self, base_url: str) -> Set[str]:
        """Extract URLs from sitemap.xml."""
        endpoints = set()
        try:
            url = urljoin(base_url, '/sitemap.xml')
            resp = self.session.get(url)
            if resp.status_code == 200:
                urls = re.findall(r'<loc>(.*?)</loc>', resp.text)
                for u in urls:
                    path = urlparse(u).path
                    if path:
                        endpoints.add(path)
                self.log(f"Found {len(endpoints)} endpoints in sitemap.xml")
        except Exception as e:
            self.log(f"Error fetching sitemap.xml: {e}")
        return endpoints
    
    def discover_from_important_files(self, base_url: str) -> Set[str]:
        """Check for important files that might expose endpoints."""
        endpoints = set()
        for file in self.IMPORTANT_FILES:
            try:
                url = urljoin(base_url, f'/{file}')
                resp = self.session.get(url)
                if resp.status_code == 200:
                    self.log(f"Found: {file}")
                    paths = re.findall(r'(?:["\'])(/[^\s"\']*)', resp.text)
                    endpoints.update(paths)
            except:
                pass
        return endpoints
    
    def discover_from_js(self, base_url: str) -> Set[str]:
        """Extract endpoints from JavaScript files in HTML."""
        endpoints = set()
        try:
            resp = self.session.get(base_url)
            if resp.status_code == 200:
                js_files = re.findall(r'(?:src|href)=["\']([^"\']*\.js[^"\']*)', resp.text)
                
                for js_file in js_files:
                    js_url = urljoin(base_url, js_file)
                    try:
                        js_resp = self.session.get(js_url)
                        if js_resp.status_code == 200:
                            paths = re.findall(r'(?:["\'])(/[^\s"\']*?)(?:["\'])', js_resp.text)
                            endpoints.update([p for p in paths if p.startswith('/')])
                    except:
                        pass
        except Exception as e:
            self.log(f"Error discovering from JS: {e}")
        return endpoints
    
    def discover_all(self, base_url: str) -> Set[str]:
        """Discover endpoints from all sources."""
        if self.verbose:
            print(f"\n[+] Discovering endpoints for: {base_url}")
        all_endpoints = set()
        
        all_endpoints.update(self.discover_from_robots(base_url))
        all_endpoints.update(self.discover_from_sitemap(base_url))
        all_endpoints.update(self.discover_from_important_files(base_url))
        all_endpoints.update(self.discover_from_js(base_url))
        
        return all_endpoints

class EndpointValidator:
    """Validate endpoints by making HTTP requests."""
    
    def __init__(self, verbose: bool = False, threads: int = 10):
        self.verbose = verbose
        self.threads = threads
        self.session = requests.Session()
        self.session.verify = False
    
    def log(self, msg: str):
        """Print log message if verbose mode is enabled."""
        if self.verbose:
            print(f"[*] {msg}")
    
    def validate_endpoint(self, base_url: str, endpoint: str) -> Tuple[str, int, bool]:
        """Validate a single endpoint."""
        url = urljoin(base_url, endpoint)
        try:
            resp = self.session.get(url, timeout=5)
            is_live = resp.status_code != 404
            return endpoint, resp.status_code, is_live
        except:
            return endpoint, 0, False
    
    def validate_endpoints(self, base_url: str, endpoints: Set[str], show_status: bool = False, verbose: bool = False) -> List[Tuple[str, int]]:
        """Validate multiple endpoints concurrently."""
        results = []
        executor = ThreadPoolExecutor(max_workers=self.threads)
        try:
            futures = {
                executor.submit(self.validate_endpoint, base_url, ep): ep 
                for ep in endpoints
            }
            
            for future in as_completed(futures):
                endpoint, status_code, is_live = future.result()
                if is_live:
                    results.append((endpoint, status_code))
                    full_url = urljoin(base_url, endpoint)
                    if show_status:
                        print(f"{full_url:<70} [{status_code}]")
                    else:
                        print(f"{full_url}")
        finally:
            executor.shutdown(wait=False)
        
        return sorted(results)

class EndpointFuzzer:
    """Fuzz for hidden endpoints using wordlists."""
    
    DEFAULT_WORDLIST = [
        # Core Directories
        'admin', 'administrator', 'api', 'backup', 'backups', 'config', 'configs',
        'data', 'database', 'db', 'debug', 'dev', 'development', 'docs', 'documentation',
        'download', 'downloads', 'export', 'feed', 'feeds', 'file', 'files', 'front',
        'ftp', 'home', 'homeadmin', 'hotspot', 'html', 'http', 'https', 'icon',
        'icons', 'id', 'image', 'images', 'img', 'import', 'includes', 'index',
        'info', 'information', 'instance', 'instances', 'internal', 'iphone',
        
        # API & Web Services
        'api/v1', 'api/v2', 'api/v3', 'api/v4', 'api/v5', 'api/rest', 'api/soap',
        'api/graphql', 'api/webhooks', 'api/callback', 'api/callbacks',
        'api/auth', 'api/login', 'api/logout', 'api/register', 'api/user', 'api/users',
        'api/account', 'api/accounts', 'api/profile', 'api/admin', 'api/dashboard',
        'rest', 'restapi', 'graphql', 'soap', 'webhook', 'webhooks', 'callback',
        'callbacks', 'events', 'event', 'stream', 'streams', 'socket', 'sockets',
        
        # Authentication & User Management
        'auth', 'authentication', 'authorize', 'authorization', 'login', 'logout',
        'signin', 'signup', 'register', 'registration', 'password', 'passwords',
        'reset', 'forgot', 'change', 'profile', 'user', 'users', 'account', 'accounts',
        'member', 'members', 'customer', 'customers', 'session', 'sessions', 'oauth',
        'oauth2', 'saml', 'ldap', 'sso', 'token', 'tokens', 'jwt', 'api-key', 'apikey',
        
        # Admin & Management Panels
        'admin', 'administrator', 'adminpanel', 'management', 'panel', 'control',
        'controlpanel', 'console', 'dashboard', 'manager', 'cms', 'wp-admin',
        'administrator', 'cp', 'cpanel', 'plesk', 'whm', 'backend', 'backoffice',
        
        # Configuration & System
        'config', 'configuration', 'conf', 'cfg', 'settings', 'system', 'status',
        'health', 'healthcheck', 'info', 'version', 'versions', 'about', 'meta',
        'metadata', 'sitemap', 'robots', 'security', 'privacy', 'terms', 'eula',
        'license', 'changelog', 'readme', 'documentation', 'wiki', 'help', 'faq',
        
        # Application Features
        'dashboard', 'home', 'homepage', 'index', 'main', 'app', 'application',
        'search', 'find', 'filter', 'sort', 'list', 'listing', 'view', 'views',
        'page', 'pages', 'post', 'posts', 'article', 'articles', 'news', 'blog',
        'feed', 'feeds', 'rss', 'xml', 'json', 'data', 'dataset', 'datasets',
        
        # Upload & Download
        'upload', 'uploads', 'download', 'downloads', 'file', 'files', 'media',
        'document', 'documents', 'report', 'reports', 'export', 'import', 'sync',
        'restore', 'backup', 'archive', 'compress', 'extract', 'zip', 'tar',
        
        # Development & Testing
        'dev', 'development', 'test', 'testing', 'staging', 'stage', 'sandbox',
        'debug', 'debugger', 'console', 'terminal', 'shell', 'repl', 'playground',
        'example', 'examples', 'sample', 'samples', 'demo', 'demos', 'mockup',
        'mock', 'stub', 'fixture', 'fixtures', 'trace', 'profiler', 'debuginfo',
        
        # Code & Assets
        'static', 'assets', 'css', 'styles', 'style', 'script', 'scripts', 'js',
        'javascript', 'images', 'img', 'pictures', 'media', 'fonts', 'font',
        'lib', 'libs', 'library', 'vendor', 'node_modules', 'bower_components',
        'public', 'src', 'source', 'dist', 'build', 'compiled',
        
        # Version Control & Sensitive Files
        '.git', '.gitignore', '.env', '.env.local', '.env.production', '.env.development',
        '.env.example', '.htaccess', '.htpasswd', '.gitkeep', '.gitattributes',
        '.DS_Store', '.svn', '.cvs', '.hg', 'Makefile', 'makefile',
        
        # Package Management & Build
        'package.json', 'package-lock.json', 'yarn.lock', 'composer.json',
        'composer.lock', 'requirements.txt', 'Pipfile', 'Gemfile', 'Gemfile.lock',
        'pom.xml', 'build.gradle', 'gradle.properties', 'maven', 'npm',
        
        # Configuration Files
        'config.php', 'config.js', 'config.xml', 'config.json', 'config.yaml',
        'web.config', 'appsettings.json', 'appsettings.development.json',
        'properties', 'settings', 'local.conf', 'database.yml', 'secrets',
        'wp-config.php', 'application.properties', 'application.yml',
        
        # CMS & Framework Specific
        'wordpress', 'wp', 'wp-admin', 'wp-content', 'wp-includes', 'plugins', 'themes',
        'joomla', 'drupal', 'magento', 'shopify', 'prestashop', 'woocommerce',
        'laravel', 'symfony', 'django', 'flask', 'express', 'spring', 'rails',
        
        # Monitoring & Analytics
        'analytics', 'metrics', 'monitoring', 'logs', 'logging', 'audit', 'audits',
        'trace', 'traces', 'telemetry', 'events', 'event', 'report', 'reports',
        'statistics', 'stats', 'performance', 'profiling', 'benchmark',
        
        # Social & Community
        'profile', 'profiles', 'user', 'users', 'comment', 'comments', 'post', 'posts',
        'like', 'likes', 'follow', 'followers', 'friend', 'friends', 'message',
        'messages', 'notification', 'notifications', 'alert', 'alerts',
        
        # Commerce & Payment
        'shop', 'store', 'cart', 'checkout', 'product', 'products', 'category',
        'categories', 'order', 'orders', 'invoice', 'invoices', 'payment', 'payments',
        'billing', 'subscription', 'subscriptions', 'license', 'licenses',
        
        # Security & Compliance
        'security', 'security.txt', 'security.json', 'privacy', 'compliance',
        'terms', 'eula', 'license', 'certificate', 'certificates', 'ssl', 'tls',
        'firewall', 'waf', 'rate-limit', 'throttle', 'ban', 'block', 'allowlist',
        
        # Database & Content
        'db', 'database', 'sql', 'mysql', 'postgres', 'mongodb', 'redis',
        'cache', 'memcached', 'elasticsearch', 'solr', 'backup', 'dump',
        'migration', 'migrations', 'seed', 'seeds', 'fixture', 'fixtures',
        
        # Error & Debug Pages
        'error', 'errors', 'exception', 'exceptions', '404', '500', 'status',
        'debug', 'trace', 'stack', 'stacktrace', 'breakpoint', 'profiler',
        
        # Hidden & Special Paths
        'secret', 'secrets', 'private', 'internal', 'restricted', 'confidential',
        'admin', 'root', 'system', 'bin', 'lib', 'var', 'tmp', 'temp',
        'cache', 'log', 'logs', 'session', 'sessions',
        
        # Common Backup & Archive Extensions (as directories)
        'old', 'backup', 'backups', 'archive', 'archives', 'versions',
        'previous', 'deprecated', 'legacy', 'obsolete', 'unused',
        
        # Machine Learning & Data Science
        'model', 'models', 'ai', 'ml', 'machine-learning', 'neural', 'network',
        'data-science', 'analytics', 'visualization', 'dataset', 'datasets',
        'training', 'inference', 'prediction', 'score', 'ranking',
        
        # Cloud & Container
        'docker', 'kubernetes', 'k8s', 'cloud', 'aws', 'azure', 'gcp',
        'container', 'containers', 'image', 'images', 'registry', 'storage',
        
        # Additional Common Paths
        'action', 'actions', 'handler', 'handlers', 'service', 'services',
        'helper', 'helpers', 'utility', 'utilities', 'tool', 'tools',
        'plugin', 'plugins', 'extension', 'extensions', 'module', 'modules',
        'include', 'includes', 'import', 'imports', 'export', 'exports',
    ]
    
    EXTENSIONS = [
        '', '.php', '.php3', '.php4', '.php5', '.php7', '.php8', '.phtml', '.phar',
        '.html', '.htm', '.shtml', '.xhtml', '.xml', '.xsl', '.xsd',
        '.jsp', '.jspx', '.jsw', '.jsv', '.jspf', '.do', '.action',
        '.asp', '.aspx', '.asax', '.ascx', '.ashx', '.asmx', '.axd',
        '.py', '.pyc', '.pyo', '.wsgi', '.jar', '.war',
        '.rb', '.erb', '.rhtml', '.rails',
        '.pl', '.cgi', '.fcgi', '.pls',
        '.js', '.jsx', '.mjs', '.node',
        '.ts', '.tsx', '.coffee',
        '.go', '.rust', '.swift', '.kotlin',
        '.conf', '.config', '.cfg', '.ini', '.properties', '.yaml', '.yml',
        '.json', '.jsonl', '.ndjson', '.csv', '.tsv', '.sql', '.db',
        '.soap', '.wsdl', '.xsd', '.dtd',
        '.txt', '.md', '.markdown', '.rst', '.asciidoc', '.doc', '.docx',
        '.pdf', '.rtf', '.odt', '.tex',
        '.zip', '.tar', '.tar.gz', '.tar.bz2', '.tar.xz', '.7z', '.rar', '.bak',
        '.backup', '.old', '.orig', '.copy', '.bkp', '.swp', '.swo', '.tmp',
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp', '.bmp',
        '.mp3', '.mp4', '.avi', '.mov', '.flv', '.wmv', '.webm',
        '.pem', '.key', '.crt', '.cer', '.pfx', '.p12', '.ssh', '.pub',
        '.env', '.env.local', '.env.production', '.secrets', '.pkey',
        '.map', '.debug', '.log', '.trace', '.lock',
        '.wp', '.joomla', '.drupal', '.magento', '.shopify',
        '.php.bak', '.php.old', '.php.txt', '.html.bak', '.html.php',
        '.php~', '.bak.php',
    ]
    
    def __init__(self, verbose: bool = False, threads: int = 10):
        self.verbose = verbose
        self.threads = threads
        self.session = requests.Session()
        self.session.verify = False
    
    def log(self, msg: str):
        """Print log message if verbose mode is enabled."""
        if self.verbose:
            print(f"[*] {msg}")
    
    def load_wordlist(self, wordlist_path: str) -> List[str]:
        """Load custom wordlist from file."""
        try:
            with open(wordlist_path, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
            self.log(f"Loaded {len(words)} words from {wordlist_path}")
            return words
        except FileNotFoundError:
            print(f"[-] Wordlist file not found: {wordlist_path}")
            sys.exit(1)
    
    def fuzz_endpoint(self, base_url: str, path: str) -> Tuple[str, int, bool]:
        """Fuzz a single endpoint."""
        url = urljoin(base_url, path)
        try:
            resp = self.session.get(url, timeout=5)
            is_live = resp.status_code != 404
            return path, resp.status_code, is_live
        except:
            return path, 0, False
    
    def fuzz(self, base_url: str, wordlist: List[str] = None, show_status: bool = False, extensions: List[str] = None, verbose: bool = False) -> List[Tuple[str, int]]:
        """Fuzz endpoints."""
        if wordlist is None:
            wordlist = self.DEFAULT_WORDLIST
        
        paths = []
        if extensions:
            for word in wordlist:
                for ext in extensions:
                    paths.append(f"/{word}{ext}")
        else:
            for word in wordlist:
                paths.append(f"/{word}")
        
        # Always show this info
        print(f"\n[+] Fuzzing {base_url}")
        if extensions:
            print(f"[+] Testing with {len(extensions)} extensions: {', '.join(extensions)}")
        else:
            print(f"[+] Testing without extensions")
        print(f"[+] Total requests: {len(paths)}")
        print(f"\n[*] Live endpoints found:\n")
        
        results = []
        executor = ThreadPoolExecutor(max_workers=self.threads)
        try:
            futures = {
                executor.submit(self.fuzz_endpoint, base_url, path): path 
                for path in paths
            }
            
            completed = 0
            for future in as_completed(futures):
                try:
                    path, status_code, is_live = future.result(timeout=1)
                    if is_live:
                        results.append((path, status_code))
                        full_url = urljoin(base_url, path)
                        if show_status:
                            print(f"{full_url:<70} [{status_code}]")
                        else:
                            print(f"{full_url}")
                    completed += 1
                    if verbose and completed % 50 == 0:
                        print(f"[+] Progress: {completed}/{len(paths)}")
                except:
                    completed += 1
        finally:
            executor.shutdown(wait=False)
        
        return sorted(results)

def save_results(results: List[Tuple[str, int]], output_file: str):
    """Save results to a file."""
    try:
        with open(output_file, 'w') as f:
            for endpoint, status_code in results:
                f.write(f"{endpoint} [{status_code}]\n")
        print(f"\n[+] Results saved to: {output_file}")
    except Exception as e:
        print(f"[-] Error saving results: {e}")

def main():
    """Main function."""
    signal.signal(signal.SIGINT, signal_handler)
    
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='EndMap - Hidden Endpoint Discovery and Fuzzing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Discover endpoints on a single host
  python3 endmap.py -u https://example.com

  # Discover endpoints from a list of hosts
  python3 endmap.py -l hosts.txt

  # Fuzz endpoints with default wordlist (no extensions)
  python3 endmap.py -u https://example.com --fuzz

  # Fuzz endpoints with custom extensions
  python3 endmap.py -u https://example.com --fuzz -e .php,.html,.asp

  # Fuzz endpoints with built-in default extensions
  python3 endmap.py -u https://example.com --fuzz --default-ext

  # Fuzz with custom wordlist and extensions
  python3 endmap.py -u https://example.com --fuzz -w wordlist.txt -e .php,.json

  # Fuzz with recursive directory fuzzing
  python3 endmap.py -u https://example.com --fuzz -r

  # Show response codes and verbose output
  python3 endmap.py -u https://example.com --fuzz -rc -v

  # Save results to file
  python3 endmap.py -u https://example.com --fuzz -o results.txt
        """
    )
    
    parser.add_argument('-u', '--url', help='Single URL to scan')
    parser.add_argument('-l', '--list', help='File with list of URLs')
    parser.add_argument('--fuzz', action='store_true', help='Enable fuzzing mode')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist for fuzzing')
    parser.add_argument('-e', '--extensions', help='Extensions to use during fuzzing (e.g., .php,.html,.asp or use --default-ext for built-in set)')
    parser.add_argument('--default-ext', action='store_true', help='Use default built-in extension list during fuzzing')
    parser.add_argument('-r', '--recursive', action='store_true', help='Enable recursive fuzzing on discovered directories')
    parser.add_argument('-o', '--output', help='Output file to save results')
    parser.add_argument('-rc', '--show-status-code', action='store_true', help='Show HTTP response codes')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of concurrent threads (default: 10)')
    
    args = parser.parse_args()
    
    # Validate input
    if not args.url and not args.list:
        parser.print_help()
        sys.exit(1)
    
    # Get list of URLs to process
    urls = []
    if args.url:
        urls.append(args.url)
    if args.list:
        try:
            with open(args.list, 'r') as f:
                urls.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"[-] File not found: {args.list}")
            sys.exit(1)
    
    # Normalize URLs
    discovery = EndpointDiscovery(verbose=args.verbose)
    urls = [discovery.normalize_url(url) for url in urls]
    
    all_results = {}
    
    # Process each URL
    for url in urls:
        try:
            if args.fuzz:
                # Fuzzing mode
                fuzzer = EndpointFuzzer(verbose=args.verbose, threads=args.threads)
                wordlist = None
                if args.wordlist:
                    wordlist = fuzzer.load_wordlist(args.wordlist)
                
                # Handle extensions
                extensions_list = None
                if args.default_ext:
                    extensions_list = fuzzer.EXTENSIONS
                elif args.extensions:
                    extensions_list = [ext.strip() for ext in args.extensions.split(',')]
                
                results = fuzzer.fuzz(url, wordlist, args.show_status_code, extensions_list, args.verbose)
                
                # Recursive fuzzing on directories
                if args.recursive:
                    for endpoint, status_code in results:
                        if status_code in [200, 301, 302, 304]:
                            full_url = urljoin(url, endpoint)
                            if endpoint.endswith('/') or status_code in [301, 302]:
                                if args.verbose:
                                    print(f"\n[+] Recursing into directory: {full_url}")
                                recursive_results = fuzzer.fuzz(full_url, wordlist, args.show_status_code, extensions_list, args.verbose)
                                results.extend(recursive_results)
            else:
                # Default discovery mode
                if args.verbose:
                    print(f"\n{'='*70}")
                    print(f"[+] Discovering endpoints for: {url}")
                    print(f"{'='*70}\n")
                else:
                    print(f"\n[+] Discovering endpoints for: {url}")
                    print(f"[*] Live endpoints found:\n")
                
                endpoints = discovery.discover_all(url)
                validator = EndpointValidator(verbose=args.verbose, threads=args.threads)
                if args.verbose:
                    print(f"[+] Validating and displaying live endpoints\n")
                results = validator.validate_endpoints(url, endpoints, args.show_status_code, args.verbose)
            
            all_results[url] = results
        except KeyboardInterrupt:
            raise
    
    # Display final summary
    if args.verbose:
        print(f"\n\n{'='*70}")
        print(f"SCAN SUMMARY")
        print(f"{'='*70}")
        for url, results in all_results.items():
            print(f"\nResults for: {url}")
            print(f"Total endpoints found: {len(results)}")
    else:
        total_endpoints = sum(len(results) for results in all_results.values())
        if total_endpoints > 0:
            print(f"\n[+] Total endpoints found: {total_endpoints}")
    
    # Save to file if requested
    if args.output:
        all_endpoints = []
        for results in all_results.values():
            all_endpoints.extend(results)
        save_results(all_endpoints, args.output)

if __name__ == '__main__':
    main()
