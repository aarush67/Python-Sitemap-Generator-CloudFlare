import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.robotparser import RobotFileParser
import dns.resolver
import json
import logging
import getpass
import time
import random
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import argparse

def create_session():
    """Create a requests session with retries."""
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=2, status_forcelist=[429, 500, 502, 503, 504, 530])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def get_user_agent():
    """Return a random User-Agent to mimic different browsers."""
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
    ]
    return random.choice(user_agents)

def is_valid_url(url, session, respect_robots=True, timeout=5, logger=None):
    """Check if the URL is valid and accessible."""
    if logger is None:
        logger = logging.getLogger(__name__)
    headers = {"User-Agent": get_user_agent()}
    try:
        response = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        content_type = response.headers.get('content-type', '').lower()
        logger.info(f"URL {url} returned status {response.status_code}, content-type: {content_type}")
        if respect_robots and response.status_code in [200, 301, 302, 403, 404]:
            if not is_allowed_by_robots(url, session, headers["User-Agent"], timeout, logger):
                return False
        return True
    except requests.RequestException as e:
        logger.error(f"Failed to validate URL {url}: {e}")
        return False

def resolve_domain(domain, logger=None):
    """Check if domain resolves via DNS."""
    if logger is None:
        logger = logging.getLogger(__name__)
    resolver = dns.resolver.Resolver()
    try:
        resolver.resolve(domain, 'A')
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return False
    except Exception as e:
        logger.error(f"Error resolving {domain}: {e}")
        return False

def get_root_domain(url):
    """Extract the root domain (e.g., example.com) from a URL."""
    parsed = urlparse(url)
    domain_parts = parsed.netloc.split('.')
    if len(domain_parts) > 2:
        return '.'.join(domain_parts[-2:])
    return parsed.netloc

def is_allowed_by_robots(url, session, user_agent, timeout, logger=None):
    """Check if URL is allowed by robots.txt for its domain."""
    if logger is None:
        logger = logging.getLogger(__name__)
    parsed = urlparse(url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    rp = RobotFileParser()
    try:
        headers = {"User-Agent": user_agent}
        response = session.get(robots_url, headers=headers, timeout=timeout)
        rp.parse(response.text.splitlines())
        allowed = rp.can_fetch(user_agent, url)
        if not allowed:
            logger.warning(f"URL {url} disallowed by robots.txt")
        return allowed
    except Exception as e:
        logger.error(f"Error reading robots.txt for {url}: {e}")
        return True

def clean_url(url):
    """Remove fragments and query strings from URL."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip('/')

def get_cloudflare_dns_records(tld, api_token, logger=None):
    """Retrieve all DNS records from Cloudflare API."""
    if logger is None:
        logger = logging.getLogger(__name__)
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    zone_id = None
    dns_records = []

    try:
        response = requests.get(
            f"https://api.cloudflare.com/client/v4/zones?name={tld}",
            headers=headers
        )
        result = response.json()
        if result["success"] and result["result"]:
            zone_id = result["result"][0]["id"]
            logger.info(f"Found Cloudflare zone ID for {tld}: {zone_id}")
        else:
            logger.error(f"Failed to find zone ID for {tld}: {result}")
            return []
    except Exception as e:
        logger.error(f"Error fetching zone ID for {tld}: {e}")
        return []

    try:
        response = requests.get(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            headers=headers
        )
        result = response.json()
        if result["success"]:
            dns_records = result["result"]
            logger.info(f"Retrieved {len(dns_records)} DNS records from Cloudflare")
        else:
            logger.error(f"Failed to retrieve DNS records: {result}")
    except Exception as e:
        logger.error(f"Error fetching DNS records: {e}")

    return dns_records

def discover_subdomains(tld, api_token, session, respect_robots=True, timeout=5, logger=None, progress=None):
    """Discover subdomains via Cloudflare DNS, wordlist, and crt.sh."""
    if logger is None:
        logger = logging.getLogger(__name__)
    subdomains = set()

    # Extended subdomain wordlist
    common_subdomains = [
        "", "www", "blog", "shop", "store", "api", "mail", "dev", "app", "login",
        "admin", "secure", "support", "forum", "news", "dashboard", "staging", "test",
        "beta", "portal", "web", "online", "home", "my", "account", "signup", "cpanel",
        "webmail", "ftp", "smtp", "pop", "imap", "vpn", "remote", "auth", "sso", "git",
        "ci", "cdn", "static", "assets", "media", "images", "files", "wiki", "docs",
        "help", "status", "monitor", "billing", "pay", "checkout", "cart", "learn",
        "community", "events", "jobs", "careers", "about", "contact", "privacy", "terms"
    ]

    # Set total subdomains for estimation
    if progress is not None:
        progress['total_subdomains'] = len(common_subdomains) + 50  # Approx. crt.sh + DNS records

    # 1. Cloudflare DNS records
    logger.info("Fetching DNS records from Cloudflare")
    dns_records = get_cloudflare_dns_records(tld, api_token, logger)
    for record in dns_records:
        name = record["name"]
        if name.endswith(tld) and not name.startswith(('_', '*')):  # Skip DMARC, DKIM, etc.
            if resolve_domain(name, logger):  # Check if domain resolves
                subdomain = f"https://{name}"
                time.sleep(random.uniform(0.5, 1.5))  # Delay to avoid rate-limiting
                if is_valid_url(subdomain, session, respect_robots, timeout, logger):
                    subdomains.add(subdomain)
                    logger.info(f"Found subdomain from Cloudflare DNS: {subdomain}")
                    if progress is not None:
                        progress['subdomains_found'] += 1
                else:
                    logger.warning(f"Skipping non-accessible subdomain: {subdomain}")

    # 2. Brute-force with wordlist
    logger.info("Brute-forcing subdomains with wordlist")
    for subdomain in common_subdomains:
        domain = f"{subdomain}.{tld}" if subdomain else tld
        if resolve_domain(domain, logger):  # Check if domain resolves
            url = f"https://{domain}"
            time.sleep(random.uniform(0.5, 1.5))  # Delay to avoid rate-limiting
            if is_valid_url(url, session, respect_robots, timeout, logger):
                subdomains.add(url)
                logger.info(f"Found subdomain from wordlist: {url}")
                if progress is not None:
                    progress['subdomains_found'] += 1
            else:
                logger.warning(f"Skipping non-accessible subdomain: {url}")

    # 3. Certificate transparency logs via crt.sh
    logger.info("Fetching subdomains from crt.sh")
    try:
        response = requests.get(f"https://crt.sh/?q=%.{tld}&output=json", timeout=timeout)
        if response.status_code == 200:
            certs = json.loads(response.text)
            for cert in certs:
                name = cert["name_value"].strip()
                if '\n' in name or '%' in name:  # Skip malformed entries
                    continue
                if name.startswith("*."):
                    name = name[2:]  # Remove wildcard
                if name.endswith(tld) and resolve_domain(name, logger):  # Check if domain resolves
                    url = f"https://{name}"
                    time.sleep(random.uniform(0.5, 1.5))  # Delay to avoid rate-limiting
                    if is_valid_url(url, session, respect_robots, timeout, logger):
                        subdomains.add(url)
                        logger.info(f"Found subdomain from crt.sh: {url}")
                        if progress is not None:
                            progress['subdomains_found'] += 1
                    else:
                        logger.warning(f"Skipping non-accessible subdomain: {url}")
    except Exception as e:
        logger.error(f"Error fetching from crt.sh: {e}")

    return subdomains

def crawl_url(url, session, visited, collected_urls, root_domain, respect_robots=True, timeout=5, logger=None, progress=None):
    """Crawl a single URL and return found links."""
    if logger is None:
        logger = logging.getLogger(__name__)
    if url in visited:
        return []

    visited.add(url)
    logger.info(f"Crawling: {url}")
    headers = {"User-Agent": get_user_agent()}
    try:
        time.sleep(random.uniform(1, 3))  # Delay to avoid Cloudflare rate-limiting
        response = session.get(url, headers=headers, timeout=timeout)
        content_type = response.headers.get('content-type', '').lower()
        if response.status_code not in [200, 301, 302, 403, 404]:
            logger.warning(f"Skipping {url}: status {response.status_code}, content-type {content_type}")
            return []
    except requests.RequestException as e:
        logger.error(f"Failed to crawl {url}: {e}")
        return []

    collected_urls.add(clean_url(url))
    if progress is not None:
        progress['urls_crawled'] += 1
    found_urls = []
    if 'text/html' in content_type:
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a', href=True):
            href = link['href']
            absolute_url = urljoin(url, href)

            if not absolute_url.startswith(('http://', 'https://')):
                continue

            parsed_url = urlparse(absolute_url)
            if not parsed_url.netloc.endswith(root_domain):
                continue

            cleaned_url = clean_url(absolute_url)
            if is_valid_url(cleaned_url, session, respect_robots, timeout, logger) and cleaned_url not in visited:
                found_urls.append(cleaned_url)

    return found_urls

def crawl_website(start_urls, root_domain, respect_robots=True, timeout=5, logger=None, progress=None):
    """Crawl the website and subdomains sequentially."""
    if logger is None:
        logger = logging.getLogger(__name__)
    visited = set()
    collected_urls = set()
    session = create_session()

    for start_url in start_urls:
        url_queue = [start_url]
        while url_queue:
            url = url_queue.pop(0)
            new_urls = crawl_url(url, session, visited, collected_urls, root_domain, respect_robots, timeout, logger, progress)
            url_queue.extend([u for u in new_urls if u not in visited])

    return collected_urls

def generate_sitemap(urls, output_file="sitemap.xml", logger=None):
    """Generate sitemap.xml from a set of URLs."""
    if logger is None:
        logger = logging.getLogger(__name__)
    urlset = ET.Element("urlset", xmlns="http://www.sitemaps.org/schemas/sitemap/0.9")

    for url in sorted(urls):
        url_element = ET.SubElement(urlset, "url")
        loc = ET.SubElement(url_element, "loc")
        loc.text = url
        lastmod = ET.SubElement(url_element, "lastmod")
        lastmod.text = datetime.now().strftime("%Y-%m-%d")
        changefreq = ET.SubElement(url_element, "changefreq")
        changefreq.text = "weekly"
        priority = ET.SubElement(url_element, "priority")
        priority.text = "0.8"

    tree = ET.ElementTree(urlset)
    ET.indent(tree, space="  ", level=0)
    tree.write(output_file, encoding="utf-8", xml_declaration=True)
    logger.info(f"Sitemap generated: {output_file}")

def run_sitemap_generation(tld, api_token, respect_robots=True, timeout=5, logger=None, progress=None):
    """Run the sitemap generation process."""
    if logger is None:
        logger = logging.getLogger(__name__)

    if not tld:
        logger.error("No domain provided. Exiting.")
        return

    if not api_token:
        logger.error("No API token provided. Exiting.")
        return

    logger.info(f"Using timeout: {timeout} seconds")

    # Create session for subdomain discovery
    session = create_session()

    # Discover subdomains
    logger.info(f"Discovering subdomains for {tld}")
    start_urls = discover_subdomains(tld, api_token, session, respect_robots, timeout, logger, progress)
    if not start_urls:
        logger.error(f"No accessible subdomains found for {tld}. Exiting.")
        return

    root_domain = tld
    logger.info(f"Starting sitemap generation for {tld} including all subdomains")
    urls = crawl_website(start_urls, root_domain, respect_robots, timeout, logger, progress)
    if not urls:
        logger.warning("No URLs were crawled. Sitemap may be empty.")
    generate_sitemap(urls, logger=logger)
    logger.info(f"Found {len(urls)} unique pages across main domain and subdomains.")

def main_cli():
    """Run the sitemap generator in CLI mode."""
    # Set up logging for CLI mode
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    logger = logging.getLogger(__name__)

    tld = input("Enter the top-level domain (e.g., techfixpro.net): ").strip()
    api_token = getpass.getpass(
        "Enter your Cloudflare API token (Get one from Cloudflare dashboard > Profile > API Tokens > Create Token > Edit zone DNS template > All Zones > Create Token): "
    ).strip()
    respect_robots_input = input("Respect robots.txt? (y/n, default: y): ").strip().lower()
    respect_robots = respect_robots_input != 'n'

    timeout_input = input("Enter timeout in seconds (default: 5): ").strip()
    try:
        timeout = float(timeout_input) if timeout_input else 5
        if timeout <= 0:
            raise ValueError("Timeout must be positive")
    except ValueError as e:
        logger.warning(f"Invalid timeout input: {e}. Using default timeout of 5 seconds.")
        timeout = 5

    run_sitemap_generation(tld, api_token, respect_robots, timeout, logger)

def main():
    """Main entry point with CLI/WebUI mode selection."""
    parser = argparse.ArgumentParser(description="Sitemap Generator for Cloudflare-hosted domains")
    parser.add_argument("--webui", action="store_true", help="Run in WebUI mode")
    args = parser.parse_args()

    if args.webui:
        try:
            from app import run_webui
            # Prompt for port customization
            customize_port = input("Customize port? (y/n, default: n): ").strip().lower()
            port = 5000  # Default port
            if customize_port == 'y':
                while True:
                    port_input = input("What port? Enter number: ").strip()
                    try:
                        port = int(port_input)
                        if not (1 <= port <= 65535):
                            raise ValueError("Port must be between 1 and 65535")
                        break
                    except ValueError as e:
                        print(f"Invalid port: {e}. Please enter a valid number.")
            run_webui(port=port)
        except ImportError:
            print("WebUI module not found. Please ensure app.py is available.")
            return
    else:
        main_cli()

if __name__ == "__main__":
    main()
