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
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Manager, Queue
import queue
import os
import sys
from logging.handlers import QueueHandler

# Add current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

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

def is_valid_url(url, session, respect_robots=True, timeout=3, logger=None):
    """Check if the URL is valid and accessible."""
    if logger is None:
        logger = logging.getLogger(__name__)
    headers = {"User-Agent": get_user_agent()}
    try:
        response = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        content_type = response.headers.get('content-type', '').lower()
        if response.status_code == 429:
            logger.warning(f"Rate limit hit for {url}")
            return False
        logger.debug(f"URL {url} status {response.status_code}, content-type: {content_type}")
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
    resolver.timeout = 3
    resolver.lifetime = 3
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
            logger.debug(f"URL {url} disallowed by robots.txt")
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
    if not api_token:
        logger.info("No Cloudflare API token provided, skipping Cloudflare DNS lookup")
        return []

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    zone_id = None
    dns_records = []

    try:
        response = requests.get(
            f"https://api.cloudflare.com/client/v4/zones?name={tld}",
            headers=headers,
            timeout=3
        )
        result = response.json()
        if result["success"] and result["result"]:
            zone_id = result["result"][0]["id"]
            logger.info(f"Found Cloudflare zone ID for {tld}: {zone_id}")
        else:
            logger.warning(f"Failed to find zone ID for {tld}: {result}")
            return []
    except Exception as e:
        logger.error(f"Error fetching zone ID for {tld}: {e}")
        return []

    try:
        response = requests.get(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            headers=headers,
            timeout=3
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

def check_subdomain(args):
    """Helper function to check a single subdomain (for multithreading)."""
    subdomain, domain, respect_robots, timeout, progress, progress_lock, include_subdomains, exclude_subdomains, rate_limit_value, rate_limit_lock, logger = args
    session = create_session()

    try:
        if subdomain:
            full_domain = f"{subdomain}.{domain}"
        else:
            full_domain = domain
        if exclude_subdomains and full_domain in exclude_subdomains:
            logger.debug(f"Skipping excluded subdomain: {full_domain}")
            return None
        if include_subdomains and full_domain not in include_subdomains:
            logger.debug(f"Skipping non-included subdomain: {full_domain}")
            return None
        logger.debug(f"Checking subdomain: {full_domain}")
        if resolve_domain(full_domain, logger):
            url = f"https://{full_domain}"
            with rate_limit_lock:
                current_rate = rate_limit_value['value']
            time.sleep(random.uniform(current_rate, current_rate * 1.5))
            if is_valid_url(url, session, respect_robots, timeout, logger):
                logger.info(f"Found subdomain: {url}")
                if progress is not None:
                    with progress_lock:
                        progress['subdomains_found'] += 1
                with rate_limit_lock:
                    if rate_limit_value['value'] > 0.1:
                        rate_limit_value['value'] = max(0.1, rate_limit_value['value'] * 0.95)
                return url
            elif not is_valid_url(url, session, respect_robots, timeout, logger):
                with rate_limit_lock:
                    rate_limit_value['value'] = min(2.0, rate_limit_value['value'] * 1.2)
        return None
    except Exception as e:
        logger.error(f"Error checking subdomain {subdomain}.{domain}: {e}", exc_info=True)
        return None

def discover_subdomains(tld, api_token, session, respect_robots=True, timeout=3, log_queue=None, progress=None, progress_lock=None, include_subdomains=None, exclude_subdomains=None, max_workers=16, rate_limit=0.5):
    """Discover subdomains via Cloudflare DNS, wordlist, and crt.sh with multithreading."""
    logger = logging.getLogger(__name__)
    if log_queue is not None:
        logger.handlers = []
        queue_handler = QueueHandler(log_queue)
        queue_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(queue_handler)
        logger.setLevel(logging.INFO)
    
    logger.info(f"Starting subdomain discovery for {tld} with {max_workers} workers")
    subdomains = set()
    include_subdomains = set(include_subdomains or [])
    exclude_subdomains = set(exclude_subdomains or [])
    rate_limit_value = Manager().dict({'value': rate_limit})
    rate_limit_lock = Manager().Lock()

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
        with progress_lock:
            progress['total_subdomains'] = len(common_subdomains) + 50

    try:
        # 1. Cloudflare DNS records
        logger.info("Fetching DNS records from Cloudflare")
        dns_records = get_cloudflare_dns_records(tld, api_token, logger)
        for record in dns_records:
            name = record["name"]
            if name.endswith(tld) and not name.startswith(('_', '*')):
                subdomain = f"https://{name}"
                if exclude_subdomains and name in exclude_subdomains:
                    continue
                if include_subdomains and name not in include_subdomains:
                    continue
                if resolve_domain(name, logger):
                    with rate_limit_lock:
                        current_rate = rate_limit_value['value']
                    time.sleep(random.uniform(current_rate, current_rate * 1.5))
                    if is_valid_url(subdomain, session, respect_robots, timeout, logger):
                        subdomains.add(subdomain)
                        logger.info(f"Found subdomain from Cloudflare DNS: {subdomain}")
                        if progress is not None:
                            with progress_lock:
                                progress['subdomains_found'] += 1
                        with rate_limit_lock:
                            if rate_limit_value['value'] > 0.1:
                                rate_limit_value['value'] = max(0.1, rate_limit_value['value'] * 0.95)
                    # Update progress periodically
                    if progress is not None:
                        with progress_lock:
                            progress['status'] = f'Checking Cloudflare DNS: {name}'
    except Exception as e:
        logger.error(f"Error in Cloudflare DNS discovery: {e}", exc_info=True)

    try:
        # 2. Brute-force with wordlist (threaded)
        if max_workers > 1:
            logger.info(f"Brute-forcing subdomains with wordlist using {max_workers} threads")
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                args = [
                    (subdomain, tld, respect_robots, timeout, progress, progress_lock, include_subdomains, exclude_subdomains, rate_limit_value, rate_limit_lock, logger)
                    for subdomain in common_subdomains
                ]
                results = executor.map(check_subdomain, args)
                for i, result in enumerate(results):
                    if result:
                        subdomains.add(result)
                    # Update progress periodically
                    if progress is not None and (i % 10 == 0 or i == len(common_subdomains) - 1):
                        with progress_lock:
                            progress['status'] = f'Checking wordlist subdomain {i+1}/{len(common_subdomains)}'
        else:
            logger.info("Brute-forcing subdomains with wordlist (single thread)")
            for i, subdomain in enumerate(common_subdomains):
                result = check_subdomain((subdomain, tld, respect_robots, timeout, progress, progress_lock, include_subdomains, exclude_subdomains, rate_limit_value, rate_limit_lock, logger))
                if result:
                    subdomains.add(result)
                # Update progress periodically
                if progress is not None and (i % 10 == 0 or i == len(common_subdomains) - 1):
                    with progress_lock:
                        progress['status'] = f'Checking wordlist subdomain {i+1}/{len(common_subdomains)}'
    except Exception as e:
        logger.error(f"Error in wordlist brute-forcing: {e}", exc_info=True)

    try:
        # 3. Certificate transparency logs via crt.sh
        logger.info("Fetching subdomains from crt.sh")
        response = requests.get(f"https://crt.sh/?q=%.{tld}&output=json", timeout=timeout)
        if response.status_code == 200:
            certs = json.loads(response.text)
            if max_workers > 1:
                logger.info(f"Checking crt.sh subdomains using {max_workers} threads")
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    args = [
                        (name.split('.')[0], tld, respect_robots, timeout, progress, progress_lock, include_subdomains, exclude_subdomains, rate_limit_value, rate_limit_lock, logger)
                        for cert in certs
                        for name in [cert["name_value"].strip()]
                        if '\n' not in name and '%' not in name and not name.startswith("*") and name.endswith(tld)
                    ]
                    results = executor.map(check_subdomain, args)
                    for i, result in enumerate(results):
                        if result:
                            subdomains.add(result)
                        # Update progress periodically
                        if progress is not None and (i % 10 == 0 or i == len(args) - 1):
                            with progress_lock:
                                progress['status'] = f'Checking crt.sh subdomain {i+1}/{len(args)}'
            else:
                logger.info("Checking crt.sh subdomains (single thread)")
                for i, cert in enumerate(certs):
                    name = cert["name_value"].strip()
                    if '\n' in name or '%' in name or name.startswith("*") or not name.endswith(tld):
                        continue
                    result = check_subdomain((name.split('.')[0], tld, respect_robots, timeout, progress, progress_lock, include_subdomains, exclude_subdomains, rate_limit_value, rate_limit_lock, logger))
                    if result:
                        subdomains.add(result)
                    # Update progress periodically
                    if progress is not None and (i % 10 == 0 or i == len(certs) - 1):
                        with progress_lock:
                            progress['status'] = f'Checking crt.sh subdomain {i+1}/{len(certs)}'
    except Exception as e:
        logger.error(f"Error fetching from crt.sh: {e}", exc_info=True)

    logger.info(f"Discovered {len(subdomains)} subdomains for {tld}")
    return subdomains

def crawl_url(args):
    """Crawl a single URL and return found links, respecting max depth (for multithreading)."""
    url, visited, collected_urls, collected_urls_lock, root_domain, respect_robots, timeout, progress, progress_lock, max_depth, current_depth, rate_limit_value, rate_limit_lock, log_queue = args
    logger = logging.getLogger(__name__)
    if log_queue is not None:
        logger.handlers = []
        queue_handler = QueueHandler(log_queue)
        queue_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(queue_handler)
        logger.setLevel(logging.INFO)
    
    session = create_session()

    try:
        if url in visited or current_depth > max_depth:
            logger.debug(f"Skipping URL {url}: already visited or depth {current_depth} > {max_depth}")
            return []

        visited.append(url)
        logger.info(f"Crawling (depth {current_depth}): {url}")
        headers = {"User-Agent": get_user_agent()}
        with rate_limit_lock:
            current_rate = rate_limit_value['value']
        time.sleep(random.uniform(current_rate, current_rate * 1.5))
        response = session.get(url, headers=headers, timeout=timeout)
        content_type = response.headers.get('content-type', '').lower()
        if response.status_code == 429:
            with rate_limit_lock:
                rate_limit_value['value'] = min(2.0, rate_limit_value['value'] * 1.2)
            logger.warning(f"Rate limit hit for {url}")
            return []
        if response.status_code not in [200, 301, 302, 403, 404]:
            logger.debug(f"Skipping {url}: status {response.status_code}, content-type {content_type}")
            return []
        with rate_limit_lock:
            if rate_limit_value['value'] > 0.1:
                rate_limit_value['value'] = max(0.1, rate_limit_value['value'] * 0.95)
    except requests.RequestException as e:
        logger.error(f"Failed to crawl {url}: {e}")
        return []

    with collected_urls_lock:
        collected_urls['urls'].append(clean_url(url))
    if progress is not None:
        with progress_lock:
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
                found_urls.append((cleaned_url, current_depth + 1))

    return found_urls

def crawl_website(start_urls, root_domain, respect_robots=True, timeout=3, log_queue=None, progress=None, progress_lock=None, use_multithreading=False, max_workers=16, max_depth=5, rate_limit=0.5):
    """Crawl the website and subdomains, using multithreading if specified."""
    logger = logging.getLogger(__name__)
    if log_queue is not None:
        logger.handlers = []
        queue_handler = QueueHandler(log_queue)
        queue_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(queue_handler)
        logger.setLevel(logging.INFO)
    
    logger.info(f"Starting crawl for {root_domain} with {len(start_urls)} start URLs")
    rate_limit_value = Manager().dict({'value': rate_limit})
    rate_limit_lock = Manager().Lock()
    visited = Manager().list()
    collected_urls = {'urls': Manager().list(), 'lock': Manager().Lock()}

    try:
        if not use_multithreading:
            logger.info("Crawling website (single thread)")
            session = create_session()
            for start_url in start_urls:
                url_queue = [(start_url, 0)]
                while url_queue:
                    url, depth = url_queue.pop(0)
                    args = (url, visited, collected_urls, collected_urls['lock'], root_domain, respect_robots, timeout, progress, progress_lock, max_depth, depth, rate_limit_value, rate_limit_lock, log_queue)
                    new_urls = crawl_url(args)
                    url_queue.extend((u, d) for u, d in new_urls if u not in visited)
        else:
            logger.info(f"Crawling website using {max_workers} threads")
            url_queue = queue.Queue()
            for start_url in start_urls:
                url_queue.put((start_url, 0))

            def worker():
                logger = logging.getLogger(__name__)
                if log_queue is not None:
                    logger.handlers = []
                    queue_handler = QueueHandler(log_queue)
                    queue_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
                    logger.addHandler(queue_handler)
                    logger.setLevel(logging.INFO)
                while True:
                    try:
                        url, depth = url_queue.get_nowait()
                    except queue.Empty:
                        break
                    args = (url, visited, collected_urls, collected_urls['lock'], root_domain, respect_robots, timeout, progress, progress_lock, max_depth, depth, rate_limit_value, rate_limit_lock, log_queue)
                    new_urls = crawl_url(args)
                    for new_url, new_depth in new_urls:
                        if new_url not in visited:
                            url_queue.put((new_url, new_depth))
                    url_queue.task_done()

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(worker) for _ in range(max_workers)]
                for future in futures:
                    future.result()

        logger.info(f"Crawled {len(collected_urls['urls'])} URLs")
        return set(collected_urls['urls'])
    except Exception as e:
        logger.error(f"Error in crawl_website: {e}", exc_info=True)
        return set()

def generate_sitemap(urls, output_file="sitemap.xml", log_queue=None):
    """Generate sitemap.xml from a set of URLs."""
    logger = logging.getLogger(__name__)
    if log_queue is not None:
        logger.handlers = []
        queue_handler = QueueHandler(log_queue)
        queue_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(queue_handler)
        logger.setLevel(logging.INFO)
    
    try:
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
    except Exception as e:
        logger.error(f"Error generating sitemap: {e}", exc_info=True)

def run_sitemap_generation(tld, api_token, respect_robots=True, timeout=3, log_queue=None, progress=None, progress_lock=None, use_multithreading=False, max_workers=16, max_depth=5, output_file="sitemap.xml", include_subdomains=None, exclude_subdomains=None, rate_limit=0.5):
    """Run the sitemap generation process."""
    logger = logging.getLogger(__name__)
    if log_queue is not None:
        logger.handlers = []
        queue_handler = QueueHandler(log_queue)
        queue_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(queue_handler)
        logger.setLevel(logging.INFO)

    try:
        if not tld:
            logger.error("No domain provided. Exiting.")
            if progress and progress_lock:
                with progress_lock:
                    progress['status'] = 'error'
                    progress['error_message'] = 'No domain provided'
                    progress['is_generating'] = False
            return

        logger.info(f"Starting sitemap generation for {tld} with timeout: {timeout}s, multithreading: {use_multithreading}, max_workers: {max_workers}, max_depth: {max_depth}, output: {output_file}")

        # Discover subdomains
        logger.info(f"Discovering subdomains for {tld}")
        session = create_session()
        start_urls = discover_subdomains(tld, api_token, session, respect_robots, timeout, log_queue, progress, progress_lock, include_subdomains, exclude_subdomains, max_workers, rate_limit)
        if not start_urls:
            logger.error(f"No accessible subdomains found for {tld}. Exiting.")
            if progress and progress_lock:
                with progress_lock:
                    progress['status'] = 'error'
                    progress['error_message'] = 'No accessible subdomains found'
                    progress['is_generating'] = False
            return

        root_domain = tld
        logger.info(f"Crawling {tld} including all subdomains")
        urls = crawl_website(start_urls, root_domain, respect_robots, timeout, log_queue, progress, progress_lock, use_multithreading, max_workers, max_depth, rate_limit)
        if not urls:
            logger.warning("No URLs were crawled. Sitemap may be empty.")
            if progress and progress_lock:
                with progress_lock:
                    progress['status'] = 'error'
                    progress['error_message'] = 'No URLs were crawled'
                    progress['is_generating'] = False
        else:
            generate_sitemap(urls, output_file, log_queue)
            logger.info(f"Found {len(urls)} unique pages across main domain and subdomains.")
            if progress and progress_lock:
                with progress_lock:
                    progress['status'] = 'completed'
                    progress['is_generating'] = False
    except Exception as e:
        logger.error(f"Error in sitemap generation: {e}", exc_info=True)
        if progress and progress_lock:
            with progress_lock:
                progress['status'] = 'error'
                progress['error_message'] = f'Sitemap generation failed: {str(e)}'
                progress['is_generating'] = False

def main_cli(args):
    """Run the sitemap generator in CLI mode."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    logger = logging.getLogger(__name__)
    file_handler = logging.FileHandler('sitemap.log')
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)

    tld = args.tld or input("Enter the top-level domain (e.g., techfixpro.net): ").strip()
    api_token = args.api_token or getpass.getpass(
        "Enter your Cloudflare API token (leave blank to skip): "
    ).strip()
    respect_robots = args.respect_robots
    timeout = args.timeout
    use_multithreading = args.multi
    max_workers = args.cores
    if max_workers == 'auto':
        max_workers = (os.cpu_count() or 4) * 4  # Increase for I/O-bound tasks
    else:
        max_workers = int(max_workers)
    max_depth = args.max_depth
    output_file = args.output
    include_subdomains = args.include_subdomains.split(',') if args.include_subdomains else None
    exclude_subdomains = args.exclude_subdomains.split(',') if args.exclude_subdomains else None
    rate_limit = args.rate_limit

    manager = Manager()
    progress = manager.dict({
        'subdomains_found': 0,
        'urls_crawled': 0,
        'total_subdomains': 0,
        'start_time': time.time(),
        'status': 'running',
        'error_message': '',
        'is_generating': True
    })
    progress_lock = manager.Lock()

    run_sitemap_generation(
        tld, api_token, respect_robots, timeout, None, progress, progress_lock,
        use_multithreading, max_workers, max_depth, output_file,
        include_subdomains, exclude_subdomains, rate_limit
    )

def main():
    """Main entry point with CLI/WebUI mode selection."""
    parser = argparse.ArgumentParser(description="Sitemap Generator for Cloudflare-hosted domains")
    parser.add_argument("--webui", action="store_true", help="Run in WebUI mode")
    parser.add_argument("--tld", type=str, help="Top-level domain (e.g., techfixpro.net)")
    parser.add_argument("--api-token", type=str, help="Cloudflare API token")
    parser.add_argument("--no-robots", action="store_false", dest="respect_robots", help="Ignore robots.txt")
    parser.add_argument("--timeout", type=float, default=5, help="Timeout in seconds")
    parser.add_argument("--multi", action="store_true", help="Enable multithreading")
    parser.add_argument("-c", "--cores", default=4, help="Number of threads for multithreading (or 'auto')")
    parser.add_argument("--max-depth", type=int, default=5, help="Maximum crawl depth")
    parser.add_argument("--output", type=str, default="sitemap.xml", help="Output sitemap file name")
    parser.add_argument("--include-subdomains", type=str, help="Comma-separated list of subdomains to include")
    parser.add_argument("--exclude-subdomains", type=str, help="Comma-separated list of subdomains to exclude")
    parser.add_argument("--rate-limit", type=float, default=0.5, help="Initial delay between requests in seconds")
    args = parser.parse_args()

    if args.webui:
        try:
            # Verify app.py exists
            if not os.path.exists(os.path.join(os.path.dirname(__file__), 'app.py')):
                print("WebUI module not found. Please ensure app.py is available.")
                return
            from app import run_webui
            customize_port = input("Customize port? (y/n, default: n): ").strip().lower()
            port = 5000
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
        except ImportError as e:
            print(f"Failed to import WebUI module: {e}. Please ensure app.py is available and dependencies are installed.")
            return
        except Exception as e:
            print(f"Error starting WebUI: {e}")
            return
    else:
        main_cli(args)

if __name__ == "__main__":
    main()
