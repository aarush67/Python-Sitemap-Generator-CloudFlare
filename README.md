# Sitemap Generator for Cloudflare Domains

This Python application generates a `sitemap.xml` for a specified domain by discovering and crawling its subdomains. It supports both a command-line interface (CLI) and a web-based user interface (WebUI) built with Flask and SocketIO. The tool leverages Cloudflare DNS records, a predefined wordlist, and certificate transparency logs (via crt.sh) for subdomain discovery, then crawls accessible URLs to create a standard sitemap. It’s optimized for Cloudflare-protected domains, using User-Agent rotation and adaptive rate-limiting to bypass Bot Fight Mode and rate limits.

## Features
- **Subdomain Discovery**:
  - Queries Cloudflare API for DNS records.
  - Uses a comprehensive wordlist (e.g., `www`, `blog`, `api`, `staging`).
  - Fetches subdomains from certificate transparency logs via crt.sh.
- **Robust Crawling**:
  - Crawls subdomains to collect URLs, supporting HTTP status codes 200, 301, 302, 403, and 404.
  - Respects or ignores `robots.txt` based on user configuration.
  - Cleans URLs by removing fragments and query strings.
- **Multithreading**:
  - Uses `ThreadPoolExecutor` for I/O-bound tasks (DNS lookups, HTTP requests).
  - Configurable thread count (default: 16, or auto-scaled to CPU count * 4 in CLI).
- **Cloudflare Compatibility**:
  - Rotates User-Agents to mimic browsers.
  - Implements adaptive rate-limiting (0.1s to 2.0s) to avoid 429 errors.
  - Supports Cloudflare API token for DNS record access.
- **WebUI**:
  - Flask-based interface for starting crawls, viewing real-time logs, and downloading sitemaps.
  - Displays progress (subdomains found, URLs crawled, estimated time).
  - Configurable via form inputs (domain, API token, threading options, etc.).
- **Sitemap Generation**:
  - Outputs a standard `sitemap.xml` compliant with the [Sitemap Protocol](http://www.sitemaps.org/schemas/sitemap/0.9).
  - Includes URL locations, last modified dates, change frequency, and priority.
- **Logging**:
  - Writes logs to `sitemap.log` and displays them in the terminal (CLI) or WebUI.
  - Supports debug, info, warning, and error levels.
- **Customization**:
  - Configurable timeout, max crawl depth, rate limit, and thread count.
  - Optional inclusion/exclusion of specific subdomains.
  - Adjustable output file name for the sitemap.

## Prerequisites
- **Python 3.12+**: Verify with `python3 --version`.
- **Cloudflare Account**: Required for API token access to DNS records.
- **Cloudflare API Token**: Must have "Edit Zone DNS" permissions for the target domain.
- **Internet Connection**: Needed for DNS resolution, HTTP requests, Cloudflare API, and crt.sh queries.
- **Web Browser**: For WebUI mode (e.g., Chrome, Firefox).
- **System Resources**: At least 8GB RAM and 2 CPU cores for efficient multithreading.

## Installation

1. **Clone or Download the Repository**
   - Clone the repository (if hosted):
     ```bash
     git clone https://github.com/aarush67/Python-Sitemap-Generator-CloudFlare.git
     cd Python-Sitemap-Generator-CloudFlare
     ```
   - Or download `main.py`, `app.py`, `templates/index.html`, `requirements.txt`, and `LICENSE`.

2. **Set Up a Virtual Environment (Recommended)**
   - Create and activate a virtual environment:
     ```bash
     python3 -m venv venv
     source venv/bin/activate  # On Windows: venv\Scripts\activate
     ```

3. **Install Dependencies**
   - Ensure `requirements.txt` contains:
     ```
     requests
     beautifulsoup4
     dnspython
     flask
     flask-socketio
     ```
   - Install dependencies:
     ```bash
     pip install -r requirements.txt
     ```

## Obtaining a Cloudflare API Token

1. **Log in to Cloudflare**
   - Visit [dash.cloudflare.com](https://dash.cloudflare.com/) and sign in.

2. **Navigate to API Tokens**
   - Click your profile icon (top-right) > **My Profile** > **API Tokens**.

3. **Create a Token**
   - Click **Create Token** > **Edit zone DNS** template > **Use template**.
   - Configure:
     - **Permissions**: "Zone: DNS: Edit".
     - **Zone Resources**: Select **All Zones** or **Specific Zone** (e.g., `sribalakashi.com`).
   - Click **Continue to summary** > **Create Token**.

4. **Copy the Token**
   - Copy the token (e.g., `abc123...xyz789`) and store it securely.
   - Regenerate if lost, as it’s not viewable again.

5. **Verify Permissions**
   - Ensure "Edit Zone DNS" is enabled. Regenerate if API errors occur.

## Usage

### CLI Mode
1. **Run the Script**
   - Ensure the virtual environment is activated and you’re in the project directory.
   - Run:
     ```bash
     python3 main.py --tld <domain> [options]
     ```

2. **Command-Line Options**
   - `--webui`: Run in WebUI mode (see WebUI section).
   - `--tld <domain>`: Top-level domain (e.g., `sribalakashi.com`).
   - `--api-token <token>`: Cloudflare API token (optional, prompts if omitted).
   - `--no-robots`: Ignore `robots.txt` restrictions (default: respect).
   - `--timeout <seconds>`: HTTP request timeout (default: 5).
   - `--multi`: Enable multithreading for discovery and crawling.
   - `-c, --cores <n|auto>`: Number of threads (default: 4, or CPU count * 4 for `auto`).
   - `--max-depth <n>`: Maximum crawl depth (default: 5).
   - `--output <file>`: Output sitemap file (default: `sitemap.xml`).
   - `--include-subdomains <list>`: Comma-separated subdomains to include (e.g., `www,blog`).
   - `--exclude-subdomains <list>`: Comma-separated subdomains to exclude (e.g., `staging,dev`).
   - `--rate-limit <seconds>`: Initial delay between requests (default: 0.5).

3. **Interactive Prompts (if no arguments provided)**
   - Example:
     ```bash
     python3 main.py
     Enter the top-level domain (e.g., techfixpro.net): sribalakashi.com
     Enter your Cloudflare API token (leave blank to skip): <paste-token>
     ```
   - Additional prompts for `robots.txt`, timeout, etc., if not specified via flags.

4. **Example Command**
   ```bash
   python3 main.py --tld sribalakashi.com --api-token abc123...xyz789 --multi --cores auto --rate-limit 0.3 --no-robots --max-depth 3 --output mysitemap.xml
   ```

5. **Output**
   - Logs are printed to the terminal and saved to `sitemap.log`.
   - Example logs:
     ```
     2025-05-06 12:00:00,000 - INFO - Starting sitemap generation for sribalakashi.com with timeout: 5s, multithreading: True, max_workers: 32, max_depth: 3, output: mysitemap.xml
     2025-05-06 12:00:00,001 - INFO - Found subdomain: https://www.sribalakashi.com
     2025-05-06 12:00:05,000 - INFO - Crawled 50 URLs
     2025-05-06 12:00:10,000 - INFO - Sitemap generated: mysitemap.xml
     ```
   - The `sitemap.xml` file is created in the current directory.

### WebUI Mode
1. **Run the WebUI**
   - Start the application in WebUI mode:
     ```bash
     python3 main.py --webui --multi --cores auto
     ```
   - When prompted, choose a port (default: 5000, recommended: 5003).
   - Example:
     ```
     Customize port? (y/n, default: n): y
     What port? Enter number: 5003
     ```

2. **Access the WebUI**
   - Open `http://localhost:5003` in a browser.
   - Fill in the form:
     - **Top-Level Domain**: e.g., `sribalakashi.com`.
     - **Cloudflare API Token**: Paste your token (optional).
     - **Respect Robots.txt**: Check to enable (default: enabled).
     - **Timeout**: e.g., `5` seconds.
     - **Use Multithreading**: Check to enable, set "Number of Cores" (e.g., `auto` or `16`).
     - **Max Depth**: e.g., `5`.
     - **Output File**: e.g., `sitemap.xml`.
     - **Include Subdomains**: Comma-separated (e.g., `www,blog`).
     - **Exclude Subdomains**: Comma-separated (e.g., `staging,dev`).
     - **Rate Limit**: e.g., `0.5` seconds.
   - Click **Generate Sitemap**.

3. **Monitor Progress**
   - Logs appear in the "Logs" section (e.g., "Found subdomain: https://www.sribalakashi.com").
   - Status updates show progress (e.g., "Checking wordlist subdomain 10/60").
   - Download the sitemap via the **Download Sitemap** button after completion.

4. **Example WebUI Workflow**
   - Input: Domain=`sribalakashi.com`, Multithreading=`auto`, Rate Limit=`0.3`.
   - Output: Logs in WebUI, `sitemap.xml` downloadable.

## Example Sitemap
```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://sribalakashi.com</loc>
    <lastmod>2025-05-06</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://www.sribalakashi.com</loc>
    <lastmod>2025-05-06</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <!-- Additional URLs -->
</urlset>
```

## Verifying the Sitemap
- Open `sitemap.xml` to confirm URLs (e.g., `https://sribalakashi.com`, `https://www.sribalakashi.com`).
- Submit to search engines like Google Search Console for indexing.

## Troubleshooting

- **Empty Sitemap**
  - **Cause**: No accessible subdomains or crawling failed.
  - **Solution**:
    - Check `sitemap.log` for errors (e.g., "Failed to validate URL").
    - Increase `--timeout` (e.g., `10`) or lower `--rate-limit` (e.g., `0.2`).
    - Disable Cloudflare Bot Fight Mode or add a firewall rule:
      - Cloudflare > Security > WAF > Create Rule: `If IP Source Address is <your-IP>, then Allow`.
    - Verify subdomains in a browser (e.g., `https://www.sribalakashi.com`).

- **Low CPU Usage**
  - **Cause**: Network latency dominates (I/O-bound tasks).
  - **Solution**:
    - Lower `--rate-limit` (e.g., `0.2`) to increase request frequency.
    - Increase `--cores` (e.g., `32`) in WebUI or CLI.
    - Monitor `htop` and `sitemap.log` to identify bottlenecks (e.g., slow crt.sh queries).
    - Test with a faster-responding domain (e.g., `example.com`).

- **WebUI Logs Not Appearing**
  - **Cause**: SocketIO or log queue issues.
  - **Solution**:
    - Check browser console (F12) for errors.
    - Verify `flask-socketio` and `python-socketio` versions:
      ```bash
      pip show flask-socketio python-socketio
      ```
    - Restart WebUI with:
      ```bash
      python3 main.py --webui --multi --cores auto
      ```
    - Check `sitemap.log` for "Emitting log" messages.

- **API Token Errors**
  - **Cause**: Invalid token or insufficient permissions.
  - **Solution**:
    - Regenerate token with "Edit Zone DNS" and "All Zones".
    - Verify domain is Cloudflare-managed.

- **Timeout Errors**
  - **Cause**: Slow or unreachable subdomains.
  - **Solution**:
    - Increase `--timeout` (e.g., `10` or `15`).
    - Check DNS resolution (`nslookup www.sribalakashi.com`).

- **429/530 Errors (Cloudflare)**
  - **Cause**: Rate-limiting or Bot Fight Mode.
  - **Solution**:
    - Lower `--rate-limit` (e.g., `0.2`).
    - Disable Bot Fight Mode: Cloudflare > Security > Bots.
    - Add firewall rule to allow your IP or User-Agent.

- **Connection Refused**
  - **Cause**: Misconfigured or offline subdomains.
  - **Solution**:
    - Verify DNS settings in Cloudflare.
    - Exclude problematic subdomains with `--exclude-subdomains`.

## Notes
- **Performance**: Crawling may take minutes for large domains due to network latency. Multithreading improves throughput but is limited by server responses.
- **Rate-Limiting**: Adaptive delays (0.1s–2.0s) adjust based on 429 errors. Use `--rate-limit 0.2` for faster crawling if servers allow.
- **WebUI Port**: Default is 5000; use 5003 or others if needed. Avoid conflicts with other services.
- **Dependencies**: Update packages if issues occur:
  ```bash
  pip install --upgrade requests beautifulsoup4 dnspython flask flask-socketio
  ```
- **Logging**: CLI logs to terminal and `sitemap.log`; WebUI logs to browser and `sitemap.log`.

## Contributing
- Report bugs or suggest features via GitHub issues (if hosted).
- Submit pull requests with improvements.
- Share `sitemap.log`, terminal output, or WebUI console errors for debugging.

## License
Licensed under the MIT License. See `LICENSE` file for details.

## Acknowledgments
- Libraries: `requests`, `beautifulsoup4`, `dnspython`, `flask`, `flask-socketio`.
- Services: Cloudflare API, crt.sh.
- Optimized for Cloudflare-protected domains with real-world constraints.
