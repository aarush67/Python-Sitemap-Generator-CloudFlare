# Sitemap Generator for Cloudflare Domains

This Python script generates a sitemap (`sitemap.xml`) for a specified domain by discovering and crawling its subdomains. It uses Cloudflare DNS records, a predefined wordlist, and certificate transparency logs (via crt.sh) to identify subdomains, then crawls them to collect accessible URLs. The script supports both a command-line interface (CLI) and a web user interface (WebUI) built with Flask and React, designed to handle Cloudflare-protected domains with User-Agent rotation and delays to bypass rate-limiting and Bot Fight Mode.

## Features
- **Subdomain Discovery**: Finds subdomains using:
  - Cloudflare API (DNS records)
  - Common subdomain wordlist (e.g., `www`, `blog`, `api`)
  - Certificate transparency logs (crt.sh)
- **Robust Crawling**: Crawls subdomains to collect URLs, handling HTTP status codes 200, 301, 302, 403, and 404.
- **Cloudflare Compatibility**: Uses User-Agent rotation and delays to avoid rate-limiting and Bot Fight Mode.
- **Customizable Timeout**: Allows adjusting HTTP request timeout (default: 5 seconds).
- **Robots.txt Support**: Optionally respects `robots.txt` restrictions.
- **Sitemap Generation**: Outputs a standard `sitemap.xml` with URLs, last modified dates, change frequency, and priority.
- **WebUI Features**:
  - Real-time logs displayed in the browser.
  - Loading animation during generation.
  - Estimated time remaining for completion.
  - Modal popup to indicate processing.
  - Download button to retrieve `sitemap.xml` after generation.

## Prerequisites
- **Python 3.6+**: Ensure Python is installed (`python3 --version`).
- **Cloudflare Account**: You need a Cloudflare account with access to the target domain's DNS settings.
- **Cloudflare API Token**: A token with "Edit Zone DNS" permissions for the target domain.
- **Internet Connection**: Required for DNS resolution, HTTP requests, Cloudflare API calls, and crt.sh queries.
- **Web Browser**: For WebUI mode, use a modern browser (e.g., Chrome, Firefox) to access the interface.
- **Dependencies**: Installed via `requirements.txt`, including `requests`, `beautifulsoup4`, `dnspython`, `lxml`, `flask`, and `flask-socketio`.

## Installation

1. **Clone or Download the Repository**
   - Download the project files (`main.py`, `app.py`, `templates/index.html`, `requirements.txt`) to a local directory.
   - Alternatively, clone the repository if hosted on GitHub:
     ```bash
     git clone https://github.com/aarush67/Python-Sitemap-Generator-CloudFlare.git
     cd Python-Sitemap-Generator-CloudFlare
     ```

2. **Set Up a Virtual Environment (Recommended)**
   - Create and activate a virtual environment to manage dependencies:
     ```bash
     python3 -m venv venv
     source venv/bin/activate  # On Windows: venv\Scripts\activate
     ```

3. **Install Dependencies**
   - Ensure `requirements.txt` is in the project directory. It includes:
     - `requests>=2.31.0`
     - `beautifulsoup4>=4.12.3`
     - `dnspython>=2.6.1`
     - `lxml>=5.3.0`
     - `flask>=3.0.3`
     - `flask-socketio>=5.3.6`
   - Install the dependencies:
     ```bash
     pip install -r requirements.txt
     ```

## Obtaining a Cloudflare API Token

To use the script, you need a Cloudflare API token with "Edit Zone DNS" permissions for your domain (e.g., `techfixpro.net`). Follow these steps:

1. **Log in to Cloudflare**
   - Go to [cloudflare.com](https://dash.cloudflare.com/) and log in to your account.

2. **Navigate to API Tokens**
   - Click your profile icon (top-right corner) and select **My Profile**.
   - In the left sidebar, click **API Tokens**.

3. **Create a Token**
   - Click **Create Token**.
   - Under **Templates**, select **Edit zone DNS** and click **Use template**.
   - Configure the token:
     - **Permissions**: Ensure "Zone: DNS: Edit" is selected.
     - **Zone Resources**: Choose **All Zones** (or **Specific Zone** and select your domain, e.g., `techfixpro.net`).
   - Click **Continue to summary**.

4. **Copy the Token**
   - Click **Create Token**.
   - Copy the generated token (e.g., `abc123...xyz789`) and store it securely. You won’t be able to view it again.
   - If you lose the token, you’ll need to create a new one.

5. **Verify Permissions**
   - Ensure the token has "Edit Zone DNS" permissions. If the script fails with an API error, regenerate the token and verify settings.

## Usage

The script supports two modes: **CLI** (command-line interface) and **WebUI** (web user interface). Follow the appropriate instructions below.

### CLI Mode

1. **Run the Script**
   - Ensure you’re in the directory containing `main.py` and your virtual environment is activated.
   - Run the script:
     ```bash
     python3 main.py
     ```

2. **Provide Inputs**
   The script will prompt you for the following:
   - **Top-level domain**: Enter your domain (e.g., `techfixpro.net`).
   - **Cloudflare API token**: Paste the token you generated (it’s hidden as you type for security).
   - **Respect robots.txt**: Enter `y` to respect `robots.txt` restrictions or `n` to ignore them (default: `y`).
   - **Timeout in seconds**: Enter the HTTP request timeout in seconds (e.g., `5` for 5 seconds; default: `5`). Use a higher value (e.g., `10`) for slow subdomains.

   Example interaction:
   ```
   Enter the top-level domain (e.g., techfixpro.net): techfixpro.net
   Enter your Cloudflare API token (Get one from Cloudflare dashboard > Profile > API Tokens > Create Token > Edit zone DNS template > All Zones > Create Token): <paste-token>
   Respect robots.txt? (y/n, default: y): y
   Enter timeout in seconds (default: 5): 5
   ```

3. **Output**
   - The script discovers subdomains, crawls them, and generates a `sitemap.xml` file in the current directory.
   - Logs are printed to the console, showing discovered subdomains (e.g., `https://articles.techfixpro.net`), crawling progress, and any errors.
   - The final log indicates the number of unique URLs found (e.g., `Found 17 unique pages across main domain and subdomains`).

### WebUI Mode

1. **Run the Script**
   - Ensure you’re in the directory containing `main.py`, `app.py`, and `templates/index.html`, with the virtual environment activated.
   - Start the WebUI:
     ```bash
     python3 main.py --webui
     ```

2. **Customize Port (Optional)**
   - When prompted, choose whether to customize the port:
     ```
     Customize port? (y/n, default: n):
     ```
   - Enter `n` to use the default port (5000) or `y` to specify a port (e.g., `5003`):
     ```
     What port? Enter number: 5003
     ```
   - If an invalid port is entered, you’ll be prompted again.

3. **Access the WebUI**
   - Open your browser and navigate to `http://localhost:<port>` (e.g., `http://localhost:5003`).
   - The WebUI displays a form with the following fields:
     - **Top-Level Domain**: Enter your domain (e.g., `techfixpro.net`).
     - **Cloudflare API Token**: Paste your API token.
     - **Respect robots.txt**: Check to respect `robots.txt` (default: checked).
     - **Timeout (seconds)**: Enter the HTTP request timeout (default: `5`).

4. **Generate Sitemap**
   - Click **Generate Sitemap**.
   - A modal appears: "Processing Your Request: This may take a while depending on how big the site is, hold tight!" Click **OK** to dismiss.
   - A loading animation and estimated time remaining (e.g., "Estimated time remaining: 45 seconds") appear.
   - Real-time logs display in the "Logs" section (e.g., `Found subdomain from Cloudflare DNS: https://articles.techfixpro.net`).
   - When complete, a green message appears: "Sitemap generation completed!"
   - A blue **Download Sitemap** button appears; click it to download `sitemap.xml`.

5. **Output**
   - The sitemap is saved as `sitemap.xml` in the current directory.
   - The WebUI shows the completion status, logs, and provides the download option.

6. **Stop the Server**
   - Press `Ctrl+C` in the terminal to stop the Flask server.

## Example Sitemap
The generated `sitemap.xml` follows the [Sitemap Protocol](http://www.sitemaps.org/schemas/sitemap/0.9) and looks like this:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://techfixpro.net</loc>
    <lastmod>2025-05-03</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://articles.techfixpro.net</loc>
    <lastmod>2025-05-03</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <!-- Additional URLs -->
</urlset>
```

## Troubleshooting

- **Empty Sitemap**
  - **Cause**: No accessible subdomains were found, or crawling failed due to timeouts or Cloudflare blocks.
  - **Solution**:
    - Check logs for errors like `Failed to validate URL` or `Skipping non-accessible subdomain`.
    - Increase the timeout (e.g., `10` seconds) for slow subdomains.
    - Disable Cloudflare’s Bot Fight Mode or add a firewall rule to allow your IP:
      - Go to Cloudflare dashboard > Security > WAF > Create Rule.
      - Set: `If IP Source Address is <your-IP>, then Allow`.
    - Manually verify subdomains (e.g., `https://articles.techfixpro.net`) in a browser.

- **API Token Errors**
  - **Cause**: Invalid or insufficient permissions in the Cloudflare API token.
  - **Solution**:
    - Regenerate the token with "Edit Zone DNS" permissions and "All Zones" access.
    - Ensure the domain is managed by Cloudflare.

- **Timeout Errors**
  - **Cause**: Subdomains are slow or unreachable, causing timeouts.
  - **Solution**:
    - Increase the timeout (e.g., `10` or `15` seconds). A timeout of `1` second may cause failures.
    - Check if subdomains resolve via DNS (`nslookup articles.techfixpro.net`). If they don’t, they’re likely offline.

- **Connection Refused (Error 61)**
  - **Cause**: Subdomains are blocked or not configured correctly.
  - **Solution**:
    - Verify the subdomain’s DNS settings in Cloudflare.
    - Skip unreachable subdomains by ensuring DNS resolution checks are working.

- **530 Errors (Cloudflare)**
  - **Cause**: Cloudflare’s Bot Fight Mode or WAF is blocking requests.
  - **Solution**:
    - Disable Bot Fight Mode in Cloudflare dashboard > Security > Bots.
    - Add a firewall rule to allow your User-Agent or IP.

- **WebUI Not Loading**
  - **Cause**: Port conflict or Flask server not running.
  - **Solution**:
    - Ensure the server is running (`python3 main.py --webui`).
    - Check for port conflicts (e.g., `5000` in use). Use a different port (e.g., `5003`).
    - Open the browser console (F12) and check for errors.

- **Logs Not Updating in WebUI**
  - **Cause**: WebSocket connection issues.
  - **Solution**:
    - Refresh the page to reconnect the WebSocket.
    - Check the browser console for WebSocket errors (e.g., `Failed to connect to ws://`).
    - Ensure `flask-socketio` is installed (`pip show flask-socketio`).

- **Sitemap Not Downloading**
  - **Cause**: `sitemap.xml` was not generated or is missing.
  - **Solution**:
    - Check logs for `Sitemap generated: sitemap.xml`.
    - Ensure the file exists in the project directory.
    - If the download button returns a 404, verify generation completed successfully.

- **Estimated Time Inaccurate**
  - **Cause**: The estimate assumes 2.5 seconds per subdomain/URL and may not match the actual site size.
  - **Solution**:
    - The script uses a fallback of 17 pages (based on `techfixpro.net`). For better accuracy, increase the timeout or adjust the `time_per_item` in `app.py`.

## Notes
- **Performance**: The script may take several minutes for domains with many subdomains due to DNS resolution, HTTP requests, and delays. The WebUI provides real-time progress and estimated time remaining.
- **Cloudflare Protections**: The script uses random User-Agents and delays (0.5–1.5s for discovery, 1–3s for crawling) to minimize blocks. If issues persist, adjust delays in `main.py` (e.g., increase `random.uniform(1, 3)` to `random.uniform(2, 5)`).
- **Robots.txt**: Ignoring `robots.txt` (`n` or unchecked in WebUI) increases coverage but may include URLs search engines won’t index. Use `y` or checked for compliance.
- **Dependencies**: Ensure `requirements.txt` versions are compatible. Update versions if needed (e.g., `pip install requests==<latest>`).
- **GitHub Sharing**: The `SECRET_KEY` in `app.py` is set to `'development-key'`, which is safe for public repositories. Do not expose your Cloudflare API token in the code; use the WebUI or CLI prompts to input it securely.
- **WebUI Timeout**: A timeout of `1` second may cause request failures. Use `5` seconds or higher for better reliability.

## Contributing
If you encounter bugs or have suggestions, feel free to:
- Open an issue on the repository.
- Submit a pull request with improvements.
- Share logs and error details for debugging, including WebUI screenshots if applicable.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details (if included).

## Acknowledgments
- Built with Python libraries: `requests`, `beautifulsoup4`, `dnspython`, `lxml`, `flask`, `flask-socketio`.
- Uses Cloudflare API and crt.sh for subdomain discovery.
- WebUI built with Flask, React, Tailwind CSS, and Socket.IO for real-time logging.
- Designed to handle real-world complexities of Cloudflare-protected domains.
