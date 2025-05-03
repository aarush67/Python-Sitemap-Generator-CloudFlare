# Sitemap Generator for Cloudflare Domains

This Python script generates a sitemap (`sitemap.xml`) for a specified domain by discovering and crawling its subdomains. It uses Cloudflare DNS records, a predefined wordlist, and certificate transparency logs (via crt.sh) to identify subdomains, then crawls them to collect accessible URLs. The script is designed to handle Cloudflare-protected domains, bypassing rate-limiting and Bot Fight Mode with User-Agent rotation and delays.

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

## Prerequisites
- **Python 3.6+**: Ensure Python is installed (`python3 --version`).
- **Cloudflare Account**: You need a Cloudflare account with access to the target domain's DNS settings.
- **Cloudflare API Token**: A token with "Edit Zone DNS" permissions for the target domain.
- **Internet Connection**: Required for DNS resolution, HTTP requests, and Cloudflare API calls.

## Installation

1. **Clone or Download the Repository**
   - Download the script (`generate_sitemap.py`) and `requirements.txt` to a local directory.
   - Alternatively, clone the repository if hosted on a platform like GitHub:
     ```bash
     git clone https://github.com/aarush67/Sitemap-Generator-CloudFlare.git
     cd Sitemap-Generator-CloudFlare
     ```

2. **Set Up a Virtual Environment (Recommended)**
   - Create and activate a virtual environment to manage dependencies:
     ```bash
     python3 -m venv venv
     source venv/bin/activate  # On Windows: venv\Scripts\activate
     ```

3. **Install Dependencies**
   - Ensure `requirements.txt` is in the same directory as the script. It includes:
     - `requests`
     - `beautifulsoup`
     - `dnspython`
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

1. **Run the Script**
   - Ensure you’re in the directory containing `generate_sitemap.py` and your virtual environment is activated.
   - Run the script:
     ```bash
     python3 generate_sitemap.py
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
   Enter your Cloudflare API token You can get one by going to your main cloudflare dashboard and clicking profile and then API Tokens Click Create Token and use Edit zone DNS as the teplate and change Zone Resources from Specific Zone to All Zones and click Continue to Summary and then click Create Token and copy the token and input it in here: <paste-token>
   Respect robots.txt? (y/n, default: y): n
   Enter timeout in seconds (default: 5): 5
   ```

3. **Output**
   - The script discovers subdomains, crawls them, and generates a `sitemap.xml` file in the current directory.
   - Logs are printed to the console, showing discovered subdomains (e.g., `https://articles.techfixpro.net`), crawling progress, and any errors.
   - The final log indicates the number of unique URLs found (e.g., `Found 15 unique pages across main domain and subdomains`).

4. **Verify the Sitemap**
   - Open `sitemap.xml` to check the listed URLs. It should include subdomains like:
     - `https://techfixpro.net`
     - `https://www.techfixpro.net`
     - `https://articles.techfixpro.net`
     - etc.
   - Submit the sitemap to search engines (e.g., Google Search Console) for indexing.

## Example Sitemap
The generated `sitemap.xml` follows the [Sitemap Protocol](http://www.sitemaps.org/schemas/sitemap/0.9) and looks like this:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://techfixpro.net</loc>
    <lastmod>2025-05-02</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://articles.techfixpro.net</loc>
    <lastmod>2025-05-02</lastmod>
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
  - **Cause**: Subdomains like `chat.techfixpro.net` are slow or unreachable, causing timeouts.
  - **Solution**:
    - Increase the timeout (e.g., `10` or `15` seconds).
    - Check if subdomains resolve via DNS (`nslookup chat.techfixpro.net`). If they don’t, they’re likely offline.

- **Connection Refused (Error 61)**
  - **Cause**: Subdomains like `ssl.techfixpro.net` are blocked or not configured correctly.
  - **Solution**:
    - Verify the subdomain’s DNS settings in Cloudflare.
    - Skip unreachable subdomains by ensuring DNS resolution checks are working.

- **530 Errors (Cloudflare)**
  - **Cause**: Cloudflare’s Bot Fight Mode or WAF is blocking requests.
  - **Solution**:
    - Disable Bot Fight Mode in Cloudflare dashboard > Security > Bots.
    - Add a firewall rule to allow your User-Agent or IP.

- **Logs Show Duplicates**
  - **Cause**: Subdomains like `techfixpro.net` are checked multiple times.
  - **Solution**: This is normal during discovery (Cloudflare DNS, wordlist, crt.sh). The script deduplicates URLs before generating the sitemap.

## Notes
- **Performance**: The script may take several minutes for domains with many subdomains due to DNS resolution, HTTP requests, and delays to avoid rate-limiting.
- **Cloudflare Protections**: The script uses random User-Agents and delays (0.5–1.5s for discovery, 1–3s for crawling) to minimize blocks. If issues persist, adjust delays in the code (e.g., increase `random.uniform(1, 3)` to `random.uniform(2, 5)`).
- **Robots.txt**: Ignoring `robots.txt` (`n`) increases coverage but may include URLs search engines won’t index. Use `y` for compliance.
- **Dependencies**: Ensure `requirements.txt` versions are compatible. Update versions if needed (e.g., `pip install requests==<latest>`).

## Contributing
If you encounter bugs or have suggestions, feel free to:
- Open an issue on the repository (if hosted).
- Submit a pull request with improvements.
- Share logs and error details for debugging.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details (if included).

## Acknowledgments
- Built with Python libraries: `requests`, `beautifulsoup4`, `dnspython`.
- Uses Cloudflare API and crt.sh for subdomain discovery.
- Designed to handle real-world complexities of Cloudflare-protected domains.
