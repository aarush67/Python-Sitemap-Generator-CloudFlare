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
     git clone <repository-url>
     cd <repository-directory>
     ```

2. **Set Up a Virtual Environment (Recommended)**
   - Create and activate a virtual environment to manage dependencies:
     ```bash
     python3 -m venv venv
     source venv/bin/activate  # On Windows: venv\Scripts\activate
     ```

3. **Install Dependencies**
   - Ensure `requirements.txt` is in the same directory as the script. It includes:
     - `requests==2.32.3`
     - `beautifulsoup4==4.12.3`
     - `dnspython==2.6.1`
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
