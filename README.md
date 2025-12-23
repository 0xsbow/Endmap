# EndMap - Hidden Endpoint Discovery and Fuzzing Tool
EndMap helps security researchers, penetration testers, and developers identify hidden API endpoints, admin panels, and other sensitive paths.

## Features
✨ **Core Features:**
- 🔍 **Endpoint Discovery** - Automatically extract endpoints from robots.txt, sitemap.xml, JavaScript files, and important configuration files
- 🎯 **Endpoint Fuzzing** - Brute-force hidden endpoints using customizable wordlists
- 🔄 **Recursive Fuzzing** - Automatically fuzz discovered directories recursively
- 🚀 **Multi-threaded** - Fast concurrent scanning with configurable thread count
- 📊 **Response Code Display** - Optional HTTP status code output
- 💾 **Result Export** - Save discovered endpoints to file
- 🔕 **Silent Mode** - Clean output by default, verbose mode with `-v` flag

## Installation
### Requirements
- Python 3.7+
- requests library

### Setup

```bash
# Clone or download the script
git clone https://github.com/0xsbow/endmap.git
cd endmap

# Install dependencies
pip install requests

# Make executable (optional)
chmod +x endmap.py
```

## Usage

### Basic Commands

#### Discovery Mode (Default)
Discover endpoints from various sources:

```bash
# Scan a single URL
python3 endmap.py -u https://example.com

# Scan multiple URLs from a file
python3 endmap.py -l urls.txt

# Enable verbose output
python3 endmap.py -u https://example.com -v

# Show HTTP status codes
python3 endmap.py -u https://example.com -rc

# Save results to file
python3 endmap.py -u https://example.com -o results.txt
```

#### Fuzzing Mode
Fuzz hidden endpoints using wordlists:

```bash
# Basic fuzzing (no extensions)
python3 endmap.py -u https://example.com --fuzz

# Fuzz with custom extensions
python3 endmap.py -u https://example.com --fuzz -e .php,.html,.asp

# Fuzz with built-in extensions
python3 endmap.py -u https://example.com --fuzz --default-ext

# Fuzz with custom wordlist
python3 endmap.py -u https://example.com --fuzz -w custom_wordlist.txt

# Recursive fuzzing (fuzz discovered directories)
python3 endmap.py -u https://example.com --fuzz -r

# Combine multiple options
python3 endmap.py -u https://example.com --fuzz -w wordlist.txt -e .php,.json -r -rc -v
```

### Advanced Usage

#### Multi-threaded Scanning
Control concurrent thread count:

```bash
# Use 20 threads (default is 10)
python3 endmap.py -u https://example.com --fuzz -t 20

# Use 5 threads for slower networks
python3 endmap.py -u https://example.com --fuzz -t 5
```

#### Combine All Options
```bash
# Complete example with all features
python3 endmap.py \
  -u https://example.com \
  --fuzz \
  -w custom_wordlist.txt \
  -e .php,.html,.asp,.json \
  -r \
  -rc \
  -o results.txt \
  -t 15 \
  -v
```
## Discovery Methods

EndMap discovers endpoints from multiple sources:

1. **robots.txt** - Extract Disallow, Allow, and Sitemap entries
2. **sitemap.xml** - Extract all URLs from XML sitemap
3. **Important Files** - Check for exposed configuration files:
   - `.env`, `.env.local`, `.env.production`
   - `.git/config`, `.gitconfig`
   - `package.json`, `composer.json`, `requirements.txt`
   - `config.php`, `wp-config.php`
   - `web.config`, `appsettings.json`
   - And many more...
4. **JavaScript Files** - Extract endpoints from JavaScript source files

## Fuzzing Wordlist

The tool includes a comprehensive built-in wordlist with 500+ entries covering:

- **Core Directories**: admin, api, backup, config, database, dev, docs, etc.
- **API Endpoints**: api/v1-v5, api/graphql, api/webhooks, api/auth, etc.
- **Authentication**: login, logout, signin, signup, register, auth, oauth, etc.
- **Admin Panels**: admin, dashboard, console, control panel, etc.
- **Configuration**: config, settings, environment variables, etc.
- **Development**: dev, test, staging, debug, console, etc.
- **Common Files**: sitemap, robots, security.txt, .well-known, etc.
- **CMS Specific**: WordPress, Drupal, Joomla, Magento, etc.
- **And more...**

## Recursive Fuzzing

When using the `-r` flag, EndMap automatically:
1. Scans the initial URL
2. Identifies discovered directories (status codes 200, 301, 302, 304)
3. Recursively fuzzes each discovered directory
4. Continues until all directories are explored


## Limitations
- Respects standard HTTP timeout (5 seconds per request)
- Does not bypass authentication
- Does not bypass WAF/IPS protections
- Requires valid target URL
- No crawling of authenticated pages

## Legal Disclaimer
⚠️ **Important**: 
EndMap is designed for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. Always:

1. **Obtain written permission** before testing
2. **Use on your own systems** or with explicit authorization
3. **Comply with local laws** regarding penetration testing
4. **Respect privacy** and confidentiality
The author assumes no liability for misuse or damage caused by this tool.

## Contributing
Contributions are welcome! Feel free to:
- Report bugs
- Suggest improvements
- Add new wordlist entries
- Improve documentation

## Future Enhancements

Planned features for upcoming releases:
- [ ] Proxy support (Burp Suite integration)
- [ ] Custom header support
- [ ] Rate limiting/throttling
- [ ] SSL certificate validation options
- [ ] Database of common endpoints
- [ ] GUI version
- [ ] Docker containerization
- [ ] Integration with other tools
- [ ] Machine learning for endpoint detection

## Support

For issues, questions, or suggestions, please create an issue on GitHub or contact the development team.

## License

This project is licensed under the MIT License.
---
**EndMap v1.0.0** | Endpoint Discovery & Fuzzing Tool | Stay Secure! 🔒
