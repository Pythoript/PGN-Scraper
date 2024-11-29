# PGN Scraper

## Overview

**PGN Scraper** is a command-line application written in Go, designed to scrape Portable Game Notation (PGN) files and related formats from the internet. It supports crawling websites, downloading files, and organizing the output efficiently, making it ideal for chess enthusiasts or developers working with large amounts of chess data.

---

## Features

- **Multi-threaded Crawling:** Scrape multiple URLs concurrently with customizable threading.
- **Custom Headers and Proxies:** Support for random user-agents, custom headers, and proxies.
- **Advanced File Handling:** Detects duplicate files using checksums, supports name regeneration, and organizes downloaded files by domain.
- **Recursive Crawling:** Optionally follow internal links up to a user-defined depth.
- **Flexible Format Support:** Download PGN, ChessBase, SCID, ZIP, and text files.
- **Random Delays:** Simulates human-like browsing behavior with random delays.

---

## Installation

1. Ensure you have Go installed on your system (version 1.18+).
2. Clone the repository:
   ```bash
   git clone https://github.com/Pythoript/PGN-Scraper.git
   ```
3. Navigate to the project directory:
   ```bash
   cd PGN-Scraper
   ```
4. Install Dependancies:
   ```bash
   go mod tidy
   ```
5. Build the application:
   ```bash
   go build -o pgn-scraper
   ```

---

## Usage

Run the scraper using the command-line interface. The following flags are supported:

### Flags

| **Flag**              | **Description**                                                                 | **Default**          |
|------------------------|---------------------------------------------------------------------------------|----------------------|
| `--url`               | Single URL to scrape.                                                           |                      |
| `--url-file`          | File containing a list of URLs (one per line).                                  |                      |
| `--depth`             | Maximum depth for recursive crawling.                                           | `1`                  |
| `--threads`           | Number of concurrent threads for crawling.                                      | `1`                  |
| `--dir`               | Directory to save downloaded files.                                             | `./`                 |
| `--proxy`             | Proxy server URL (e.g., `http://proxy.example.com`).                            |                      |
| `--port`              | Proxy server port (used with `--proxy`).                                        |                      |
| `--user-agent`        | Custom user-agent string.                                                       |                      |
| `--ua-file`           | File containing user-agent strings (one per line).                              |                      |
| `--rename`            | Rename downloaded files to random strings.                                      | `false`              |
| `--log`               | Enable logging to a file.                                                       | `false`              |
| `--log-file`          | Specify the log file name.                                                      | `pgn-scraper.log`    |
| `--verbose`           | Enable verbose logging.                                                         | `false`              |
| `--no-header`         | Disable custom headers in requests.                                             | `false`              |
| `--delay`             | Base delay (ms) between requests.                                               | `0`                  |
| `--vary`              | Random variation (ms) added to base delay.                                      | `0`                  |
| `--keep-duplicates`   | Keep duplicate files (disables checksums).                                      | `false`              |
| `--cookie`            | Send cookie with each request                                                   |                      |
| `--cookie-file`       | File containing cookies for authentication                                      |                      |
| `--log-failed`        | File to save faild (non 404 error) download URLs                                |                      |
| `--save-urls`         | File to save successfully downloaded URLs                                       |                      |
| `--overwrite`         | Overwrite existing files.                                                       | `false`              |
| `--chessbase`         | Support downloading ChessBase files                                             | `false`              |
| `--scid`              | Support downloading SCID files                                                  | `false`              |
| `--text`              | Support downloading text files                                                  | `false`              |
| `--zip`               | Support downloading zip and 7z files                                            | `false`              |
| `--fide`              | Support downloading PGN files on ratings.fide.com.                              | `false`              |
| `--all`               | Download all supported formats.upport downloading PGN files                     | `false`              |
| `--crawl`             | Enable crawling for internal links.                                             | `false`              |

### Examples

1. **Basic Scraping:**
   ```bash
   ./pgn-scraper --url https://example.com/pgns
   ```

2. **Scrape Multiple URLs from a File:**
   ```bash
   ./pgn-scraper --url-file urls.txt --threads 5 --dir chess-data
   ```

3. **Enable Proxies and Custom User-Agent:**
   ```bash
   ./pgn-scraper --url https://example.com/pgns --proxy http://proxyserver.com --user-agent "CustomAgent/1.0"
   ```

4. **Recursive Crawling:**
   ```bash
   ./pgn-scraper --url https://example.com --crawl --depth 3
   ```

---

## Contributing

1. Fork the repository.
2. Create a new branch for your feature:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Add new feature"
   ```
4. Push to your branch:
   ```bash
   git push origin feature-name
   ```
5. Submit a pull request.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
