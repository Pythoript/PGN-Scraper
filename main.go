package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/urfave/cli/v2"
)

const version = "1.0.0"

func initLogger(logToFile bool, logFile string, verbose bool) *log.Logger {
	var output io.Writer

	if logToFile {
		if logFile == "" {
			logFile = "pgn-scraper.log"
		}
		file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("[error] Error opening log file: %v\n", err)
			os.Exit(1)
		}
		output = file
	} else {
		output = os.Stdout
	}

	logger := log.New(output, "", log.Ldate|log.Ltime)
	if verbose {
		logger.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	}
	return logger
}

func getURLs(urlFile, urlArg string, logger *log.Logger, verbose bool) ([]string, error) {
	var urls []string

	if urlFile != "" {
		if verbose {
			logger.Printf("[info] Using URL file: %s", urlFile)
		}
		data, err := os.ReadFile(urlFile)
		if err != nil {
			return nil, fmt.Errorf("[error] Failed to read file: %v", err)
		}
		urls = strings.Split(string(data), "\n")
	}
	if urlArg != "" {
		if verbose {
			logger.Printf("[info] Using URL argument: %s", urlArg)
		}
		urls = append(urls, urlArg)
	}

	uniqueURLs := make(map[string]struct{})
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u != "" {
			uniqueURLs[u] = struct{}{}
		}
	}

	finalURLs := make([]string, 0, len(uniqueURLs))
	for u := range uniqueURLs {
		finalURLs = append(finalURLs, u)
	}

	urlCount := len(finalURLs)
	if urlCount == 0 {
		return nil, fmt.Errorf("[error] No URLs found")
	} else {
		logger.Printf("[info] Found %d unique URL(s)", urlCount)
	}

	return finalURLs, nil
}

func createHTTPClient(proxyURL string, logger *log.Logger, verbose bool) *http.Client {
	transport := &http.Transport{}
	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			logger.Printf("[error] Invalid proxy URL: %s, error: %v", proxyURL, err)
			return &http.Client{Transport: transport}
		}
		transport.Proxy = http.ProxyURL(proxy)
		if verbose {
			logger.Printf("[info] Using proxy: %s", proxyURL)
		}
	}
	return &http.Client{Transport: transport}
}

func appendToLogFile(filename string, message string) {
	mu := &sync.Mutex{}
	mu.Lock()
	defer mu.Unlock()

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[error] Failed to open log file: %s, %v", filename, err)
		return
	}
	defer file.Close()

	_, err = file.WriteString(message + "\n")
	if err != nil {
		log.Printf("[error] Failed to write to log file: %s, %v", filename, err)
	}
}

func randomDelay(base, vary int) time.Duration {
	base = max(0, base)
	min := max(0, base-vary)
	max := base + vary
	return time.Duration(rand.Intn(max-min+1)+min) * time.Millisecond
}

func randomHeader(userAgents []string) map[string]string {
	if len(userAgents) > 0 {
		userAgents = []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
			"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
			"Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Mobile Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) obsidian/1.7.5 Chrome/128.0.6613.186 Electron/32.2.3 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0.1 Mobile/15E148 Safari/604.1",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 11.6; rv:92.0) Gecko/20100101 Firefox/92.0",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
		}
	}
	headers := map[string]string{
		"User-Agent":      userAgents[rand.Intn(len(userAgents))],
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.5",
		"Referer":         "https://google.com",
		"Connection":      "keep-alive",
		"Cache-Control":   "max-age=0",
	}
	return headers
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	src := rand.NewSource(time.Now().UnixNano())
	r := rand.New(src)
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[r.Intn(len(letters))]
	}
	return string(b)
}

func sanitizeName(host string) string {
	host = strings.TrimPrefix(host, "www.")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	return host
}

func createDir(path string) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err := os.MkdirAll(path, os.ModePerm)
		if err != nil {
			log.Printf("[error] Failed to create directory %s: %v", path, err)
		}
	}
}

func validFileName(name string) string {
	re := regexp.MustCompile(`[<>:"/\\|?*\x00-\x1F]`)
	name = re.ReplaceAllString(name, "_")
	if name == "" || strings.HasPrefix(name, ".") {
		name = randomString(7)
	}
	return name
}

func saveDownloadedURLs(fileName string, downloadedURLs []string, logger *log.Logger) error {
	downloadedURLsLength := len(downloadedURLs)
	if downloadedURLsLength == 0 {
		logger.Printf("[info] No URLs to save")
		return nil
	}

	domainURLs := make(map[string][]string)
	totalURLLength := 0

	for _, u := range downloadedURLs {
		totalURLLength += len(u)

		parsedURL, err := url.Parse(u)
		if err != nil {
			logger.Printf("[error] Failed to parse URL: %s, error: %v", u, err)
			continue
		}
		domain := sanitizeName(parsedURL.Host)
		domainURLs[domain] = append(domainURLs[domain], u)
	}

	file, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("[error] Failed to create file %s: %v", fileName, err)
	}
	defer file.Close()

	averageURLLength := 0
	if downloadedURLsLength > 0 {
		averageURLLength = totalURLLength / downloadedURLsLength
	}

	for domain, urls := range domainURLs {
		separatorLength := averageURLLength - len(domain) - 1
		if separatorLength < 0 {
			separatorLength = 0
		}
		separator := strings.Repeat("=", separatorLength)

		_, err := file.WriteString(fmt.Sprintf("%s %s\n\n", domain, separator))
		if err != nil {
			return fmt.Errorf("[error] Failed to write to file %s: %v", fileName, err)
		}

		for _, url := range urls {
			_, err := file.WriteString(url + "\n")
			if err != nil {
				return fmt.Errorf("[error] Failed to write to file %s: %v", fileName, err)
			}
		}

		_, err = file.WriteString("\n")
		if err != nil {
			return fmt.Errorf("[error] Failed to write to file %s: %v", fileName, err)
		}
	}

	logger.Printf("[success] Saved downloaded URLs to %s", fileName)
	return nil
}

var uniqueChecksums = struct {
	mu        sync.Mutex
	checksums map[string]struct{}
}{
	checksums: make(map[string]struct{}),
}

func computeChecksum(content []byte) string {
	hash := sha256.Sum256(content)
	return fmt.Sprintf("%x", hash[:])
}

func isChecksumUnique(checksum string) bool {
	uniqueChecksums.mu.Lock()
	defer uniqueChecksums.mu.Unlock()

	if _, exists := uniqueChecksums.checksums[checksum]; exists {
		return false
	}
	uniqueChecksums.checksums[checksum] = struct{}{}
	return true
}

func fileNotExists(path string) bool {
	_, err := os.Stat(path)
	return os.IsNotExist(err)
}

func downloadFile(client *http.Client, fileURL string, dest string, rename bool, keepDuplicates bool, opts map[string]interface{}, logger *log.Logger, verbose bool) (bool, error) {

	failedUrlLog := opts["log-failed"].(string)
	delay := opts["delay"].(int)
	vary := opts["vary"].(int)
	time.Sleep(randomDelay(delay, vary))

	req, err := http.NewRequest("GET", fileURL, nil)
	if err != nil {
		appendToLogFile(failedUrlLog, fileURL)
		return false, err
	}
	if !opts["no-header"].(bool) {
		headers := randomHeader(opts["useragent"].([]string))
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		if opts["user-agent"].(string) != "" {
			req.Header.Set("user-agent", opts["user-agent"].(string))
		}
		if opts["cookie"].(string) != "" {
			req.Header.Set("cookie", opts["cookie"].(string))
		} else if opts["cookie-file"].(string) != "" {
			req.Header.Set("Cookie", opts["cookie-file"].(string))
		}
		if verbose {
			logger.Printf("[Verbose] Requesting URL: %s with headers: %v", fileURL, headers)
		}
	} else if verbose {
		logger.Printf("[Verbose] Requesting URL: %s with no headers", fileURL)
	}

	resp, err := client.Do(req)
	if err != nil {
		appendToLogFile(failedUrlLog, fileURL)
		return false, err
	}
	defer resp.Body.Close()
	if verbose {
		logger.Printf("[Verbose] Received response %d for URL %s:", resp.StatusCode, fileURL)
	}

	if resp.StatusCode != http.StatusOK && failedUrlLog != "" {
		appendToLogFile(failedUrlLog, fileURL)
		return false, err
	} else if resp.StatusCode != http.StatusOK {
		return false, err
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		appendToLogFile(failedUrlLog, fileURL)
		return false, err
	}

	if !keepDuplicates {
		checksum := computeChecksum(content)
		if !isChecksumUnique(checksum) {
			logger.Printf("[info] Skipping duplicate file: %s", fileURL)
			return false, err
		}
	}

	parsedURL, err := url.Parse(fileURL)
	if err != nil {
		appendToLogFile(failedUrlLog, fileURL)
		return false, err
	}
	filename := validFileName(filepath.Base(parsedURL.Path))
	ext := filepath.Ext(filename)
	if rename {
		filename = randomString(6) + ext
	}
	if dest == "ratings.fide.com" {
		filename = randomString(6) + ".pgn"
	}
	if opts["dir"].(string) != "" {
		dest = filepath.Join(opts["dir"].(string), dest)
	}
	createDir(dest)

	for {
		destPath := filepath.Join(dest, filename)
		if opts["overwrite"].(bool) || fileNotExists(destPath) {
			err := os.WriteFile(destPath, content, 0644)
			if err != nil {
				appendToLogFile(failedUrlLog, fileURL)
				return false, err
			}
			logger.Printf("[success] Downloaded and saved: %s", destPath)
			return true, err
		}
		filename = randomString(6) + ext
	}
}

func scrapePGN(urls []string, threads int, opts map[string]interface{}, logger *log.Logger, verbose bool, client *http.Client) []string {
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)
	visited := make(map[string]bool)
	var mu sync.Mutex
	var resultMu sync.Mutex
	var successfulDownloads []string

	for _, u := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			downloads, _ := crawlPage(client, u, opts, visited, &mu, logger, verbose, 1)
			resultMu.Lock()
			successfulDownloads = append(successfulDownloads, downloads...)
			resultMu.Unlock()
		}(u)
	}
	wg.Wait()

	return successfulDownloads
}

var allValidExts = []string{".pgn", ".cbv", ".cbz", ".cbf", ".cbb", ".cbh", ".cbt", ".si4", ".sn4", ".sg4", ".zip", ".7z", ".txt"}
var zipValidExts = []string{".zip", ".7z"}
var chessbaseValidExts = []string{".cbv", ".cbz", ".cbf", ".cbb", ".cbh", ".cbt"}
var scidValidExts = []string{".si4", ".sn4", ".sg4"}
var textValidExts = []string{".txt"}

func isValidFileExtension(link *url.URL, opts map[string]interface{}, logger *log.Logger, verbose bool) bool {
	filePath := link.Path
	ext := strings.ToLower(filepath.Ext(filePath))

	if opts["fide"].(bool) || opts["all"].(bool) {
		query := link.Query()
		if query.Get("download") == "1" {
			return true
		}
	}
	if opts["all"].(bool) {
		for _, validExt := range allValidExts {
			if ext == validExt {
				return true
			}
		}
		return false
	}
	if opts["zip"].(bool) {
		for _, validExt := range zipValidExts {
			if ext == validExt {
				return true
			}
		}
	}
	if opts["chessbase"].(bool) {
		for _, validExt := range chessbaseValidExts {
			if ext == validExt {
				return true
			}
		}
	}
	if opts["scid"].(bool) {
		for _, validExt := range scidValidExts {
			if ext == validExt {
				return true
			}
		}
	}
	if opts["text"].(bool) {
		for _, validExt := range textValidExts {
			if ext == validExt {
				return true
			}
		}
	}
	if ext == ".pgn" {
		return true
	}

	return false
}

func crawlPage(client *http.Client, startURL string, opts map[string]interface{}, visited map[string]bool, mu *sync.Mutex, logger *log.Logger, verbose bool, currentDepth int) ([]string, error) {

	maxDepth := opts["depth"].(int)
	if currentDepth > maxDepth {
		return nil, nil
	}

	parsedURL, err := url.Parse(startURL)
	if err != nil {
		logger.Printf("[error] Invalid URL: %s", startURL)
		return nil, err
	}

	mu.Lock()
	if visited[startURL] {
		mu.Unlock()
		return nil, nil
	}
	visited[startURL] = true
	mu.Unlock()

	delay := opts["delay"].(int)
	vary := opts["vary"].(int)
	randomDelayMs := randomDelay(delay, vary)

	if verbose {
		logger.Printf("[info] Sleeping for %d Milliseconds", randomDelayMs)
	}
	time.Sleep(randomDelayMs)

	req, err := http.NewRequest("GET", startURL, nil)
	if err != nil {
		logger.Printf("[error] Failed to create request for %s: %v", startURL, err)
		return nil, err
	}

	if !opts["no-header"].(bool) {
		headers := randomHeader(opts["useragent"].([]string))
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		if opts["user-agent"].(string) != "" {
			req.Header.Set("user-agent", opts["user-agent"].(string))
		}
		if opts["cookie"].(string) != "" {
			req.Header.Set("cookie", opts["cookie"].(string))
		} else if opts["cookie-file"].(string) != "" {
			req.Header.Set("Cookie", opts["cookie-file"].(string))
		}
		if verbose {
			logger.Printf("[Verbose] Requesting URL: %s with headers: %v", startURL, headers)
		}
	} else if verbose {
		logger.Printf("[Verbose] Requesting URL: %s with no headers", startURL)
	}

	resp, err := client.Do(req)
	if err != nil {
		logger.Printf("[error] Failed to fetch URL %s: %v", startURL, err)
		return nil, err
	}
	defer resp.Body.Close()

	if verbose {
		logger.Printf("[Verbose] Visited URL: %s, Response: %d", startURL, resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		logger.Printf("[error] Failed to parse HTML at %s: %v", startURL, err)
		return nil, err
	}

	var successfulDownloads []string
	doc.Find("a, iframe, frame, object, embed").Each(func(i int, s *goquery.Selection) {
		var link string
		if href, exists := s.Attr("href"); exists {
			link = href
		} else if src, exists := s.Attr("src"); exists {
			link = src
		} else if data, exists := s.Attr("data"); exists {
			link = data
		}
		linkURL, err := url.Parse(link)
		if err != nil {
			logger.Printf("[error] Failed to parse link %s: %v", link, err)
			return
		}

		if !linkURL.IsAbs() {
			linkURL = parsedURL.ResolveReference(linkURL)
		}

		if isValidFileExtension(linkURL, opts, logger, verbose) {
			savedToDisk, err := downloadFile(client, linkURL.String(), sanitizeName(parsedURL.Host), opts["rename"].(bool), opts["keep-duplicates"].(bool), opts, logger, verbose)
			if err != nil {
				logger.Printf("[error] Failed to download %s: %v", linkURL.String(), err)
			}
			if savedToDisk {
				successfulDownloads = append(successfulDownloads, linkURL.String())
			}
		} else if opts["crawl"].(bool) && linkURL.Host == parsedURL.Host {
			crawlPage(client, linkURL.String(), opts, visited, mu, logger, verbose, currentDepth+1)
		}
	})

	return successfulDownloads, nil
}

func main() {
	app := &cli.App{
		Name:    "PGNScraper",
		Usage:   "A robust PGN scraper written in go",
		Version: version,
		Action: func(c *cli.Context) error {

			logToFile := c.Bool("log")
			logFile := c.String("log-file")
			verbose := c.Bool("verbose")
			logger := initLogger(logToFile, logFile, verbose)

			proxy := c.String("proxy")
			port := c.Int("port")

			if port != 0 && proxy != "" {
				proxy = fmt.Sprintf("%s://%s:%d", proxy, port)
			}
			client := createHTTPClient(proxy, logger, verbose)

			urls, err := getURLs(c.String("url-file"), c.String("url"), logger, c.Bool("verbose"))
			if err != nil {
				logger.Printf("%v", err)
				return err
			}

			uaFile := c.String("ua-file")
			var userAgents []string
			if uaFile != "" {
				data, err := os.ReadFile(uaFile)
				if err != nil {
					logger.Printf("[error] Failed to read User-Agent file %s: %v", uaFile, err)
					return err
				}
				userAgents = strings.Split(strings.TrimSpace(string(data)), "\n")
				logger.Printf("[info] Loaded %d User-Agent(s) from %s", len(userAgents), uaFile)
			}

			cookieFile := c.String("cookie-file")
			var cookies string
			if cookieFile != "" {
				data, err := os.ReadFile(cookieFile)
				if err != nil {
					logger.Printf("[error] Failed to read cookie file %s: %v", cookieFile, err)
					return err
				}
				cookies = strings.TrimSpace(string(data))
				logger.Printf("[info] Loaded cookies from %s", cookieFile)
			}

			opts := map[string]interface{}{
				"zip":             c.Bool("zip"),
				"crawl":           c.Bool("crawl"),
				"depth":           c.Int("depth"),
				"delay":           c.Int("delay"),
				"vary":            c.Int("vary"),
				"log-failed":      c.String("log-failed"),
				"rename":          c.Bool("rename"),
				"all":             c.Bool("all"),
				"chessbase":       c.Bool("chessbase"),
				"scid":            c.Bool("scid"),
				"text":            c.Bool("text"),
				"fide":            c.Bool("fide"),
				"prefer-pgn":      c.Bool("prefer-pgn"),
				"keep-duplicates": c.Bool("keep-duplicates"),
				"cookie":          c.String("cookie"),
				"no-header":       c.Bool("no-header"),
				"user-agent":      c.String("user-agent"),
				"overwrite":       c.Bool("overwrite"),
				"dir":             c.String("dir"),
				"user-agents":     userAgents,
				"cookie-file":     cookies,
			}

			downloadedURLs := scrapePGN(urls, c.Int("threads"), opts, logger, verbose, client)
			saveFile := c.String("save-urls")
			if saveFile != "" {
				err := saveDownloadedURLs(saveFile, downloadedURLs, logger)
				if err != nil {
					logger.Printf("[error] %v", err)
					return err
				}
			}

			return nil
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "url",
				Usage:    "Target URL to scrape",
				Required: false,
				Aliases:  []string{"u"},
			},
			&cli.StringFlag{
				Name:     "url-file",
				Usage:    "A file containg URLs to scrape seperated by newline",
				Required: false,
				Aliases:  []string{"f"},
			},
			&cli.IntFlag{
				Name:    "threads",
				Value:   5,
				Usage:   "The number of max threads",
				Aliases: []string{"t"},
			},
			&cli.BoolFlag{
				Name:    "zip",
				Usage:   "Download zip files",
				Aliases: []string{"z"},
			},
			&cli.BoolFlag{
				Name:    "crawl",
				Usage:   "Crawl the website for chess files",
				Aliases: []string{"c"},
			},
			&cli.IntFlag{
				Name:  "depth",
				Value: 1,
				Usage: "The crawl depth",
			},
			&cli.IntFlag{
				Name:  "delay",
				Value: 0,
				Usage: "The delay is ms betwean requests",
			},
			&cli.IntFlag{
				Name:  "vary",
				Value: 0,
				Usage: "The amount is ms the deylay can very",
			},
			&cli.StringFlag{
				Name:  "ua-file",
				Usage: "File containing User-Agent strings for rotation",
			},
			&cli.StringFlag{
				Name:  "cookie-file",
				Usage: "File containing cookies for authentication",
			},
			&cli.BoolFlag{
				Name:    "log",
				Usage:   "Save logs to a file instead of printing to the console",
				Aliases: []string{"l"},
			},
			&cli.StringFlag{
				Name:  "log-file",
				Value: "pgn-scraper.log",
				Usage: "The file to save logged data if --log is enabled",
			},
			&cli.StringFlag{
				Name:  "log-failed",
				Usage: "Filename to log urls of games that failed to download",
			},
			&cli.StringFlag{
				Name:    "save-urls",
				Usage:   "File to save successfully downloaded URLs",
				Aliases: []string{"s"},
			},
			&cli.StringFlag{
				Name:    "dir",
				Usage:   "Directory to save downloaded files",
				Aliases: []string{"d"},
			},
			&cli.BoolFlag{
				Name:    "rename",
				Usage:   "Rename files with randomly generated filename",
				Aliases: []string{"r"},
			},
			&cli.BoolFlag{
				Name:    "all",
				Usage:   "Download all ches game files",
				Aliases: []string{"a"},
			},
			&cli.BoolFlag{
				Name:  "chessbase",
				Usage: "Download ChessBase game files",
			},
			&cli.BoolFlag{
				Name:  "scid",
				Usage: "Download SCID game files",
			},
			&cli.BoolFlag{
				Name:  "text",
				Usage: "Download plain-text game files",
			},
			&cli.BoolFlag{
				Name:  "fide",
				Usage: "Download Chess games from ratings.fide.com",
			},
			&cli.BoolFlag{
				Name:    "keep-duplicates",
				Usage:   "Keep duplicate files",
				Aliases: []string{"k"},
			},
			&cli.StringFlag{
				Name:  "cookie",
				Usage: "Send cookie with each request",
			},
			&cli.BoolFlag{
				Name:    "overwrite",
				Usage:   "Allow overwriting old files with new ones",
				Aliases: []string{"o"},
			},
			&cli.BoolFlag{
				Name:  "no-header",
				Usage: "Do not send headers with request to the host",
			},
			&cli.StringFlag{
				Name:  "user-agent",
				Usage: "Manually specify a User-Agent string",
			},
			&cli.StringFlag{
				Name:     "proxy",
				Usage:    "Proxy URL (e.g., http://127.0.0.1:8080)",
				Aliases:  []string{"p"},
				Required: false,
			},
			&cli.IntFlag{
				Name:     "port",
				Usage:    "Proxy port (e.g., 8080)",
				Required: false,
			},
			&cli.BoolFlag{
				Name:  "verbose",
				Usage: "Enable verbose logging, useful for debugging",
			},
		},
	}
	app.Run(os.Args)
}
