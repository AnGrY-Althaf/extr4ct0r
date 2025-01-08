package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/fatih/color"
)

type Patterns struct {
	Name    string
	Pattern string
}

type Finding struct {
	Type       string `json:"type"`
	Value      string `json:"value"`
	File       string `json:"file"`
	LineNumber int    `json:"line_number"`
}

type ScanResult struct {
	JSFiles       []string  `json:"js_files"`
	Endpoints     []string  `json:"endpoints"`
	SensitiveInfo []Finding `json:"sensitive_info"`
}

type Scanner struct {
	patterns []Patterns
	client   *http.Client
	results  map[string]*ScanResult
	mutex    sync.RWMutex
}

func NewScanner() *Scanner {
	return &Scanner{
		patterns: getPatterns(),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		results: make(map[string]*ScanResult),
	}
}

func printBanner() {
	banner := `
___________            __                _____              __    _______             
\_   _____/ ___  ___ _/  |_  _______    /  |  |    ____   _/  |_  \   _  \   _______  
 |    __)_  \  \/  / \   __\ \_  __ \  /   |  |_ _/ ___\  \   __\ /  /_\  \  \_  __ \ 
 |        \  >    <   |  |    |  | \/ /    ^   / \  \___   |  |   \  \_/   \  |  | \/ 
/_______  / /__/\_ \  |__|    |__|    \____   |   \___  >  |__|    \_____  /  |__|    
        \/        \/                       |__|       \/                 \/           
                                                                                      
                                                                            -AnGrY
	`
	color.White(banner)
}

func getPatterns() []Patterns {
    return []Patterns{
        // Google and Firebase
        {"google_api", `AIza[0-9A-Za-z-_]{35}`},
        {"firebase", `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`},
        {"google_captcha", `6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$`},
        {"google_oauth", `ya29\.[0-9A-Za-z\-_]+`},

        // AWS
        {"amazon_aws_access_key_id", `A[SK]IA[0-9A-Z]{16}`},
        {"amazon_mws_auth_token", `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`},
        {"amazon_aws_url", `s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com`},
        {"amazon_aws_url2", `([a-zA-Z0-9-\._]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-\._]+|s3-[a-zA-Z0-9-\._\/]+|s3.amazonaws.com/[a-zA-Z0-9-\._]+|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\._]+)`},

        // Social Media & OAuth
        {"facebook_access_token", `EAACEdEose0cBA[0-9A-Za-z]+`},
        {"authorization_basic", `basic [a-zA-Z0-9=:_\+\/-]{5,100}`},
        {"authorization_bearer", `bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}`},
        {"authorization_api", `api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}`},

        // Email & Communications
        {"mailgun_api_key", `key-[0-9a-zA-Z]{32}`},

        // Payment Services
        {"paypal_braintree_access_token", `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`},
        {"square_oauth_secret", `sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}`},
        {"square_access_token", `sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}`},
        {"stripe_standard_api", `sk_live_[0-9a-zA-Z]{24}`},
        {"stripe_restricted_api", `rk_live_[0-9a-zA-Z]{24}`},

        // Version Control
        {"github_access_token", `[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*`},

        // Private Keys
        {"rsa_private_key", `-----BEGIN RSA PRIVATE KEY-----`},
        {"ssh_dsa_private_key", `-----BEGIN DSA PRIVATE KEY-----`},
        {"ssh_dc_private_key", `-----BEGIN EC PRIVATE KEY-----`},
        {"pgp_private_block", `-----BEGIN PGP PRIVATE KEY BLOCK-----`},
        {"ssh_private_key", `([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)`},

        // JWT & Authentication
        {"json_web_token", `ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$`},
        {"slack_token", `"api_token":"(xox[a-zA-Z]-[a-zA-Z0-9-]+)"`},

        // Platform Specific
        {"heroku_api_key", `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`},

        // Credentials
        {"possible_credentials", `(?i)(password\s*[` + "`" + `=:"]+\s*[^\s]+|password is\s*[` + "`" + `=:"]*\s*[^\s]+|pwd\s*[` + "`" + `=:"]*\s*[^\s]+|passwd\s*[` + "`" + `=:"]+\s*[^\s]+)`},
	    
	    // IP Addresses and Internal Endpoints
		{"internal_ip", `\b(?:localhost|\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b)`},
		{"staging_url", `(?i)(dev\.|stage\.|staging\.|test\.)[a-zA-Z0-9-]+\.[a-zA-Z]{2,}`},
	}
}

func (s *Scanner) extractJSLinks(url string) ([]string, error) {
	resp, err := s.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	var jsFiles []string
	doc.Find("script[src]").Each(func(_ int, s *goquery.Selection) {
		if src, exists := s.Attr("src"); exists {
			jsFiles = append(jsFiles, normalizeURL(url, src))
		}
	})

	return jsFiles, nil
}

func (s *Scanner) findEndpoints(url string) ([]string, error) {
    var endpoints []string
    jsFiles, err := s.extractJSLinks(url)
    if err != nil {
        return nil, err
    }

    for _, jsURL := range jsFiles {
        resp, err := s.client.Get(jsURL)
        if err != nil {
            continue
        }
        content, err := io.ReadAll(resp.Body)
        resp.Body.Close()
        if err != nil {
            continue
        }

        patterns := []string{
            // API endpoints
            `(?:"|')(/api/[^"'{\s]+)(?:"|')`,
            // Full URLs
            `(?:"|')(https?://[a-zA-Z0-9][a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}[^"'{\s]*)(?:"|')`,
            // Paths starting with slash (excluding common JS patterns)
            `(?:"|')(/[a-zA-Z0-9-_/]+(?:\.[a-zA-Z]{2,})?[^"'{\s]*?)(?:"|')`,
        }

        isValidEndpoint := func(endpoint string) bool {
            invalidPatterns := []string{
                `^//`,
                `/\w+[<>]`,
                `^/[g]+$`,
                `^/\[`,
                `^/\d+$`,
                `/\${`,
                `\s`,
                `[<>{}]`,
                `/[a-z]+/[a-z]+$`,
            }

            for _, pattern := range invalidPatterns {
                if matched, _ := regexp.MatchString(pattern, endpoint); matched {
                    return false
                }
            }

            return len(endpoint) > 2 && regexp.MustCompile(`^[a-zA-Z0-9/._-]+$|^https?://`).MatchString(endpoint)
        }

        for _, pattern := range patterns {
            re := regexp.MustCompile(pattern)
            matches := re.FindAllStringSubmatch(string(content), -1)
            for _, match := range matches {
                if len(match) > 1 {
                    endpoint := match[1]
                    if isValidEndpoint(endpoint) {
                        endpoints = append(endpoints, endpoint)
                    }
                }
            }
        }
    }

    return unique(endpoints), nil
}

func (s *Scanner) findSensitiveInfo(url string) ([]Finding, error) {
	var findings []Finding
	jsFiles, err := s.extractJSLinks(url)
	if err != nil {
		return nil, err
	}

	for _, jsURL := range jsFiles {
		resp, err := s.client.Get(jsURL)
		if err != nil {
			continue
		}
		content, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		contentStr := string(content)
		lines := strings.Split(contentStr, "\n")

		for _, pattern := range s.patterns {
			re := regexp.MustCompile(pattern.Pattern)
			for i, line := range lines {
				matches := re.FindAllString(line, -1)
				for _, match := range matches {
					findings = append(findings, Finding{
						Type:       pattern.Name,
						Value:      match,
						File:       jsURL,
						LineNumber: i + 1,
					})
				}
			}
		}
	}

	return findings, nil
}

func (s *Scanner) scanURL(url string) {
	result := &ScanResult{}

	// Extract JS files
	jsFiles, err := s.extractJSLinks(url)
	if err == nil {
		result.JSFiles = jsFiles
	}

	// Find endpoints
	endpoints, err := s.findEndpoints(url)
	if err == nil {
		result.Endpoints = endpoints
	}

	// Find sensitive info
	sensitiveInfo, err := s.findSensitiveInfo(url)
	if err == nil {
		result.SensitiveInfo = sensitiveInfo
	}

	s.mutex.Lock()
	s.results[url] = result
	s.mutex.Unlock()
}

func (s *Scanner) scanURLs(urls []string) {
	var wg sync.WaitGroup
	for _, url := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			color.Yellow("[*] Scanning: %s", u)
			s.scanURL(u)
		}(url)
	}
	wg.Wait()
}

func (s *Scanner) saveJSFiles(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	for url, result := range s.results {
		fmt.Fprintf(f, "\n=== JavaScript files for %s ===\n", url)
		for _, js := range result.JSFiles {
			fmt.Fprintln(f, js)
		}
	}
	return nil
}

func (s *Scanner) saveEndpoints(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	for url, result := range s.results {
		fmt.Fprintf(f, "\n=== Endpoints found for %s ===\n", url)
		for _, endpoint := range result.Endpoints {
			fmt.Fprintln(f, endpoint)
		}
	}
	return nil
}

func (s *Scanner) saveSensitiveInfo(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	for url, result := range s.results {
		fmt.Fprintf(f, "\n=== Sensitive information found in %s ===\n", url)
		for _, info := range result.SensitiveInfo {
			fmt.Fprintf(f, "Type: %s\n", info.Type)
			fmt.Fprintf(f, "Value: %s\n", info.Value)
			fmt.Fprintf(f, "File: %s\n", info.File)
			fmt.Fprintf(f, "Line: %d\n\n", info.LineNumber)
		}
	}
	return nil
}

func (s *Scanner) saveOutput(option string) error {
	outDir := "output"
	os.MkdirAll(outDir, 0755)

	var filename string
	switch option {
	case "1":
		filename = filepath.Join(outDir, fmt.Sprintf("javascript-files.txt"))
		return s.saveJSFiles(filename)
	case "2":
		filename = filepath.Join(outDir, fmt.Sprintf("endpoints.txt"))
		return s.saveEndpoints(filename)
	case "3":
		filename = filepath.Join(outDir, fmt.Sprintf("js-exposures.txt"))
		return s.saveSensitiveInfo(filename)
	}
	return nil
}

func normalizeURL(baseURL, ref string) string {
	if strings.HasPrefix(ref, "http") {
		return ref
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return ref
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return base.ResolveReference(refURL).String()
}

func unique(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func main() {
    printBanner()

    urlsFlag := flag.String("u", "", "Comma-separated list of URLs to scan")
    flag.Parse()

    var urls []string
    var isPipe bool

    stat, _ := os.Stdin.Stat()
    if (stat.Mode() & os.ModeCharDevice) == 0 {
        isPipe = true
        scanner := bufio.NewScanner(os.Stdin)
        for scanner.Scan() {
            url := strings.TrimSpace(scanner.Text())
            if url != "" {
                urls = append(urls, url)
            }
        }
    } else if *urlsFlag != "" {
        urls = strings.Split(*urlsFlag, ",")
    } else {
        os.Exit(1)
    }

    if len(urls) == 0 {
        os.Exit(1)
    }

    scanner := NewScanner()

    color.Green("[+] Starting scan...")
    scanner.scanURLs(urls)
    color.Green("[+] Scan completed!")

    if isPipe {
        outDir := "output"
        os.MkdirAll(outDir, 0755)

        for i := 1; i <= 3; i++ {
            if err := scanner.saveOutput(fmt.Sprintf("%d", i)); err != nil {
                color.Red("[!] Error saving output %d: %v", i, err)
            } else {
                color.Green("[+] Output %d saved successfully!", i)
            }
        }
        return
    }

    reader := bufio.NewReader(os.Stdin)
    for {
        color.Cyan("\n[+] Extract0r - What would you like to extract?")
        fmt.Println("1. Extract all JavaScript files")
        fmt.Println("2. Find all links and endpoints")
        fmt.Println("3. Check for exposures")
        fmt.Println("4. Exit")

        fmt.Print("\nEnter your choice (1-4): ")
        choice, _ := reader.ReadString('\n')
        choice = strings.TrimSpace(choice)

        if choice == "4" {
            color.Green("\n[+] Bie Biee!")
            break
        }

        if choice >= "1" && choice <= "3" {
            if err := scanner.saveOutput(choice); err != nil {
                color.Red("[!] Error saving output: %v", err)
            } else {
                color.Green("[+] Output saved successfully!")
            }
        } else {
            color.Red("[!] Invalid choice. Please try again.")
        }
    }
}