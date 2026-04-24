package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const blobSuffix = ".blob.core.windows.net"

type Result struct {
	Name      string
	Exists    bool
	IP        string
	Public    bool
	PublicMsg string
}

var (
	flagWordlist  = flag.String("w", "", "wordlist file (one name per line)")
	flagThreads   = flag.Int("t", 50, "concurrent threads")
	flagOutput    = flag.String("o", "", "output file for hits (optional)")
	flagTimeout   = flag.Int("timeout", 5, "DNS/HTTP timeout in seconds")
	flagOnlyFound = flag.Bool("found", false, "only print names that exist (DNS hit)")
	flagQuiet     = flag.Bool("q", false, "suppress banner and summary")
	flagPrefix    = flag.String("prefix", "", "prefix to prepend to every word (e.g. acme-)")
	flagSuffix    = flag.String("suffix", "", "suffix to append to every word (e.g. -prod)")
	flagNoHTTP    = flag.Bool("no-http", false, "skip HTTP probe (DNS enumeration only)")
)

func main() {
	flag.Parse()

	if !*flagQuiet {
		printBanner()
	}

	if *flagWordlist == "" {
		fmt.Fprintln(os.Stderr, "[!] use -w <wordlist>")
		flag.Usage()
		os.Exit(1)
	}

	f, err := os.Open(*flagWordlist)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] cannot open wordlist: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	var outFile *os.File
	if *flagOutput != "" {
		outFile, err = os.Create(*flagOutput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] cannot create output file: %v\n", err)
			os.Exit(1)
		}
		defer outFile.Close()
	}

	timeout := time.Duration(*flagTimeout) * time.Second
	resolver := &net.Resolver{PreferGo: true}

	httpClient := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: false},
			DisableKeepAlives: true,
		},
	}

	jobs := make(chan string, *flagThreads*2)
	results := make(chan Result, *flagThreads*2)

	var wg sync.WaitGroup
	for i := 0; i < *flagThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range jobs {
				results <- probe(name, resolver, httpClient, timeout)
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	go func() {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			candidate := *flagPrefix + line + *flagSuffix
			jobs <- candidate
		}
		close(jobs)
	}()

	total, found, public := 0, 0, 0
	for r := range results {
		total++
		if *flagOnlyFound && !r.Exists {
			continue
		}
		if r.Exists {
			found++
		}
		if r.Public {
			public++
		}
		line := formatResult(r)
		fmt.Println(line)
		if outFile != nil && r.Exists {
			fmt.Fprintln(outFile, line)
		}
	}

	if !*flagQuiet {
		fmt.Fprintf(os.Stderr, "\n[*] done — checked: %d | found: %d | public: %d\n", total, found, public)
	}
}

func probe(name string, resolver *net.Resolver, client *http.Client, timeout time.Duration) Result {
	host := name + blobSuffix
	r := Result{Name: name}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	addrs, err := resolver.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		return r
	}
	r.Exists = true
	r.IP = addrs[0]

	if *flagNoHTTP {
		return r
	}

	// Try to list containers at account level
	url := fmt.Sprintf("https://%s/?comp=list", host)
	resp, err := client.Get(url)
	if err != nil {
		return r
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	bodyStr := string(body)
	azErr := extractAzureError(bodyStr)

	switch {
	case resp.StatusCode == 200 && strings.Contains(bodyStr, "<EnumerationResults"):
		r.Public = true
		r.PublicMsg = "ANONYMOUS LISTING — containers exposed"
	case resp.StatusCode == 200:
		r.PublicMsg = "200 OK (unexpected body)"
	case resp.StatusCode == 403:
		if azErr != "" {
			r.PublicMsg = "403 " + azErr
		} else {
			r.PublicMsg = "403 Forbidden (private)"
		}
	case resp.StatusCode == 400:
		if azErr != "" {
			r.PublicMsg = "400 " + azErr
		} else {
			r.PublicMsg = "400 Bad Request"
		}
	case resp.StatusCode == 404:
		r.PublicMsg = "404 " + azErr
	default:
		r.PublicMsg = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	return r
}

func extractAzureError(body string) string {
	start := strings.Index(body, "<Code>")
	end := strings.Index(body, "</Code>")
	if start >= 0 && end > start {
		return body[start+6 : end]
	}
	return ""
}

func formatResult(r Result) string {
	if !r.Exists {
		return fmt.Sprintf("[ ] %s%s", r.Name, blobSuffix)
	}
	tag := "[+]"
	if r.Public {
		tag = "[!]"
	}
	access := r.PublicMsg
	if access == "" {
		access = "no HTTP response"
	}
	return fmt.Sprintf("%s %s%s  ip=%-16s  %s", tag, r.Name, blobSuffix, r.IP, access)
}

func printBanner() {
	fmt.Fprintln(os.Stderr, `
  _                _       _     _       _
 | |__  _ __ _   _| |_ ___| |__ | | ___ | |__
 | '_ \| '__| | | | __/ _ \ '_ \| |/ _ \| '_ \
 | |_) | |  | |_| | ||  __/ |_) | | (_) | |_) |
 |_.__/|_|   \__,_|\__\___|_.__/|_|\___/|_.__/
  Azure Blob Storage Enumerator — bug bounty edition
`)
}
