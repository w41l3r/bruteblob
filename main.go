package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const blobSuffix = ".blob.core.windows.net"

type azContainer struct {
	Name       string `json:"name"`
	Properties struct {
		PublicAccess string `json:"publicAccess"` // "blob", "container", or ""
	} `json:"properties"`
}

type Result struct {
	Name      string
	Exists    bool
	IP        string
	Public    bool
	PublicMsg string
	// authenticated probe
	AuthChecked    bool
	AuthOK         bool
	AuthContainers []azContainer
	AuthMsg        string
}

// resolverPool distributes DNS queries across multiple resolvers in round-robin.
type resolverPool struct {
	resolvers []*net.Resolver
	counter   atomic.Uint64
}

func (p *resolverPool) next() *net.Resolver {
	idx := p.counter.Add(1) - 1
	return p.resolvers[idx%uint64(len(p.resolvers))]
}

var (
	flagWordlist  = flag.String("w", "", "wordlist file (one name per line)")
	flagResolvers = flag.String("r", "", "file with DNS resolver IPs (one per line, e.g. 8.8.8.8 or 8.8.8.8:53)")
	flagThreads   = flag.Int("t", 50, "concurrent threads")
	flagOutput    = flag.String("o", "", "output file for hits (optional)")
	flagTimeout   = flag.Int("timeout", 5, "DNS/HTTP timeout in seconds")
	flagOnlyFound = flag.Bool("found", false, "only print names that exist (DNS hit)")
	flagQuiet     = flag.Bool("q", false, "suppress banner and summary")
	flagPrefix    = flag.String("prefix", "", "prefix to prepend to every word (e.g. acme-)")
	flagSuffix    = flag.String("suffix", "", "suffix to append to every word (e.g. -prod)")
	flagNoHTTP    = flag.Bool("no-http", false, "skip HTTP probe (DNS enumeration only)")
	flagAuth      = flag.Bool("auth", false, "authenticated mode: use 'az' CLI to test access with Azure credentials")
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

	if *flagAuth {
		if err := checkAzCLI(); err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			os.Exit(1)
		}
		if err := ensureAzLogin(*flagQuiet); err != nil {
			fmt.Fprintf(os.Stderr, "[!] az login failed: %v\n", err)
			os.Exit(1)
		}
		if !*flagQuiet {
			fmt.Fprintln(os.Stderr, "[*] auth mode enabled — authenticated probes will run on DNS hits")
		}
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

	pool, err := buildResolverPool(*flagResolvers, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
	if !*flagQuiet {
		fmt.Fprintf(os.Stderr, "[*] resolvers loaded: %d\n", len(pool.resolvers))
	}

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
				results <- probe(name, pool.next(), httpClient, timeout)
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
			jobs <- *flagPrefix + line + *flagSuffix
		}
		close(jobs)
	}()

	total, found, public, authOK := 0, 0, 0, 0
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
		if r.AuthOK {
			authOK++
		}
		lines := formatResult(r)
		fmt.Println(lines)
		if outFile != nil && r.Exists {
			fmt.Fprintln(outFile, lines)
		}
	}

	if !*flagQuiet {
		summary := fmt.Sprintf("\n[*] done — checked: %d | found: %d | public: %d", total, found, public)
		if *flagAuth {
			summary += fmt.Sprintf(" | auth-access: %d", authOK)
		}
		fmt.Fprintln(os.Stderr, summary)
	}
}

// ── DNS + HTTP probe ──────────────────────────────────────────────────────────

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

	if !*flagNoHTTP {
		probeHTTP(&r, host, client)
	}

	if *flagAuth {
		probeAz(&r, name)
	}

	return r
}

func probeHTTP(r *Result, host string, client *http.Client) {
	url := fmt.Sprintf("https://%s/?comp=list", host)
	resp, err := client.Get(url)
	if err != nil {
		return
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
	case resp.StatusCode == 409 && azErr == "PublicAccessNotPermitted":
		r.PublicMsg = "409 PublicAccessNotPermitted (public access disabled at account level)"
	case resp.StatusCode == 409:
		if azErr != "" {
			r.PublicMsg = "409 " + azErr
		} else {
			r.PublicMsg = "409 " + strings.TrimPrefix(resp.Status, "409 ")
		}
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
}

// ── Authenticated probe (az CLI) ──────────────────────────────────────────────

func probeAz(r *Result, accountName string) {
	r.AuthChecked = true

	// az CLI startup is slow; give it a generous timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "az", "storage", "container", "list",
		"--account-name", accountName,
		"--auth-mode", "login",
		"--output", "json")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		r.AuthMsg = extractAzError(stderr.String())
		return
	}

	r.AuthOK = true
	_ = json.Unmarshal(stdout.Bytes(), &r.AuthContainers)
}

// checkAzCLI verifies that the az CLI is available in PATH.
func checkAzCLI() error {
	if _, err := exec.LookPath("az"); err != nil {
		return fmt.Errorf("'az' CLI not found in PATH\nInstall: https://aka.ms/installazurecli")
	}
	return nil
}

// ensureAzLogin checks for an active session and runs 'az login' if needed.
func ensureAzLogin(quiet bool) error {
	cmd := exec.Command("az", "account", "show", "--output", "none")
	if err := cmd.Run(); err == nil {
		if !quiet {
			// Show which account/tenant is active
			out, _ := exec.Command("az", "account", "show",
				"--query", "{user:user.name,subscription:name}",
				"--output", "tsv").Output()
			parts := strings.Fields(strings.TrimSpace(string(out)))
			if len(parts) >= 2 {
				fmt.Fprintf(os.Stderr, "[*] az: already authenticated as %s (subscription: %s)\n", parts[0], parts[1])
			} else {
				fmt.Fprintln(os.Stderr, "[*] az: already authenticated")
			}
		}
		return nil
	}

	fmt.Fprintln(os.Stderr, "[*] az: no active session — launching 'az login'...")
	login := exec.Command("az", "login")
	login.Stdin = os.Stdin
	login.Stdout = os.Stdout
	login.Stderr = os.Stderr
	return login.Run()
}

// extractAzError pulls a clean error message out of az CLI stderr output,
// which can be plain text ("ERROR: ...") or JSON.
func extractAzError(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "unknown error"
	}
	// az sometimes emits JSON errors to stderr
	var obj struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Error   struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(raw), &obj); err == nil {
		if obj.Error.Code != "" {
			return obj.Error.Code + ": " + firstLine(obj.Error.Message)
		}
		if obj.Code != "" {
			return obj.Code + ": " + firstLine(obj.Message)
		}
	}
	// Plain text: strip "ERROR: " prefix and return first line
	line := firstLine(raw)
	line = strings.TrimPrefix(line, "ERROR: ")
	return line
}

func firstLine(s string) string {
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		return strings.TrimSpace(s[:idx])
	}
	return strings.TrimSpace(s)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func extractAzureError(body string) string {
	start := strings.Index(body, "<Code>")
	end := strings.Index(body, "</Code>")
	if start >= 0 && end > start {
		return body[start+6 : end]
	}
	return ""
}

func buildResolverPool(path string, timeout time.Duration) (*resolverPool, error) {
	if path == "" {
		return &resolverPool{resolvers: []*net.Resolver{{PreferGo: true}}}, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open resolver file: %w", err)
	}
	defer f.Close()

	var resolvers []*net.Resolver
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		addr := strings.TrimSpace(scanner.Text())
		if addr == "" || strings.HasPrefix(addr, "#") {
			continue
		}
		resolvers = append(resolvers, makeResolver(addr, timeout))
	}

	if len(resolvers) == 0 {
		return nil, fmt.Errorf("resolver file is empty or has no valid entries")
	}
	return &resolverPool{resolvers: resolvers}, nil
}

func makeResolver(addr string, timeout time.Duration) *net.Resolver {
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

// ── Output ────────────────────────────────────────────────────────────────────

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
	line := fmt.Sprintf("%s %s%s  ip=%-16s  %s", tag, r.Name, blobSuffix, r.IP, access)

	if !r.AuthChecked {
		return line
	}

	var authLine string
	if r.AuthOK {
		if len(r.AuthContainers) == 0 {
			authLine = "    [AUTH] ACCESS GRANTED — no containers found (account may be empty)"
		} else {
			parts := make([]string, 0, len(r.AuthContainers))
			for _, c := range r.AuthContainers {
				access := c.Properties.PublicAccess
				if access == "" {
					access = "private"
				}
				parts = append(parts, fmt.Sprintf("%s(%s)", c.Name, access))
			}
			authLine = fmt.Sprintf("    [AUTH] ACCESS GRANTED — %d container(s): %s",
				len(r.AuthContainers), strings.Join(parts, ", "))
		}
	} else {
		authLine = "    [AUTH] access denied — " + r.AuthMsg
	}

	return line + "\n" + authLine
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
