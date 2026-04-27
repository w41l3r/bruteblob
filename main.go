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

// ── Types ─────────────────────────────────────────────────────────────────────

type azContainer struct {
	Name       string `json:"name"`
	Properties struct {
		PublicAccess string `json:"publicAccess"`
	} `json:"properties"`
}

// ContainerResult holds the outcome of probing one container within an account.
type ContainerResult struct {
	Name        string
	IsPublic    bool
	Denied      bool
	BlobCount    int
	SampleBlobs  []string
	Msg          string // Azure error code when denied
	WriteAllowed bool
	WriteMsg     string
}

type Result struct {
	Name             string
	Exists           bool
	IP               string
	Public           bool
	PublicMsg        string
	AccountBlocked   bool // account-level Block Public Access (409 PublicAccessNotPermitted)
	// container brute-force
	Containers []ContainerResult
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

// ── Flags ─────────────────────────────────────────────────────────────────────

var (
	flagWordlist      = flag.String("w", "", "wordlist for storage account names (one per line)")
	flagContainers    = flag.String("containers", "", "wordlist for container brute-force on found accounts")
	flagContThreads   = flag.Int("container-threads", 10, "concurrent container probes per account")
	flagResolvers     = flag.String("r", "", "file with DNS resolver IPs (one per line, e.g. 8.8.8.8 or 8.8.8.8:53)")
	flagThreads       = flag.Int("t", 50, "concurrent threads")
	flagOutput        = flag.String("o", "", "output file for hits (optional)")
	flagTimeout       = flag.Int("timeout", 5, "DNS/HTTP timeout in seconds")
	flagOnlyFound     = flag.Bool("found", false, "only print names that exist (DNS hit)")
	flagQuiet         = flag.Bool("q", false, "suppress banner and summary")
	flagPrefix        = flag.String("prefix", "", "prefix to prepend to every word (e.g. acme-)")
	flagSuffix        = flag.String("suffix", "", "suffix to append to every word (e.g. -prod)")
	flagNoHTTP        = flag.Bool("no-http", false, "skip HTTP probe (DNS enumeration only)")
	flagAuth          = flag.Bool("auth", false, "authenticated mode: use 'az' CLI to test access with Azure credentials")
	flagCheckWrite    = flag.Bool("check-write", false, "test anonymous write access on discovered containers (PUT + immediate DELETE)")
)

// ── Main ──────────────────────────────────────────────────────────────────────

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

	// Load container wordlist once — shared across all workers.
	var containerNames []string
	if *flagContainers != "" {
		var err error
		containerNames, err = loadWordlist(*flagContainers)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] cannot open containers wordlist: %v\n", err)
			os.Exit(1)
		}
		if !*flagQuiet {
			fmt.Fprintf(os.Stderr, "[*] container wordlist loaded: %d entries\n", len(containerNames))
		}
	}

	accounts, err := loadWordlist(*flagWordlist)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] cannot open wordlist: %v\n", err)
		os.Exit(1)
	}

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
				results <- probe(name, containerNames, pool.next(), httpClient, timeout)
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	go func() {
		for _, name := range accounts {
			jobs <- *flagPrefix + name + *flagSuffix
		}
		close(jobs)
	}()

	total, found, public, authOK, writeOK := 0, 0, 0, 0, 0
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
		for _, cr := range r.Containers {
			if cr.WriteAllowed {
				writeOK++
			}
		}
		out := formatResult(r)
		fmt.Println(out)
		if outFile != nil && r.Exists {
			fmt.Fprintln(outFile, out)
		}
	}

	if !*flagQuiet {
		summary := fmt.Sprintf("\n[*] done — checked: %d | found: %d | public: %d", total, found, public)
		if *flagCheckWrite {
			summary += fmt.Sprintf(" | write-access: %d", writeOK)
		}
		if *flagAuth {
			summary += fmt.Sprintf(" | auth-access: %d", authOK)
		}
		fmt.Fprintln(os.Stderr, summary)
	}
}

// ── DNS + HTTP probe ──────────────────────────────────────────────────────────

func probe(name string, containerNames []string, resolver *net.Resolver, client *http.Client, timeout time.Duration) Result {
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

	if r.Exists && len(containerNames) > 0 {
		r.Containers = probeContainers(name, containerNames, client, *flagContThreads)
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
		r.AccountBlocked = true
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

// ── Container brute-force ─────────────────────────────────────────────────────

// probeContainers tests each name as an Azure Blob container within the account.
// It sends:
//
//	GET https://<account>.blob.core.windows.net/<container>?restype=container&comp=list
//
// A 404 means the container does not exist and is silently discarded.
// A 403 means it exists but access is denied.
// A 200 with <EnumerationResults> means it exists and is publicly listable.
func probeContainers(accountName string, names []string, client *http.Client, threads int) []ContainerResult {
	jobs := make(chan string, len(names))
	for _, n := range names {
		jobs <- n
	}
	close(jobs)

	resultsCh := make(chan ContainerResult, len(names))

	if threads > len(names) {
		threads = len(names)
	}

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for containerName := range jobs {
				cr := probeOneContainer(accountName, containerName, client)
				if cr.IsPublic || cr.Denied {
					resultsCh <- cr
				}
			}
		}()
	}

	wg.Wait()
	close(resultsCh)

	var out []ContainerResult
	for cr := range resultsCh {
		out = append(out, cr)
	}
	return out
}

func probeOneContainer(accountName, containerName string, client *http.Client) ContainerResult {
	cr := ContainerResult{Name: containerName}

	url := fmt.Sprintf("https://%s%s/%s?restype=container&comp=list",
		accountName, blobSuffix, containerName)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return cr
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	bodyStr := string(body)
	azErr := extractAzureError(bodyStr)

	switch {
	case resp.StatusCode == 200 && strings.Contains(bodyStr, "<EnumerationResults"):
		cr.IsPublic = true
		cr.BlobCount = strings.Count(bodyStr, "<Blob>")
		cr.SampleBlobs = extractBlobNames(bodyStr, 5)

	case resp.StatusCode == 403:
		cr.Denied = true
		if azErr != "" {
			cr.Msg = azErr
		} else {
			cr.Msg = "AccessDenied"
		}

	case resp.StatusCode == 409:
		// Container exists but has a conflict (e.g. account-level block).
		cr.Denied = true
		if azErr != "" {
			cr.Msg = azErr
		} else {
			cr.Msg = strings.TrimPrefix(resp.Status, "409 ")
		}

	// 404 = container does not exist → drop silently (cr has zero values).
	}

	if (cr.IsPublic || cr.Denied) && *flagCheckWrite {
		cr.WriteAllowed, cr.WriteMsg = probeWriteBlob(accountName, containerName, client)
	}

	return cr
}

// probeWriteBlob tests whether anonymous PUT is allowed on the container.
// On HTTP 201 it immediately DELETEs the blob to clean up.
func probeWriteBlob(accountName, containerName string, client *http.Client) (bool, string) {
	blobName := fmt.Sprintf("bruteblob-writetest-%d.txt", time.Now().UnixNano())
	targetURL := fmt.Sprintf("https://%s%s/%s/%s", accountName, blobSuffix, containerName, blobName)
	payload := "security-research-write-test"

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, targetURL,
		strings.NewReader(payload))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("x-ms-blob-type", "BlockBlob")
	req.ContentLength = int64(len(payload))

	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode == 201 {
		delReq, _ := http.NewRequestWithContext(context.Background(), http.MethodDelete, targetURL, nil)
		delResp, err := client.Do(delReq)
		if err == nil {
			io.Copy(io.Discard, delResp.Body)
			delResp.Body.Close()
		}
		return true, "write access confirmed — blob uploaded and deleted"
	}

	return false, ""
}

func extractBlobNames(body string, max int) []string {
	var names []string
	rest := body
	for len(names) < max {
		s := strings.Index(rest, "<Name>")
		e := strings.Index(rest, "</Name>")
		if s < 0 || e < 0 || e <= s {
			break
		}
		names = append(names, rest[s+6:e])
		rest = rest[e+7:]
	}
	return names
}

// ── Authenticated probe (az CLI) ──────────────────────────────────────────────

func probeAz(r *Result, accountName string) {
	r.AuthChecked = true

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

func checkAzCLI() error {
	if _, err := exec.LookPath("az"); err != nil {
		return fmt.Errorf("'az' CLI not found in PATH\nInstall: https://aka.ms/installazurecli")
	}
	return nil
}

func ensureAzLogin(quiet bool) error {
	cmd := exec.Command("az", "account", "show", "--output", "none")
	if err := cmd.Run(); err == nil {
		if !quiet {
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

func extractAzError(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "unknown error"
	}
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
	line := firstLine(raw)
	return strings.TrimPrefix(line, "ERROR: ")
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

func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, scanner.Err()
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

func firstLine(s string) string {
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		return strings.TrimSpace(s[:idx])
	}
	return strings.TrimSpace(s)
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

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s%s  ip=%-16s  %s", tag, r.Name, blobSuffix, r.IP, access))

	if len(r.Containers) > 0 && r.AccountBlocked {
		sb.WriteString("\n    [!] account-level Block Public Access active — container 403s do not confirm existence")
	}
	for _, cr := range r.Containers {
		sb.WriteString("\n    " + formatContainerResult(cr, r.AccountBlocked))
		if cr.WriteAllowed {
			sb.WriteString(fmt.Sprintf("\n    [WR!] /%s  → %s", cr.Name, cr.WriteMsg))
		}
	}

	if r.AuthChecked {
		if r.AuthOK {
			if len(r.AuthContainers) == 0 {
				sb.WriteString("\n    [AUTH] ACCESS GRANTED — no containers found (account may be empty)")
			} else {
				parts := make([]string, 0, len(r.AuthContainers))
				for _, c := range r.AuthContainers {
					acc := c.Properties.PublicAccess
					if acc == "" {
						acc = "private"
					}
					parts = append(parts, fmt.Sprintf("%s(%s)", c.Name, acc))
				}
				sb.WriteString(fmt.Sprintf("\n    [AUTH] ACCESS GRANTED — %d container(s): %s",
					len(r.AuthContainers), strings.Join(parts, ", ")))
			}
		} else {
			sb.WriteString("\n    [AUTH] access denied — " + r.AuthMsg)
		}
	}

	return sb.String()
}

func formatContainerResult(cr ContainerResult, accountBlocked bool) string {
	switch {
	case cr.IsPublic:
		if cr.BlobCount == 0 {
			return fmt.Sprintf("[PUB] /%s  → container is public (empty)", cr.Name)
		}
		line := fmt.Sprintf("[PUB] /%s  → PUBLIC — %d blob(s)", cr.Name, cr.BlobCount)
		if len(cr.SampleBlobs) > 0 {
			line += ": " + strings.Join(cr.SampleBlobs, ", ")
		}
		return line
	case cr.Denied && accountBlocked:
		// 403 caused by account-level policy — cannot confirm container existence.
		return fmt.Sprintf("[BLK] /%s  → 403 %s (account policy, not container-specific)", cr.Name, cr.Msg)
	case cr.Denied:
		return fmt.Sprintf("[---] /%s  → 403 %s", cr.Name, cr.Msg)
	default:
		return fmt.Sprintf("[ c ] /%s  → not found", cr.Name)
	}
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
