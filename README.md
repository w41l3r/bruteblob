# bruteblob

Azure Blob Storage enumerator for bug bounty and security research.

Exploits the fact that `<name>.blob.core.windows.net` only resolves via DNS if the storage account actually exists. Non-existent accounts return NXDOMAIN. This allows fast, low-noise enumeration using a wordlist, followed by an HTTP probe to detect publicly accessible (anonymous) containers.

## How it works

1. **DNS probe** — resolves `<word>.blob.core.windows.net`. Success means the storage account exists.
2. **HTTP probe** — requests `/?comp=list` to check for anonymous container listing. A `200 OK` with an `<EnumerationResults>` body means the account is fully public (critical finding).

## Installation

Requires Go 1.18+.

```bash
git clone https://github.com/YOUR_USER/bruteblob
cd bruteblob
go build -o bruteblob .
```

## Usage

```bash
./bruteblob -w wordlist.txt [options]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-w` | *(required)* | Path to wordlist (one name per line) |
| `-t` | `50` | Number of concurrent threads |
| `-timeout` | `5` | DNS and HTTP timeout in seconds |
| `-prefix` | — | Prefix to prepend to every word (e.g. `acme-`) |
| `-suffix` | — | Suffix to append to every word (e.g. `-prod`) |
| `-found` | `false` | Only print names that exist (DNS hit) |
| `-no-http` | `false` | Skip HTTP probe, DNS enumeration only |
| `-o` | — | Save hits to output file |
| `-q` | `false` | Quiet mode — suppress banner and summary |

### Examples

```bash
# Basic enumeration
./bruteblob -w wordlist.txt

# Show only accounts that exist, save to file
./bruteblob -w wordlist.txt -found -o hits.txt

# Target-specific: add company prefix and environment suffixes
./bruteblob -w words.txt -prefix "acme-" -suffix "-prod" -found
./bruteblob -w words.txt -prefix "acme-" -suffix "-dev"  -found
./bruteblob -w words.txt -prefix "acme-" -suffix "-stg"  -found

# DNS-only (faster, no HTTP noise)
./bruteblob -w wordlist.txt -no-http -found

# High concurrency, quiet output for pipelines
./bruteblob -w wordlist.txt -t 200 -q -found | tee results.txt
```

## Output

```
[ ] nonexistent.blob.core.windows.net
[+] target-prod.blob.core.windows.net  ip=20.150.x.x    403 PublicAccessNotPermitted
[!] target-backup.blob.core.windows.net  ip=20.60.x.x   ANONYMOUS LISTING — containers exposed
```

| Prefix | Meaning |
|--------|---------|
| `[ ]` | DNS failed — account does not exist |
| `[+]` | Account exists — private or HTTP details below |
| `[!]` | Account exists and **anonymous listing is enabled** (critical finding) |

### HTTP status reference

| Response | Meaning |
|----------|---------|
| `ANONYMOUS LISTING` | `?comp=list` returned 200 — containers are publicly enumerable |
| `403 PublicAccessNotPermitted` | Account exists, public access disabled at account level |
| `403 AuthenticationFailed` | Account exists, authentication required |
| `404 ResourceNotFound` | Account exists, resource not found at this path |
| `409` | Account exists, conflict (e.g. feature not enabled) |

## Wordlist tips

- Start with generic storage-related words: `backup`, `assets`, `files`, `data`, `media`, `uploads`, `logs`, `archive`
- Add target-specific terms using `-prefix`/`-suffix`: company name, product names, environment names (`-dev`, `-prod`, `-stg`, `-uat`)
- Combine multiple runs with different prefix/suffix pairs
- Public wordlists like [SecLists](https://github.com/danielmiessler/SecLists) `Discovery/Web-Content/` can be adapted

## Legal

This tool is intended for use on systems you own or have explicit written authorization to test. Unauthorized use against third-party infrastructure may violate computer fraud laws. Always operate within the scope of your bug bounty program's rules of engagement.
