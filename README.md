# bruteblob

Azure Blob Storage enumerator for bug bounty and security research.

Exploits the fact that `<name>.blob.core.windows.net` only resolves via DNS if the storage account actually exists. Non-existent accounts return NXDOMAIN. This allows fast, low-noise enumeration using a wordlist, followed by an HTTP probe to detect publicly accessible (anonymous) containers.

## How it works

1. **DNS probe** — resolves `<word>.blob.core.windows.net`. Success means the storage account exists.
2. **HTTP probe** — requests `/?comp=list` to check for anonymous container listing and classify the access level based on the HTTP status and Azure error code in the response body.

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
| `-r` | — | File with DNS resolver IPs, one per line (e.g. `8.8.8.8` or `8.8.8.8:53`) |
| `-t` | `50` | Number of concurrent threads |
| `-timeout` | `5` | DNS and HTTP timeout in seconds |
| `-prefix` | — | Prefix to prepend to every word (e.g. `acme-`) |
| `-suffix` | — | Suffix to append to every word (e.g. `-prod`) |
| `-found` | `false` | Only print names that exist (DNS hit) |
| `-no-http` | `false` | Skip HTTP probe, DNS enumeration only |
| `-o` | — | Save hits to output file (only writes DNS hits) |
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

# Custom resolvers (round-robin across all)
./bruteblob -w wordlist.txt -r resolvers.txt -found

# High concurrency with custom resolvers, quiet output for pipelines
./bruteblob -w wordlist.txt -r resolvers.txt -t 200 -q -found | tee results.txt
```

## Output

```
[ ] nonexistent.blob.core.windows.net
[+] target-prod.blob.core.windows.net    ip=20.150.x.x   409 PublicAccessNotPermitted (public access disabled at account level)
[+] target-files.blob.core.windows.net   ip=20.150.x.x   403 AuthenticationFailed
[!] target-backup.blob.core.windows.net  ip=20.60.x.x    ANONYMOUS LISTING — containers exposed
```

| Prefix | Meaning |
|--------|---------|
| `[ ]` | DNS failed — account does not exist |
| `[+]` | Account exists — details from HTTP probe |
| `[!]` | Account exists and **anonymous listing is enabled** (critical finding) |

## HTTP status reference

Azure returns different HTTP status codes and XML error codes depending on the account configuration. The tool extracts the `<Code>` field from the XML body and maps it as follows:

| HTTP | Azure Code | Meaning |
|------|-----------|---------|
| `200` + `<EnumerationResults>` | — | **Public** — anonymous container listing enabled |
| `409` | `PublicAccessNotPermitted` | Account exists, public access **explicitly disabled** at account level |
| `403` | `AuthenticationFailed` | Account exists, authentication required |
| `403` | `AuthorizationFailure` | Account exists, insufficient permissions |
| `404` | `ResourceNotFound` | Account exists, no resource at this path |
| `400` | `InvalidQueryParameterValue` | Account exists, malformed request |

> **Note:** `409 PublicAccessNotPermitted` and `403 AuthenticationFailed` are the two most common responses for existing private accounts. The 409 case indicates the account has the "Allow Blob public access" setting explicitly disabled at the account level — a stronger security posture than a plain 403.

## Resolver file format

One IP per line. Port is optional (defaults to `:53`). Lines starting with `#` are ignored.

```
# resolvers.txt
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
208.67.222.222
208.67.220.220
9.9.9.9
```

Queries are distributed across all resolvers in round-robin order. When `-r` is omitted, the system resolver is used.

## Wordlist tips

- Start with generic storage-related words: `backup`, `assets`, `files`, `data`, `media`, `uploads`, `logs`, `archive`
- Add target-specific terms using `-prefix`/`-suffix`: company name, product names, environment names (`-dev`, `-prod`, `-stg`, `-uat`, `-hml`)
- Combine multiple runs with different prefix/suffix pairs
- Public wordlists like [SecLists](https://github.com/danielmiessler/SecLists) `Discovery/Web-Content/` can be adapted

## Legal

This tool is intended for use on systems you own or have explicit written authorization to test. Unauthorized use against third-party infrastructure may violate computer fraud laws. Always operate within the scope of your bug bounty program's rules of engagement.
