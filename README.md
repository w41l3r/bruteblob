# bruteblob

Azure Blob Storage enumerator for bug bounty and security research.

Exploits the fact that `<name>.blob.core.windows.net` only resolves via DNS if the storage account actually exists. Non-existent accounts return NXDOMAIN. This allows fast, low-noise enumeration using a wordlist, followed by an HTTP probe to detect publicly accessible (anonymous) containers.

## How it works

1. **DNS probe** — resolves `<word>.blob.core.windows.net`. Success means the storage account exists.
2. **HTTP probe** — requests `/?comp=list` to check for anonymous container listing and classify the access level based on the HTTP status and Azure error code in the response body.
3. **Authenticated probe** *(optional, `-auth`)* — for each DNS hit, runs `az storage container list --auth-mode login` using the active Azure CLI session to test access with real credentials.

## Installation

Requires Go 1.18+.

```bash
git clone https://github.com/YOUR_USER/bruteblob
cd bruteblob
go build -o bruteblob .
```

For authenticated mode, also install the [Azure CLI](https://aka.ms/installazurecli).

## Usage

```bash
./bruteblob -w wordlist.txt [options]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-w` | *(required)* | Path to wordlist (one name per line) |
| `-r` | — | File with DNS resolver IPs, one per line (e.g. `8.8.8.8` or `8.8.8.8:53`) |
| `-t` | `50` | Concurrent threads |
| `-timeout` | `5` | DNS/HTTP timeout in seconds (auth probe uses a fixed 30 s) |
| `-prefix` | — | Prefix to prepend to every word (e.g. `acme-`) |
| `-suffix` | — | Suffix to append to every word (e.g. `-prod`) |
| `-found` | `false` | Only print names that exist (DNS hit) |
| `-no-http` | `false` | Skip HTTP probe, DNS enumeration only |
| `-auth` | `false` | Authenticated mode: test access via `az` CLI credentials |
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

# Authenticated mode (insider-threat / leaked credential simulation)
./bruteblob -w wordlist.txt -auth -found

# Full pipeline: custom resolvers + auth + output file
./bruteblob -w wordlist.txt -r resolvers.txt -auth -found -o hits.txt
```

## Output

### Anonymous mode (default)

```
[ ] nonexistent.blob.core.windows.net
[+] target-prod.blob.core.windows.net    ip=20.150.x.x   409 PublicAccessNotPermitted (public access disabled at account level)
[+] target-files.blob.core.windows.net   ip=20.150.x.x   403 AuthenticationFailed
[!] target-backup.blob.core.windows.net  ip=20.60.x.x    ANONYMOUS LISTING — containers exposed
```

### Authenticated mode (`-auth`)

Each DNS hit gets an additional `[AUTH]` line:

```
[+] target-prod.blob.core.windows.net    ip=20.150.x.x   409 PublicAccessNotPermitted (public access disabled at account level)
    [AUTH] access denied — AuthorizationPermissionMismatch: ...
[+] target-files.blob.core.windows.net   ip=20.150.x.x   403 AuthenticationFailed
    [AUTH] ACCESS GRANTED — 3 container(s): logs(private), backups(private), exports(blob)
```

| Output tag | Meaning |
|------------|---------|
| `[ ]` | DNS failed — account does not exist |
| `[+]` | Account exists — details from HTTP probe |
| `[!]` | Account exists and **anonymous listing enabled** (critical finding) |
| `[AUTH] ACCESS GRANTED` | Authenticated access confirmed — container list included |
| `[AUTH] access denied` | Credentials don't have access to this account |

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

> **Note:** `409 PublicAccessNotPermitted` and `403 AuthenticationFailed` are the two most common responses for existing private accounts. The 409 indicates the "Allow Blob public access" setting is explicitly disabled at the account level — a stronger security posture than a plain 403.

## Authenticated mode (`-auth`)

When `-auth` is set, the tool:

1. Checks that `az` is in `PATH` (fails fast if not found).
2. Runs `az account show` — if no active session exists, launches `az login` interactively and waits for completion.
3. After DNS confirms an account exists, runs:
   ```
   az storage container list --account-name <name> --auth-mode login --output json
   ```
4. On success, parses the container list and shows each container name and its public access level (`private`, `blob`, or `container`).
5. On failure, extracts and displays the Azure error code from the CLI output.

**Use cases:**
- Simulate an insider-threat scenario with valid domain credentials
- Test access with a leaked or compromised Azure identity
- Validate the blast radius of a compromised service principal

> The auth probe runs with a 30-second timeout per account to accommodate `az` CLI startup overhead. Use a lower `-t` value (e.g. `-t 10`) when running with `-auth` to avoid spawning too many concurrent `az` processes.

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
