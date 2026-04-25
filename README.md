# bruteblob

Azure Blob Storage enumerator for bug bounty and security research.

Exploits the fact that `<name>.blob.core.windows.net` only resolves via DNS if the storage account actually exists. Non-existent accounts return NXDOMAIN. This allows fast, low-noise enumeration using a wordlist, followed by an HTTP probe to classify the access level and an optional container brute-force on every confirmed account.

## How it works

1. **DNS probe** — resolves `<word>.blob.core.windows.net`. Success means the storage account exists.
2. **HTTP probe** — requests `/?comp=list` at account level to classify access (public listing, private, or blocked).
3. **Container brute-force** *(optional, `-containers`)* — for every confirmed account, tests each word in the container wordlist as a container name via `/<container>?restype=container&comp=list`.
4. **Authenticated probe** *(optional, `-auth`)* — runs `az storage container list --auth-mode login` using the active Azure CLI session to test access with real credentials.

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
| `-w` | *(required)* | Wordlist for storage account names (one per line) |
| `-containers` | — | Wordlist for container brute-force on found accounts |
| `-container-threads` | `10` | Concurrent container probes per account |
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

# Only existing accounts, save to file
./bruteblob -w wordlist.txt -found -o hits.txt

# Container brute-force on found accounts
./bruteblob -w wordlist.txt -containers wordlists/containers.txt -found

# Target-specific: prefix + container brute + auth
./bruteblob -w words.txt -prefix "acme-" -containers wordlists/containers.txt -auth -found

# Custom resolvers + container brute, full pipeline
./bruteblob -w wordlist.txt -r resolvers.txt -containers wordlists/containers.txt -t 30 -container-threads 20 -found -o hits.txt -q

# DNS-only (fastest, no HTTP noise)
./bruteblob -w wordlist.txt -no-http -found
```

## Output

### Anonymous mode with container brute-force

```
[ ] nonexistent.blob.core.windows.net
[+] target-prod.blob.core.windows.net      ip=20.150.x.x   409 PublicAccessNotPermitted (public access disabled at account level)
    [!] account-level Block Public Access active — container 403s do not confirm existence
    [BLK] /logs     → 403 PublicAccessNotPermitted (account policy, not container-specific)
    [BLK] /backup   → 403 PublicAccessNotPermitted (account policy, not container-specific)
[+] target-files.blob.core.windows.net     ip=20.150.x.x   403 AuthenticationFailed
    [---] /logs     → 403 AuthorizationFailure
    [---] /backup   → 403 AuthorizationFailure
[!] target-backup.blob.core.windows.net    ip=20.60.x.x    ANONYMOUS LISTING — containers exposed
    [PUB] /data     → PUBLIC — 34 blob(s): report.csv, dump.sql, keys.json, ...
    [PUB] /logs     → PUBLIC — 8 blob(s): app-2024.log, error.log, ...
    [---] /private  → 403 AuthorizationFailure
```

### Authenticated mode (`-auth`) with container brute-force

```
[+] target-files.blob.core.windows.net     ip=20.150.x.x   403 AuthenticationFailed
    [---] /logs    → 403 AuthorizationFailure
    [---] /backup  → 403 AuthorizationFailure
    [AUTH] ACCESS GRANTED — 3 container(s): logs(private), backups(private), exports(blob)
```

### Tag reference

| Tag | Meaning |
|-----|---------|
| `[ ]` | DNS failed — account does not exist |
| `[+]` | Account exists — details from HTTP probe |
| `[!]` | Account exists and **anonymous listing enabled** (critical finding) |
| `[PUB]` | Container exists and is **publicly listable** — blobs exposed |
| `[---]` | Container exists but access denied (403 container-specific) |
| `[BLK]` | 403 caused by **account-level Block Public Access** — cannot confirm container existence |
| `[AUTH] ACCESS GRANTED` | Authenticated access confirmed — container list included |
| `[AUTH] access denied` | Credentials don't have access to this account |

## Container brute-force (`-containers`)

For every storage account confirmed to exist via DNS, the tool probes each word in the container wordlist with:

```
GET https://<account>.blob.core.windows.net/<container>?restype=container&comp=list
```

| Response | Meaning |
|----------|---------|
| `200` + `<EnumerationResults>` | Container exists and is **publicly listable** — blob names and count shown |
| `403` | Container exists, access denied — Azure error code extracted from XML |
| `404` | Container does not exist — silently discarded |
| `409` | Container exists, conflict (e.g. account-level policy) |

### Block Public Access caveat

When the account-level HTTP probe returns `409 PublicAccessNotPermitted`, Azure enforces the block **before** checking container existence. This means every container probe returns 403 regardless of whether the container actually exists, making the results unreliable for confirming existence.

The tool detects this automatically:
- Container results under a blocked account use the `[BLK]` tag instead of `[---]`
- A warning line is printed before the container list: `[!] account-level Block Public Access active — container 403s do not confirm existence`

In this scenario, container brute-force is still useful when combined with `-auth`, since authenticated requests bypass the public access restriction and can confirm existence.

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

> `409 PublicAccessNotPermitted` is a stronger security posture than a plain `403` — it means the "Allow Blob public access" setting is explicitly disabled at the account level, overriding any container-level policy.

## Authenticated mode (`-auth`)

When `-auth` is set, the tool:

1. Checks that `az` is in `PATH` (fails fast with install link if not found).
2. Runs `az account show` — if no active session exists, launches `az login` interactively and waits for completion.
3. After DNS confirms an account exists, runs:
   ```
   az storage container list --account-name <name> --auth-mode login --output json
   ```
4. On success, shows each container name and its public access level (`private`, `blob`, or `container`).
5. On failure, extracts and displays the Azure error code from the CLI output.

**Use cases:**
- Simulate an insider-threat scenario with valid domain credentials
- Test access with a leaked or compromised Azure identity
- Validate the blast radius of a compromised service principal
- Confirm container existence on accounts with account-level Block Public Access (where anonymous probes are unreliable)

> The auth probe runs with a 30-second timeout per account. Use `-t 10` or lower when running with `-auth` to avoid spawning too many concurrent `az` processes.

## Concurrency model

```
outer pool (-t threads)
  └─ per account: DNS probe → HTTP probe
       └─ if account exists + -containers set:
            inner pool (-container-threads per account)
              └─ per container: GET ?restype=container&comp=list
       └─ if -auth set:
            az storage container list (30 s timeout)
```

With `-t 30` and `-container-threads 20`, up to 30 accounts and 600 container requests may be in-flight simultaneously. Tune to target rate limits.

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

### Account names (`-w`)
- Generic: `backup`, `assets`, `files`, `data`, `media`, `uploads`, `logs`, `archive`
- Target-specific with `-prefix`/`-suffix`: `acme-prod`, `acme-backup`, `acme-data-dev`
- Pre-built wordlists: `wordlists/tim-brasil.txt` (560 entries), `wordlists/sek-group.txt` (608 entries)

### Container names (`-containers`)
- Use `wordlists/containers.txt` as a starting point — covers logs, backups, config, secrets, environments, databases, and more (189 entries)
- Add target-specific container names: app name, service name, team names, internal codenames
- Note: Azure container names must be lowercase and 3–63 characters

## Legal

This tool is intended for use on systems you own or have explicit written authorization to test. Unauthorized use against third-party infrastructure may violate computer fraud laws. Always operate within the scope of your bug bounty program's rules of engagement.
