# DNSSEC Verification Tool

This .NET console application queries DNS records and validates their DNSSEC signatures. By default, it performs a fully-recursive lookup using the built-in root trust anchors provided by `ARSoft.Tools.Net`. You can also point it at one or more upstream DNS servers and the tool will perform DNSSEC validation of the responses it receives from those servers.

## Prerequisites

- .NET SDK 9.0 or later (includes the `dotnet` CLI)

## Building and Running

```bash
dotnet build
dotnet run -- <domain> [options]
```

The double dash (`--`) separates `dotnet run` arguments from the tool's own arguments.

## Command-Line Options

| Option | Description |
| ------ | ----------- |
| `--type`, `-t` | DNS record type(s) to query (default: `A`). Accepts comma-separated values or repeated flags. |
| `--class`, `-c` | DNS record class. Accepts `IN`, `CH`, `HS`, or any value from `ARSoft.Tools.Net.Dns.RecordClass` (default: `IN`). |
| `--server`, `-s` | One or more comma-separated DNS server IPs to query instead of performing full recursion. The responses are still validated with DNSSEC. |
| `--format`, `-f` | Output format. Accepted values: `text` (default) or `json`. |
| `--output`, `-o` | Write CLI output to the specified file in addition to stdout. |
| `--append` | Append to the output file instead of overwriting (requires `--output`). |
| `--quiet`, `-q` | Suppress stdout output (useful with `--output`). |
| `--require-signed` | Treat unsigned DNSSEC responses as failures (non-zero exit). |
| `--timeout` | Query timeout in milliseconds. Applies to both recursive and stub modes. |
| `--overall-timeout` | Cancels the entire run if the total duration exceeds the given milliseconds. |
| `--help`, `-h` | Shows usage information. |

## Examples

Validate the `A` record for `example.com` using the built-in recursive resolver:

```bash
dotnet run -- example.com
```

Validate an `AAAA` record using Cloudflare's resolver with a custom timeout:

```bash
dotnet run -- example.com --type AAAA --server 1.1.1.1 --timeout 3000
```

Query both `A` and `AAAA` records in a single run:

```bash
dotnet run -- example.com --type A,AAAA
```

Emit JSON for downstream tooling:

```bash
dotnet run -- example.com --type DS --format json | jq
```

Abort the run if combined lookups exceed 5 seconds:

```bash
dotnet run -- example.com --type A,AAAA --overall-timeout 5000
```

Persist JSON results to a file:

```bash
dotnet run -- example.com --type DS --format json --output results.json
```

Run quietly while saving output:

```bash
dotnet run -- example.com --type DS --format json --output results.json --quiet
```

Append results to an existing log:

```bash
dotnet run -- example.com --type A --output history.log --append
```

Fail if responses are not DNSSEC signed:

```bash
dotnet run -- example.com --type A --require-signed
```

## Tests

End-to-end tests exercise the CLI against live DNS resolvers. Run them with:

```bash
dotnet test
```

The suite verifies signed vs. unsigned domains, file output/quiet combinations, and `--require-signed` behaviour. Tests rely on public DNS infrastructure and require network access.

## How It Works

- The application uses `SelfValidatingInternalDnsSecStubResolver` when `--server` is provided, otherwise it falls back to `DnsSecRecursiveDnsResolver` with the default root trust anchors.
- `ResolveSecure<T>()` is used to retrieve records along with their DNSSEC validation status.
- Exit codes: `0` for successful validation or unsigned-but-validated responses, `2` for DNSSEC validation failures, and `99` for unexpected errors.
- Additional exit codes: `5` when writing to an output file fails, `6` when `--append` is used without `--output`, `7` when `--quiet` is used without `--output`.
  - Exit code `8` when `--require-signed` is set and any answer validates as unsigned.

## Notes

- When DNSSEC validation fails, the tool prints the failure reason and returns a non-zero exit code.
- DNS zones without DNSSEC return `Unsigned` and the tool will still exit with `0`, indicating the response validated according to DNSSEC opt-out rules.
- The `--overall-timeout` limit is evaluated after each record-type query finishes. A single long-running lookup may exceed the limit before cancellation can be observed.
- Default per-query timeouts: 10 seconds for stub resolver mode, 15 seconds for recursive mode when `--timeout` is not provided.
