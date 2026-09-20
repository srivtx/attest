# Security Policy

## attest

attest is an offline C2PA verifier. It parses an untrusted contract
(YAML or JSON) and an untrusted CSV dataset, lints the contract, and validates
the data against it. It reports structural and value failures as `DP-*` findings
rather than executing anything from the input.

## Supported versions

The latest commit on `main` is the only supported version. Security fixes land on
`main` and ship in the next tagged release. Older tags do not receive backports.

| Version | Supported |
| --- | --- |
| Latest on `main` | Yes |
| Older tags | No |

## Threat model

- **Offline by design.** attest contains no network code. It never opens a
  socket, resolves a remote reference from a contract, or checks for updates.
- **No telemetry.** Nothing about your contracts, your data, your usage, or your
  machine is collected or transmitted.
- **Files never leave the machine.** Parsing, linting, and validation run
  in-process and locally.
- **Untrusted input.** A contract and a data file are treated as hostile: they
  are parsed as data only. No tags, expressions, or formulas are evaluated, and
  no code path interprets a field as a command.
- **No code execution from input.** YAML is parsed without resolving custom or
  executable tags, JSON is parsed as JSON, and CSV cells are always text.
- **No warehouse connection.** There is no connection string, no driver, and no
  query. attest cannot read from or write to a database.
- **Fail safe.** A contract or data file that cannot be parsed produces a
  `DP-PARSE-000` error and exit code `2`. Unreadable input is never reported as a
  clean run.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings at or above `--fail-on` |
| `1` | At least one finding at or above `--fail-on` |
| `2` | Invalid usage, or input that could not be parsed (`DP-PARSE-000`) |
| `3` | I/O error: an input file could not be read, or a report could not be written |

## Reporting a vulnerability

Report privately through GitHub Security Advisories on the repository:

https://github.com/srivtx/attest/security/advisories/new

Do not open a public issue for a suspected vulnerability. Include a description,
the affected revision, a minimal reproducer (a small contract and CSV where
possible), and any suggested fix. Expect an acknowledgement within a few days.

## Verifying a build

```bash
bun install
bunx tsc --noEmit
bun test
```

This installs the locked dependency set, typechecks in strict mode, and runs the
test suite against the example contract and data. In CI the same gate runs on
every push and pull request.
