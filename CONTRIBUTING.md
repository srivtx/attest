# Contributing to attest

Thanks for helping make data contracts checkable. This document covers what you
need to build, test, and submit a change.

## Development setup

attest targets [Bun](https://bun.sh) and TypeScript in strict mode.

```bash
git clone https://github.com/srivtx/attest.git
cd attest
bun install
```

Run the CLI from source while you work:

```bash
bun run src/cli.ts lint --contract spec/example-contract.yaml
bun run src/cli.ts check --contract spec/example-contract.yaml --data spec/example-data.csv
```

## The gate

Every pull request must pass the same gate CI runs:

```bash
bunx tsc --noEmit && bun test
```

Do not open a PR with a red typecheck or a failing test. Fix the cause rather
than disabling a rule or a test.

## Spec and fixtures

`spec/` holds the contract and data the tests and the docs run against:

- `spec/SPEC.md` — the normative description of the supported ODCS subset, the
  rules, and the CSV parsing rules. Change behavior and this document together.
- `spec/example-contract.yaml` — an `orders` contract that exercises every
  supported field.
- `spec/example-data.csv` — CSV that is valid RFC 4180 and deliberately violates
  several rules. `SPEC.md` lists the expected findings.

When you add a rule, add a case that exercises it and assert on the emitted rule
code. Contract linting belongs with the lint tests; dataset validation belongs
with the validation tests; CLI and exit-code behavior belongs with the CLI tests.
Keep the CSV parser as its own unit so parsing can be tested without a contract.

## Code style

- Strict TypeScript. No `any` to silence a type error, no non-null assertions to
  dodge null checks.
- `src/` is browser-safe: no `node:` imports and no Node-only globals, because it
  is bundled for the browser. Node-only code belongs in `src/cli.ts`.
- No new runtime dependencies without discussion in an issue first. The offline
  and dependency-light posture is a feature.
- No network access, ever. Parsing, linting, and validation are local operations.
- Keep contract parsing, contract linting, CSV parsing, and dataset validation in
  separate modules so each stays testable on its own.
- Match the surrounding style; keep modules small and focused.
- No comments unless they explain something non-obvious.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <summary>

fix(csv): treat a lone CR as a record terminator
feat(rules): flag unknown formats with DP-107
test(validation): cover the empty-value skip rule
docs: document the suppression cap
```

Common types: `feat`, `fix`, `test`, `docs`, `refactor`, `chore`. Useful scopes:
`rules`, `csv`, `validation`, `lint`, `cli`, `mcp`, `spec`.

## Pull request checklist

- [ ] Tests added or updated for the change.
- [ ] `bunx tsc --noEmit` is clean.
- [ ] `bun test` passes.
- [ ] Docs (`README.md` or `spec/SPEC.md`) updated when behavior or flags change.
- [ ] Commit messages follow Conventional Commits.
