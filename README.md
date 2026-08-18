# release-oras-spike

Throwaway scratch repository for `meigma/release` architecture **spike B**:
does `oras-go` v2 reproduce the current ORAS 1.3.3 publication contract on GHCR,
and can all trust metadata precede public tags?

Not a product. Safe to delete once the spike verdict is recorded in the
`meigma/release` session journal.

- `main.go`, `layout.go`, `publish.go` — probe program. `-mode=local` runs
  everything against an in-process registry with no network.
- `.github/workflows/spike.yml` — GHCR phase: publish by digest, sign, attest
  three subjects, inspect referrers, then tag last and re-verify.
