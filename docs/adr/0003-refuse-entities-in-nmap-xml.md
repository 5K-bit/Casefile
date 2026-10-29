# ADR 0003: Refuse Nmap XML that declares entities

Status: accepted

## Context

Nmap output is untrusted input; it may come from a compromised host or a third party. The standard-library XML parser expands internal entities, which allows "billion laughs" memory exhaustion. Real Nmap output contains only a bare `<!DOCTYPE nmaprun>`, never entity declarations or an internal subset.

## Decision

Before parsing, refuse any file containing `<!ENTITY` or a `<!DOCTYPE ... [` internal subset, case-insensitively. Accept the bare DOCTYPE. Report the refusal as a normal import error.

## Consequences

- No supported use case is lost, because genuine Nmap output never needs these features.
- No dependency on `defusedxml`.
- The check is a screen, not a full XML sandbox; the evidence size cap still bounds memory for very large valid files.
