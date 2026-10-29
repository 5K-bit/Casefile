# ADR 0003: Refuse Nmap XML that declares entities

Status: accepted

## Context

Nmap output is untrusted input; it may come from a compromised host or a third party. The standard-library XML parser expands internal entities, which allows "billion laughs" memory exhaustion. Real Nmap output contains only a bare `<!DOCTYPE nmaprun>`, never entity declarations or an internal subset.

## Decision

Before building a tree, run the file through expat with handlers that raise on any entity declaration, on a `<!DOCTYPE ... [` internal subset, and on any external entity reference. Accept the bare DOCTYPE. Report the refusal as a normal import error.

The check is made by the parser, not by matching bytes. An earlier byte-pattern screen was bypassed by a UTF-16 document, whose `<!ENTITY` is not the ASCII byte sequence the pattern looked for, while expat decoded it and expanded the entity. Using expat for the screen means the screen and the real parse see the same decoded text whatever the encoding. Encodings expat cannot decode are reported as invalid XML.

## Consequences

- No supported use case is lost, because genuine Nmap output never needs these features.
- No dependency on `defusedxml`.
- The file is parsed twice (a cheap handler-only pass, then the tree). Both passes are expat, so they cannot disagree about encoding.
- The check is a screen, not a full XML sandbox; the evidence size cap still bounds memory for very large valid files.
