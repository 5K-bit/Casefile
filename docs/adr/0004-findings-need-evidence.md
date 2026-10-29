# ADR 0004: A finding is supported by evidence, or it is a hypothesis

Status: accepted

## Context

The purpose of the tool is a clear investigation: what happened, what supports the conclusion, what remains unknown. A report that states conclusions with nothing behind them is worse than no report.

## Decision

- A finding starts as a hypothesis.
- Marking it `supported` requires at least one supporting link, and the last supporting link of a supported finding cannot be removed.
- Links can name a range of observations, which must exist.
- Evidence may contradict or give context as well as support. The report shows all three and flags a supported finding that has no contradicting evidence recorded.
- Unknowns are first-class: per finding or for the whole case, resolved only with an explanation.
- Casefile does not infer conclusions or score confidence. The analyst decides what the evidence means.

## Consequences

- The tool can prevent an unsupported claim from being marked supported, but not a wrong one.
- Reports always have a "what remains unknown" section, empty or not.
