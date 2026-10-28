# Security

## Reporting a vulnerability

Please do **not** open a public issue for anything that could put a household at risk: a
mandate that validates although it should not, an evaluation that allows what the
specification denies, a digest, signature or audit log check that accepts what it should
reject.

Report it privately through this repository on GitHub: **Security → Report a vulnerability**
(GitHub private vulnerability reporting). I answer as soon as possible, aiming for a week,
and disclose in a coordinated manner.

## Scope

In scope: the code in `src/`. If the cause is an ambiguity or a flaw in the specification
itself, report it to the [specification](https://github.com/home-mandate/spec/security)
as well: it affects every implementation.

## How fixes are made

Every fix starts with a test that fails. If the specification's conformance cases did not
catch the flaw, a case is proposed for the specification too.
