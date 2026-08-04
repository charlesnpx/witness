# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately by emailing
`charles.anderson@npxinnovation.ca`. Include the affected command or contract,
the impact, reproduction steps, and any suggested mitigation. Do not include
live credentials or sensitive third-party data.

Please avoid opening a public issue until the report has been assessed and a
coordinated disclosure plan has been agreed.

## Supported versions

Security fixes are made on `main`. This is early-stage `v0.x` software and no
older release line currently receives long-term security support.

## Trust boundaries

Witness assumes a trusted local caller. In particular:

- `witness-harness` executes caller-selected programs with structured argv but
  with the current user's operating-system privileges.
- The harness does not provide network, container, kernel, or same-user process
  isolation. Its containment record is evidence about an execution, not proof
  of a stronger sandbox.
- State directories, configuration, retained relay observations, and output
  directories are inside the local-caller trust boundary.
- The execution environment supplied to the harness is recorded in the signed
  receipt. It must not contain credentials or other secrets.
- Receipts can capture stdout, stderr, source inventories, and produced files.
  Use private directories and a restrictive umask on shared systems.
- HMAC authenticates a receipt to a caller-held key; it does not make an
  untrusted command safe or independently reproduce the execution.
- Validation and execution assume no hostile concurrent mutation. A local
  attacker able to modify trusted state or output paths during a run is outside
  the supported threat model.

Do not run Witness or its harness on untrusted requests without an independent
OS-level sandbox appropriate to your threat model.
