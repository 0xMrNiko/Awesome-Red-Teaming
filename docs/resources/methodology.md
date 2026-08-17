# Red Teaming Methodology

[← Home](../../README.md) · [Topic index](../INDEX.md)

Use this repository as a map, not as a checklist. Good red-team work starts with scope, assumptions, evidence handling, and clear stop conditions.

## Engagement flow

1. Scope: targets, dates, identities, allowed tooling, excluded systems, reporting path, emergency contacts.
2. Threat model: realistic adversary goals, initial access paths, crown jewels, trust boundaries, detection assumptions.
3. Recon: external footprint, identity surface, exposed services, SaaS/cloud assets, third parties.
4. Initial access simulation: phishing, web, VPN, exposed services, cloud identities, supply chain, or physical paths only where authorized.
5. Execution and persistence: controlled proofs, minimal blast radius, documented cleanup.
6. Lateral movement: prove impact with least privilege and least noise.
7. Objective actions: demonstrate business risk without unnecessary data access.
8. Reporting: attack path, evidence, affected controls, root cause, fix priority, and detection opportunities.

## Evidence discipline

- Record commands, timestamps, hostnames, account names, source IPs, and hashes of artifacts.
- Prefer screenshots only when logs or machine-readable evidence are insufficient.
- Do not collect sensitive data when proof can be made with metadata, counts, or synthetic canaries.
- Keep cleanup steps explicit and reproducible.

## Engagement tooling

- [ROE-Lint](https://github.com/r00tmancer/roelint) - Imports Rules of Engagement documents into cited, reviewable policy and blocks out-of-scope commands and playbooks before execution.

## Repository paths

- Classic infrastructure and domain content: `docs/topics/`
- New AI and fuzzing content: `docs/resources/`
- Visual navigation graph: `docs/graphs/repo-map.md`
