# AI Red Teaming

[← Home](../../README.md) · [Topic index](../INDEX.md)

AI red teaming needs a different lens than classic infrastructure testing: model behavior, prompts, retrieval, tools, agents, authorization boundaries, and telemetry all become part of the attack surface.

## Start here

- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/) - baseline application-risk taxonomy for LLM apps.
- [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/) - OWASP GenAI resources for agentic systems and governance.
- [MITRE ATLAS](https://atlas.mitre.org/) - adversary tactics, techniques, mitigations, and case studies for AI-enabled systems.
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) - risk management framework for trustworthy AI systems.
- [NIST AI Resource Center](https://airc.nist.gov/) - AI RMF playbooks, profiles, and TEVV resources.

## Practical tools and labs

- [garak](https://github.com/NVIDIA/garak) - LLM vulnerability scanner and probing framework.
- [PyRIT](https://github.com/Azure/PyRIT) - automation framework for generative AI red teaming.
- [Counterfit](https://github.com/Azure/counterfit) - command-line tool for assessing AI systems.
- [promptfoo](https://github.com/promptfoo/promptfoo) - prompt and model evaluation, red-team test cases, and CI workflows.
- [Giskard](https://github.com/Giskard-AI/giskard) - testing framework for ML and LLM applications.
- [Inspect AI](https://github.com/UKGovernmentBEIS/inspect_ai) - model evaluation framework from the UK AI Safety Institute.
- [AgentDojo](https://github.com/ethz-spylab/agentdojo) - benchmark for evaluating agent security against prompt injection and tool misuse.
- [Lakera Gandalf](https://gandalf.lakera.ai/) - interactive prompt-injection practice environment.

## What to test

- Prompt injection: direct, indirect, cross-session, and tool-mediated.
- Data exposure: training-data leakage, retrieval leakage, system prompt disclosure, and sensitive output handling.
- Agent boundaries: tool authorization, confused-deputy paths, transaction approval, memory poisoning, and plugin isolation.
- Model behavior: jailbreak resistance, policy bypasses, unsafe instruction following, hallucination risk in security-sensitive workflows.
- Supply chain: model provenance, dataset poisoning, unsafe eval dependencies, and prompt/package injection.
- Operations: logging, abuse monitoring, rate limits, rollback plans, and reproducible evaluation datasets.

## Reporting template

```text
Target:
Model / app surface:
Attack class:
Preconditions:
Steps to reproduce:
Observed behavior:
Expected control:
Impact:
Evidence:
Suggested fix:
Regression test:
```
