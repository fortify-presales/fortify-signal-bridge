# Classifier Catalog

Classifiers attach labels to findings when their predicates match. They evaluate native FoD issue/application fields or SSC issue fields; they do not change the source finding or independently establish remediation, exploitability, or malware status.

Only the classifier directory for the selected platform is used: [`fod/`](fod/) for FoD and [`ssc/`](ssc/) for SSC. The YAML files define `issue_query`, optional `scan_types`, and optional `application_query`. FoD scan types further constrain where a classifier applies. An application query limits matching to findings whose owning application satisfies that query.

In findings exports, `tag` mode keeps the selected findings and adds matching classifier IDs. `filter` mode exports only findings that match at least one configured classifier. For configuring and running the actions, see [actions/README.md](../actions/README.md#classifiers).

## FoD

| Classifier | Applies to | Match condition | Interpretation |
|---|---|---|---|
| [`fod-ai-agentic-risk-categories.yaml`](fod/fod-ai-agentic-risk-categories.yaml) | Static findings in applications where `businessCriticalityType == 'High'` | `category` exactly matches one of the AI/agentic-related FoD categories listed below | Category-based tag only; it does not identify `scanTool` or confirm that a finding came from Fortify AA. The optional AI application-type restriction in the YAML is commented out. |
| [`fod-aviator-sast-true-positive.yaml`](fod/fod-aviator-sast-true-positive.yaml) | Static findings in applications where `businessCriticalityType == 'High'` | `fortifyAviator == true` and `auditorStatus` is `Remediation Required` or `Required Remediation` | FoD records Aviator audit evidence indicating remediation is required. This does not mean a fix was applied. |
| [`fod-aviator-dast-true-positive.yaml`](fod/fod-aviator-dast-true-positive.yaml) | Dynamic findings in applications where `businessCriticalityType == 'High'` | Same Aviator and auditor-status conditions as the SAST classifier | DAST counterpart to the SAST classifier; also audit evidence, not proof of a fix. |
| [`fod-aviator-guidance-available.yaml`](fod/fod-aviator-guidance-available.yaml) | Any FoD scan type in applications where `businessCriticalityType == 'High'` | `aviatorRemediationGuidanceAvailable == true` | FoD indicates Aviator remediation guidance is available; this does not imply a particular audit disposition or that a fix was applied. |
| [`fod-oss-exploited.yaml`](fod/fod-oss-exploited.yaml) | Open-source findings in applications where `businessCriticalityType == 'High'` | `exploited == true` | FoD's native exploited flag is true. A null value means unknown, not false. |
| [`fod-oss-malware.yaml`](fod/fod-oss-malware.yaml) | Open-source findings in applications where `businessCriticalityType == 'High'` | `malware == true` | FoD's native malware flag is true; this is a source assertion, not an independent malware verdict. |

The AI/agentic category classifier currently matches these exact FoD categories: `Anthropic Misconfiguration`, `Data Poisoning`, `Excessive Agency`, `Insecure Tool Calling`, `MCP Misconfiguration`, `OpenAI Misconfiguration`, `Prompt Injection`, `System Prompt Leakage`, `LLM Misconfiguration`, `Unbounded Consumption Misconfiguration`, `Cross-Site Scripting: AI`, `Cross-Site Scripting: DOM AI`, `Prompt Injection: Jailbreak Attempts`, and `Prompt Injection: Assistant Prompt`.

**AI application scope note:** The agentic category classifier currently limits matches to high-business-criticality applications. Its additional `AI Application Type` predicate is commented out, so it does not currently require the owning application to be classified as an LLM application or AI agent.

## SSC

| Classifier | Match condition | Interpretation |
|---|---|---|
| [`ssc-correlated.yaml`](ssc/ssc-correlated.yaml) | `hasCorrelatedIssues == true` | SSC marks the issue as having correlated issues. This is not a SignalBridge join between separate SAST and DAST findings. |
| [`ssc-debricked.yaml`](ssc/ssc-debricked.yaml) | `engineType == 'DEBRICKED'` | SSC identifies the finding as coming from Debricked. This does not mean the dependency is exploited or malicious. |
| [`ssc-reintroduced.yaml`](ssc/ssc-reintroduced.yaml) | `scanStatus == 'REINTRODUCED'` | SSC marks the issue as absent from an earlier scan and reported again by a later scan. |

## Maintenance

Classifier predicates are executable query expressions, so keep these files under trusted source control. When a predicate changes, increment its `version`; the file hash is also included in classifier provenance by the collector.