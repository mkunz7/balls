# BALLS

**Better Agentic Large Language Scanner** is a Codex-native, local-first source vulnerability audit workflow inspired by Cloudflare's security audit skill, vulnerability harness, and anthropics original project glasswing blog. It replaces Claude Code agent definitions with Codex skills and native subagents, and builds repository knowledge with CodeGraph's locally indexed symbol/call graph.

### Why BALLS?

Agentic code analysis keeps a lot of balls in the air: component reviews, focused hunts, candidate tracking, independent verification, and report writing all need to stay coordinated. BALLS is a reminder to keep those threads moving without dropping the evidence.

![Three colorful balls following a juggling arc](assets/balls-juggling.png)

BALLS uses the Codex session you are already signed into. It does not call the OpenAI API and does not require API billing or an API key. Open and trust the `BALLS` folder as the Codex project to load its project-scoped settings. Configuration defaults the coordinator and subagents to `gpt-6-luna`, with up to 12 concurrent subagent threads. Full scans launch independent work together and refill slots as tasks finish; routine verification uses medium reasoning, while high-risk or contested findings use a high-reasoning verifier. Codex's own model and reasoning availability are controlled by your account and client.

## How to Use

1. Pay for a $20 chatgpt subscription.
2. Signup for chatgpt.com/cyber (you might be able to get by without it for a bit)
3. Download and install the chatgpt app
4. Prompt chatgpt to install this app and use it to scan your code repo

Don't like chatgpt? No worries, point your LLM choice to this repo and ask it to port it to whatever you use ie claude code, copilot, or something else. 

Didn't get chatgpt cyber verification right away? Perhaps try an abliterated model?
   
## Setup

1. Open the `BALLS` folder as the Codex workspace (or copy `.agents/skills/balls-scan` and `.codex/` into a project you trust).
2. Install the scanner-pinned CodeGraph CLI locally:

   ```bash
   npm install --prefix .tools/codegraph --no-audit --no-fund @colbymchenry/codegraph@1.6.2
   ```

   The `.tools/` directory is ignored by Git. BALLS agents call `scripts/codegraph-agent.sh`, which resolves the local binary without relying on a child session inheriting your shell `PATH`. The CLI works without a CodeGraph MCP connection.
3. Scan a repository with a request such as: `Use the balls-scan skill to audit /path/to/repository`.

The skill initializes CodeGraph for the target if needed, maps its architecture, and tracks coverage as explicit component-by-category units. Reviewers stay scoped to one component; category hunters work bounded related units within that component. It independently verifies each candidate and writes artifacts under `<target>/.balls/scans/<scan-id>/`. The target source is not edited. The optional `.codegraph/` index and `.balls/` scan output are local generated artifacts.

The audit reference library contains vulnerability-category and workflow guides, indexed in `.agents/skills/balls-scan/references/README.md`. The scan records each candidate from initial hypothesis through final disposition; `balls-quick-scan` supports bounded triage.

## Adding a vulnerability category

Just ask your AI to add some based on skill files you find online or types you want. 

Category guides are the focused security skills that BALLS hunters load for a scan. To add one:

1. Create `.agents/skills/balls-scan/references/categories/<category>.md`, using a short kebab-case name that matches the category identifier.
2. Make the guide actionable: describe the weakness and relevant sources/sinks, give checks for the supported language or framework, explain common defenses and false positives, and require evidence for attacker reachability and impact. Include concise remediation guidance and authoritative references where useful.
3. Add a link to the new guide in `.agents/skills/balls-scan/references/README.md`. If the category is new to the scanner’s required coverage, update the category list in `.agents/skills/balls-scan/SKILL.md` as well.
4. During a scan, add a component-by-category unit to `coverage.json` (for example, `web-app::<category>`), assign it to a hunter, and point the prompt to the relevant guide sections. The hunter should trace the source to the sensitive operation with CodeGraph, inspect the source directly, and return either an evidence-backed candidate or an explicit no-finding result. Record every candidate before verification.

These Markdown guides are reference material loaded by the `balls-scan` skill; they do not need separate Codex skill frontmatter or their own skill directory.

## Pipeline

1. **Reconnaissance and coverage:** map project boundaries and build a coverage ledger.
2. **Review and hunt:** fan out Codex subagents by component and vulnerability class, using CodeGraph to trace source, calls, and trust boundaries.
3. **Independent verification:** a fresh verifier tries to disprove each candidate.
4. **Candidate ledger:** every hypothesis is retained with a pending, verified, needs-validation, rejected, or merged disposition.
5. **Evidence ledger:** concurrent-safe SQLite stores components, verifier decisions, and promoted findings.
6. **Deterministic report:** IDs and counts are assembled from the DB; source excerpts are read from disk with obvious hard-coded credential values redacted.

## Output

- `BALLS-REPORT.md` — executive summary, methodology, scope, architecture diagram, component/category coverage, severity/component/CWE indexes, evidence and data-flow diagrams, chains, unresolved leads, remediation priorities, and appendices. Each finding includes vulnerable source, safe reproduction steps (with bounded commands when supported), an example fixed implementation, and remediation guidance.
- `BALLS-REPORT.json` — machine-readable report with the same scan metadata and candidates
- `report-narrative.json` — evidence-led executive and section summaries saved with the scan for review
- `scan.db` — evidence ledger
- `coverage.json` / `candidates.json` — scan coverage and complete candidate audit trail, including rejected, merged, likely, and unresolved leads
- `reference-claim-matrix.json` — optional claim-by-claim comparison against a supplied prior assessment

For CLI details, run `python3 scripts/balls-db.py --help`.

## References

- [Cloudflare Security Audit Skill](https://github.com/cloudflare/security-audit-skill)
- [Build your own vulnerability harness](https://blog.cloudflare.com/build-your-own-vulnerability-harness)
- [evilsocket/audit](https://github.com/evilsocket/audit)
- [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter/tree/main)
- [Mythos Preview](https://www.anthropic.com/research/mythos-preview)
- [CodeGraph](https://github.com/colbymchenry/codegraph)
- [Codex subagents and project-scoped agents](https://developers.openai.com/codex/subagents)
- [Claude Security](https://github.com/anthropics/claude-plugins-official/tree/main/plugins/claude-security)
- [OpenAI Security](https://github.com/openai/codex-security)
