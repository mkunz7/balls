# BALLS (Antigravity Edition)

**Better Agentic Large Language Scanner** is an Antigravity-native, local-first source vulnerability audit workflow inspired by Cloudflare's security audit skill, vulnerability harness, and Anthropic's Project Glasswing blog. This fork ports BALLS from Codex to **Google Antigravity**, pairing Antigravity's workspace skills, bundled subagents, and reactive parallel orchestration with CodeGraph's locally indexed symbol/call graph and a deterministic SQLite evidence ledger.

### Why BALLS?

Agentic code analysis keeps a lot of balls in the air: component reviews, focused hunts, candidate tracking, independent verification, and report writing all need to stay coordinated. BALLS keeps those threads moving without dropping the evidence.

![Three colorful balls following a juggling arc](assets/balls-juggling.png)

BALLS runs entirely through the Antigravity session you are already signed into — it never calls an external LLM API directly and never asks for an API key. Opening this repository as your Antigravity workspace automatically loads its project rules (`AGENTS.md`), audit skills (`.agents/skills/`), and custom read-only security subagents (`.agents/plugins/balls/agents/`):

- **High-fan-out exploration & hunting (`Model: "flash"`)**: `balls-reviewer`, `balls-hunter`, and `balls-coverage-critic` fan out across components and vulnerability categories in parallel.
- **Skeptical verification (`Model: "pro"`)**: `balls-verifier` and `balls-verifier-deep` independently attempt to disprove every candidate against actual source code and exploit-chain pivots.

## Setup

1. Open the `balls-antigravity` folder as your workspace in Google Antigravity (IDE, App, or `agy` CLI).
2. Install the scanner-pinned CodeGraph CLI locally inside `.tools/` (gitignored):

   ```bash
   npm install --prefix .tools/codegraph --no-audit --no-fund @colbymchenry/codegraph@1.6.2
   ```

   BALLS subagents invoke `scripts/codegraph-agent.sh` by absolute path so child sessions resolve the local CodeGraph binary without relying on inherited `PATH` or an MCP server.
3. Run a scan by prompting Antigravity:
   - **Full audit:** `Use balls-scan to audit /path/to/repository`
   - **Rapid triage:** `Use balls-quick-scan to triage /path/to/repository`
   - **Long unattended audits:** Pair with `/goal` so Antigravity drives reconnaissance, parallel hunting, coverage critique, verification, and reporting to completion.

The coordinator initializes CodeGraph for the target if needed, maps its architecture, and tracks coverage as explicit `component::category` units. Reviewers stay scoped to one component; category hunters work bounded related units within that component. All subagents have read-only file access (`[read_file, run_command, manage_task]`) and return structured evidence to the coordinator, which writes artifacts under `<target>/.balls/scans/<scan-id>/`. Target source files are never modified or executed.

## Antigravity Architecture

```text
balls-antigravity/
├── AGENTS.md                           # Workspace rules & Flash/Pro model tier policy
├── .agents/
│   ├── plugins/balls/
│   │   ├── plugin.json                 # Workspace plugin manifest & starter prompts
│   │   ├── assets/logo.svg             # Plugin card icon
│   │   └── agents/                     # Read-only Antigravity subagents
│   │       ├── balls-reviewer.md       # Component mapper (flash)
│   │       ├── balls-hunter.md         # Category vulnerability hunter (flash)
│   │       ├── balls-coverage-critic.md# Coverage & ledger auditor (flash)
│   │       ├── balls-verifier.md       # Skeptical verifier (pro)
│   │       └── balls-verifier-deep.md  # High-risk / chain verifier (pro)
│   └── skills/
│       ├── balls-scan/                 # Full audit skill + 24 category & workflow guides
│       └── balls-quick-scan/           # Bounded triage skill
└── scripts/
    ├── balls-db.py                     # Concurrent-safe SQLite ledger & report renderer
    ├── balls-candidates.py             # Complete candidate hypothesis ledger CLI
    └── codegraph-agent.sh              # Local CodeGraph wrapper for subagents
```

## Adding a Vulnerability Category

Category guides are the focused security references that BALLS hunters load on demand:

1. Create `.agents/skills/balls-scan/references/categories/<category>.md`, using a short kebab-case name matching the category identifier.
2. Describe the weakness and relevant sources/sinks, checks for supported languages/frameworks, common defenses and false positives, reachability/impact evidence requirements, and concise remediation guidance.
3. Add a link in `.agents/skills/balls-scan/references/README.md` (and add to the default category list in `.agents/skills/balls-scan/SKILL.md` if required on every full scan).
4. During a scan, assign `<component>::<category>` units in `coverage.json` to `balls-hunter` subagents with the relevant guide sections.

## Pipeline

1. **Reconnaissance and coverage:** map project boundaries with CodeGraph and build an explicit `component::category` coverage ledger.
2. **Parallel review and hunt:** fan out `balls-reviewer` and `balls-hunter` (`flash`) subagents concurrently via `invoke_subagent` (with reactive wakeup slot refilling) or `run_workflow`.
3. **Candidate ledger:** retain every hypothesis in `candidates.json` (`PENDING` → `CONFIRMED`, `LIKELY`, `POSSIBLE`, `NEEDS_VALIDATION`, `REJECTED`, or `MERGED`) while `balls-coverage-critic` checks for gaps.
4. **Independent verification:** fresh `balls-verifier` and `balls-verifier-deep` (`pro`) subagents attempt to disprove each deduplicated candidate from source.
5. **Evidence ledger:** concurrent-safe SQLite (`scan.db`) stores components, raw findings, verifier council verdicts, and cross-component exploit chains.
6. **Deterministic report:** IDs, counts, indexes, diagrams, and secret-redacted source excerpts are rendered deterministically alongside `report-narrative.json`.

## Output (`<target>/.balls/scans/<scan-id>/`)

- `BALLS-REPORT.md` — executive summary, methodology, scope, Mermaid architecture & data-flow diagrams, component/category coverage, severity/component/CWE indexes, exploit chains, safe reproduction steps, minimal fixed-code examples, and appendices.
- `BALLS-REPORT.json` — machine-readable report with full metadata and candidate dispositions.
- `report-narrative.json` — evidence-led executive and section summaries grounded strictly in verified artifacts.
- `scan.db` — SQLite evidence ledger (`python3 scripts/balls-db.py --help`).
- `coverage.json` / `candidates.json` — complete audit trail of coverage units and candidate hypotheses.
- `reference-claim-matrix.json` — optional claim-by-claim comparison against a prior assessment.

## References

- [Upstream BALLS (Codex)](https://github.com/mkunz7/balls)
- [Google Antigravity Documentation](https://antigravity.google/docs)
- [Cloudflare Security Audit Skill](https://github.com/cloudflare/security-audit-skill)
- [Build your own vulnerability harness](https://blog.cloudflare.com/build-your-own-vulnerability-harness)
- [evilsocket/audit](https://github.com/evilsocket/audit)
- [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter/tree/main)
- [Mythos Preview](https://www.anthropic.com/research/mythos-preview)
- [CodeGraph](https://github.com/colbymchenry/codegraph)
