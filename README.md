# Entra ID Attack Path Visualizer

Scans a Microsoft Entra ID tenant via Microsoft Graph, detects privilege escalation paths through direct role assignments, group memberships, and PIM eligible assignments, and produces two artifacts: a structured HTML report and an interactive graph.

Part of a three-tool portfolio built on the shared [`entra-security-report`](https://github.com/Dfrank77/entra-security-report) library, alongside [`entra-workload-identity-scanner`](https://github.com/Dfrank77/entra-workload-identity-scanner) and [`entra-zt-policy-engine`](https://github.com/Dfrank77/entra-zt-policy-engine).

![Privilege Escalation Map](docs/Entra ID Privilege Escalation Map.jpeg)

## The Problem

Organizations lose track of who has administrative privileges in Entra ID:

- **Shadow admins** inherit admin access through nested group memberships without anyone realizing it
- **PIM blind spots**: users with eligible (not yet activated) roles don't show up in standard directory role queries, but they can activate to admin at any time
- **Role sprawl**: multiple users and groups assigned to privileged roles unnecessarily
- **Manual reviews miss indirect paths**: a user in a group that's assigned Global Administrator is a Global Administrator, but that doesn't show up when you look at the user's direct role assignments

Manual review of hundreds of users and groups takes 40+ hours per quarter. This tool automates it in under 5 minutes.

## What It Detects

Each escalation path is emitted as a structured finding with stable identity across scans, allowing the tool to answer "what's new since last run" and "what got fixed."

| Rule | Severity | What it means |
|---|---|---|
| `direct-role-assignment` (HIGH-risk role) | critical | User directly holds a tier-0 admin role like Global Administrator or Privileged Role Administrator |
| `direct-role-assignment` (MEDIUM-risk role) | high | User directly holds a mid-tier admin role |
| `transitive-role-via-group` (HIGH-risk role) | critical | User inherits a tier-0 role through group membership |
| `transitive-role-via-group` (MEDIUM-risk role) | high | User inherits a mid-tier role through group membership |
| `pim-eligible-direct` (HIGH-risk role) | high | User is PIM-eligible for a tier-0 role — dormant privilege they can activate |
| `pim-eligible-via-group` (HIGH-risk role) | high | User is PIM-eligible through group membership |
| `pim-eligible-direct` / `pim-eligible-via-group` (MEDIUM-risk) | medium | Same as above for mid-tier roles |

Findings persist across scans in `.findings/` via the shared reporting library. Re-running the scanner produces automatic diffs: `X new since last run`, `Y fixed since last run`.

## Output

Two artifacts are generated:

```
output/
├── privilege_report.html    # Structured card-based report matching the other two tools
└── privilege_graph.html     # Interactive network graph via pyvis
```

The structured report uses the same visual language as the workload identity scanner and ZT policy engine — one card per subject (user), findings grouped by highest severity, colored by tier.

The interactive graph is built with [pyvis](https://pyvis.readthedocs.io/). Nodes are draggable, hovering shows role and risk detail. Group-based paths are collapsed into a single edge with a member count so the graph stays readable at scale.

### Graph Visual Encoding

| Element | Meaning |
|---|---|
| Red solid line | Active HIGH risk path |
| Purple dashed line | PIM eligible path (dormant privilege) |
| Red box | Admin role |
| Orange ellipse | Group |
| Blue dot | User |

## Installation

### Prerequisites

- Python 3.10+
- Microsoft Entra ID tenant with admin read access
- Entra ID P2 license (for PIM eligible role scanning)

### Setup

```bash
git clone https://github.com/Dfrank77/entra-attack-path-visualizer.git
cd entra-attack-path-visualizer

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
pip install git+https://github.com/Dfrank77/entra-security-report.git
```

The last line installs the shared reporting library. If you have it locally, `pip install -e ../entra-security-report` instead.

### Microsoft Graph Permissions Required

| Permission | Why |
|---|---|
| `User.Read.All` | Read all user profiles |
| `Group.Read.All` | Read all group memberships |
| `Directory.Read.All` | Read directory data |
| `RoleManagement.Read.All` | Read role assignments |
| `RoleManagement.Read.Directory` | Read directory role definitions |
| `RoleEligibilitySchedule.Read.Directory` | Read PIM eligible role assignments |

## Usage

```bash
source venv/bin/activate

# Scan the tenant (opens browser for OAuth2 login)
python entra_scanner.py

# Generate both artifacts from the stored findings
python visualizer.py

# Open the report
open output/privilege_report.html
open output/privilege_graph.html
```

### What Happens

1. **Scanner** authenticates via browser, enumerates users, groups, active role assignments, and PIM eligible assignments. Every escalation path becomes a `Finding` object with severity mapped from role tier and assignment type. Findings persist to `.findings/`.
2. **Visualizer** reads the latest scan from storage and produces both the structured report (via shared `render()`) and the interactive graph.

## Architecture

- entra_scanner.py: scanner, emits Finding objects, persists to shared storage
- visualizer.py: reads latest scan, produces structured HTML plus pyvis graph
- lib/: pyvis and vis.js dependencies for standalone HTML
- output/: generated reports (gitignored)
- .findings/: persisted findings and scan history (gitignored)

### Design decisions worth calling out

**Findings are structured, not display strings.** Each path is a Finding with a subject (the user), evidence (the full path array plus type), and severity mapped from HIGH/MEDIUM risk times active/eligible assignment. The workload scanner and ZT engine produce findings in the same schema, which is what enables cross-tool correlation.

**Group-based paths are collapsed in the graph, not the report.** In a 250-user tenant with heavily nested groups, drawing every user-to-role line makes the graph unreadable. The graph shows one collapsed edge per group with a member count and tooltip. The structured report shows every user individually since it is designed for reading, not eyeballing.

**Severity mapping.** HIGH-risk role plus active equals critical. HIGH-risk role plus eligible equals high. MEDIUM-risk role plus active equals high. MEDIUM-risk role plus eligible equals medium. This is the "direct plus privileged equals urgent, dormant plus mid-tier equals watch" logic explicit in code rather than left as text.

**PIM queries use aiohttp directly.** The Graph SDK's roleEligibilitySchedules support is unreliable. Rather than fight SDK bugs, the scanner makes direct REST calls using aiohttp with a raw bearer token. Async is required because the Graph SDK is async-only.

## Author

**Darius Frank** — IAM and Cloud Security

- GitHub: [@Dfrank77](https://github.com/Dfrank77)
- LinkedIn: [Darius Frank](https://www.linkedin.com/in/darius-frank/)

## License

MIT — see [LICENSE](LICENSE)

## Disclaimer

This tool is for authorized security assessments and compliance audits only. You must have appropriate permissions to scan your Entra ID environment. Unauthorized access to systems is illegal.
HEREDOC_END