# G-CTR Subagent for Kilo

Game-Theoretic Cyber Threat Response (G-CTR) subagent system for strategic attack path analysis in Kilo's GLM-4.7 security pipeline.

## Overview

This subagent analyzes tool execution logs to construct attack graphs and generate strategic digests that guide the main agent toward optimal attack paths using game-theoretic principles.

## Architecture

```
kilocode/
├── agent.yaml              # Main agent configuration
├── subagent.yaml           # G-CTR subagent definition
├── subagents/
│   ├── gctr_agent.py       # Digest generation logic
│   └── graph_utils.py      # Graph construction utilities
└── logs/
    └── last_run.json       # Tool execution logs
```

## Installation

### 1. Install Python Dependencies

```bash
pip install networkx
```

Or using requirements file:

```bash
pip install -r subagents/requirements.txt
```

### 2. Verify Installation

```bash
python subagents/gctr_agent.py logs/last_run.json
```

Expected output:

```
⚔️ Strategic Attack Paths (G-CTR Analysis)
============================================================

#1 Priority Path (Score: 11.25)
   Route: ROOT → IP:10.0.0.1 → /admin → config-exposed → admin-credentials
   Total Effort: 4.50
   💡 Tactical Rec: Immediate exploitation candidate
...
```

## Usage

### Standalone Testing

Test the G-CTR agent directly:

```bash
# Run with sample data
python subagents/gctr_agent.py logs/last_run.json

# Run with custom log file
python subagents/gctr_agent.py /path/to/custom_logs.json
```

### Integration with Kilo Agent

The subagent automatically runs as part of the main agent workflow defined in `agent.yaml`:

1. **Recon step** executes tools and writes to `logs/last_run.json`
2. **Analyze step** invokes `gctr-digest` subagent
3. **Plan step** uses the digest to select next action
4. **Execute step** runs the chosen tool

## Log Format

Tool execution logs must follow this structure:

```json
[
	{
		"tool": "nmap",
		"from": "ROOT",
		"to": "IP:10.0.0.1",
		"effort": 1.0,
		"timestamp": "2026-01-17T10:00:00Z",
		"success": true,
		"finding": "Open ports: 80, 443, 22"
	}
]
```

### Required Fields

- `tool`: Name of the tool used
- `from`: Source node (use "ROOT" for initial reconnaissance)
- `to`: Target/finding node

### Optional Fields

- `effort`: Cost metric (default: 1.0)
- `success`: Whether the action succeeded (default: true)
- `timestamp`: ISO 8601 timestamp
- `finding`: Human-readable description

## G-CTR Scoring Algorithm

The subagent calculates path priority using:

```
Priority = Impact / Effort

Impact = (path_length × 1.5) + critical_node_bonus

Where critical_node_bonus = 5.0 for nodes containing:
- admin, config, secret, api, token, root
```

### Effort Adjustments

- Failed attempts: `effort × 2.0`
- Duplicate paths: Uses minimum effort

## Features

### ✅ Implemented

- [x] Attack graph construction from logs
- [x] Shortest path analysis with effort weighting
- [x] Priority scoring with impact/effort ratio
- [x] Critical node detection (admin, config, etc.)
- [x] Tactical recommendations per path
- [x] ASCII graph visualization
- [x] Graph statistics (density, avg path length)

### 🚧 Next Steps

- [ ] Add effort heuristics (token count, log length)
- [ ] Track tool-failure branches (dead ends)
- [ ] Implement dynamic planning based on digest
- [ ] Auto-update attack graph after tool execution
- [ ] Add multi-objective optimization (stealth vs. speed)
- [ ] Integrate with defensive strategy modeling

## Advanced Usage

### Visualize Attack Graph

```python
from subagents.graph_utils import build_attack_graph, visualize_graph_ascii
import json

with open('logs/last_run.json') as f:
    logs = json.load(f)

G = build_attack_graph(logs)
print(visualize_graph_ascii(G, max_depth=5))
```

### Get Graph Statistics

```python
from subagents.graph_utils import build_attack_graph, get_graph_stats
import json

with open('logs/last_run.json') as f:
    logs = json.load(f)

G = build_attack_graph(logs)
stats = get_graph_stats(G)
print(f"Nodes: {stats['num_nodes']}, Edges: {stats['num_edges']}")
print(f"Avg Path Length: {stats['avg_path_length']:.2f}")
```

## Configuration

### Adjust Number of Paths

Edit `subagent.yaml`:

```yaml
subagents:
    - name: gctr-digest
      # ... other config ...
      params:
          max_paths: 5 # Default: 3
```

### Custom Effort Calculation

Modify `gctr_agent.py`:

```python
def calculate_path_priority(path, effort, logs):
    # Custom scoring logic
    impact = len(path) * 2.0  # Increase path length weight
    # ... your logic ...
    return impact / effort
```

## Troubleshooting

### Error: `ModuleNotFoundError: No module named 'networkx'`

**Solution:** Install dependencies

```bash
pip install networkx
```

### Error: `FileNotFoundError: logs/last_run.json`

**Solution:** Run reconnaissance tools first or create test data

```bash
cp logs/last_run.json logs/last_run.backup.json
```

### No paths found in digest

**Cause:** Logs don't contain connected nodes from ROOT

**Solution:** Ensure logs have a `from: "ROOT"` entry and connected chains

## Contributing

When adding new features:

1. Follow Kilo's `kilocode_change` marking conventions
2. Add tests to `subagents/tests/`
3. Update this README with new capabilities

## References

- [G-CTR Original Paper](https://doi.org/10.1145/3243734.3243747) (Cybersecurity as a Game-Theoretic AI)
- [NetworkX Documentation](https://networkx.org/documentation/stable/)
- [Kilo Agent Framework](../../docs/agents.md)

## License

See [LICENSE](../LICENSE) file.
