# kilocode_change - new file
"""
G-CTR Digest Generator

This module implements the core digest generation logic for the G-CTR
(Game-Theoretic Cyber Threat Response) subagent. It analyzes tool execution
logs and generates strategic attack path recommendations.
"""

from graph_utils import build_attack_graph, find_top_paths
import json
import sys
from typing import Dict, List, Any


def calculate_path_priority(path: List[str], effort: float, logs: List[Dict]) -> float:
    """
    Calculate priority score for an attack path using G-CTR heuristics.
    
    Priority = Impact / Effort
    Where Impact is based on:
    - Node criticality (depth in graph)
    - Historical success rate
    - Potential information gain
    """
    # Base impact from path length (deeper = more valuable)
    impact = len(path) * 1.5
    
    # Bonus for reaching critical nodes
    critical_keywords = ['admin', 'config', 'secret', 'api', 'token', 'root']
    for node in path:
        if any(keyword in node.lower() for keyword in critical_keywords):
            impact += 5.0
    
    # Normalize by effort
    if effort > 0:
        priority = impact / effort
    else:
        priority = impact
    
    return priority


def format_digest(top_paths: List[tuple], logs: List[Dict]) -> str:
    """
    Format the strategic digest in a human-readable format.
    """
    digest = "⚔️ Strategic Attack Paths (G-CTR Analysis)\n"
    digest += "=" * 60 + "\n\n"
    
    if not top_paths:
        digest += "⚠️  No viable attack paths found in current logs.\n"
        digest += "Recommendation: Expand reconnaissance scope.\n"
        return digest
    
    for i, (path, effort) in enumerate(top_paths, 1):
        priority = calculate_path_priority(path, effort, logs)
        
        digest += f"#{i} Priority Path (Score: {priority:.2f})\n"
        digest += f"   Route: {' → '.join(path)}\n"
        digest += f"   Total Effort: {effort:.2f}\n"
        
        # Add tactical recommendations
        last_node = path[-1]
        if 'exposed' in last_node.lower():
            digest += f"   💡 Tactical Rec: Immediate exploitation candidate\n"
        elif 'admin' in last_node.lower():
            digest += f"   💡 Tactical Rec: High-value target for privilege escalation\n"
        else:
            digest += f"   💡 Tactical Rec: Continue reconnaissance\n"
        
        digest += "\n"
    
    # Add strategic summary
    digest += "📊 Strategic Summary:\n"
    digest += f"   Total Paths Analyzed: {len(top_paths)}\n"
    avg_effort = sum(e for _, e in top_paths) / len(top_paths)
    digest += f"   Average Effort: {avg_effort:.2f}\n"
    digest += f"   Recommended Focus: Path #{1}\n"
    
    return digest


def generate_digest(logs_path: str) -> str:
    """
    Main entry point for digest generation.
    
    Args:
        logs_path: Path to the JSON file containing tool execution logs
        
    Returns:
        Formatted strategic digest string
    """
    try:
        with open(logs_path, 'r') as f:
            logs = json.load(f)
        
        if not logs:
            return "⚠️  No logs found. Please run reconnaissance tools first."
        
        # Build attack graph from logs
        G = build_attack_graph(logs)
        
        # Find top attack paths
        top_paths = find_top_paths(G, target="ROOT", max_paths=5)
        
        # Generate formatted digest
        digest = format_digest(top_paths, logs)
        
        return digest
        
    except FileNotFoundError:
        return f"❌ Error: Log file not found at {logs_path}"
    except json.JSONDecodeError:
        return f"❌ Error: Invalid JSON format in {logs_path}"
    except Exception as e:
        return f"❌ Error generating digest: {str(e)}"


def main():
    """CLI entry point for testing."""
    if len(sys.argv) < 2:
        print("Usage: python gctr_agent.py <logs_path>")
        sys.exit(1)
    
    logs_path = sys.argv[1]
    digest = generate_digest(logs_path)
    print(digest)


if __name__ == "__main__":
    main()
