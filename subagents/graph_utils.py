# kilocode_change - new file
"""
Graph Utilities for G-CTR Attack Path Analysis

Provides graph construction and path-finding utilities for analyzing
tool execution logs and identifying optimal attack paths.
"""

import networkx as nx
from typing import List, Tuple, Dict, Any


def build_attack_graph(logs: List[Dict[str, Any]]) -> nx.DiGraph:
    """
    Build a directed attack graph from tool execution logs.
    
    Args:
        logs: List of log entries with structure:
              {
                "tool": str,
                "from": str (optional, defaults to tool name),
                "to": str (target/finding),
                "effort": float (optional, defaults to 1.0),
                "finding": str (alternative to "to"),
                "success": bool (optional)
              }
    
    Returns:
        NetworkX directed graph with weighted edges
    """
    G = nx.DiGraph()
    
    for entry in logs:
        # Extract source node
        src = entry.get("from", entry.get("tool", "UNKNOWN"))
        
        # Extract destination node
        dst = entry.get("to", entry.get("finding", "UNKNOWN"))
        
        # Skip invalid entries
        if src == "UNKNOWN" or dst == "UNKNOWN":
            continue
        
        # Extract effort (cost/weight)
        effort = float(entry.get("effort", 1.0))
        
        # Adjust effort based on success
        if "success" in entry and not entry["success"]:
            effort *= 2.0  # Penalty for failed attempts
        
        # Add metadata to edge
        metadata = {
            "weight": effort,
            "tool": entry.get("tool", ""),
            "timestamp": entry.get("timestamp", ""),
            "success": entry.get("success", True)
        }
        
        # Add edge with metadata
        if G.has_edge(src, dst):
            # If edge exists, use minimum effort
            current_effort = G[src][dst]["weight"]
            if effort < current_effort:
                G[src][dst].update(metadata)
        else:
            G.add_edge(src, dst, **metadata)
    
    return G


def find_top_paths(
    G: nx.DiGraph,
    target: str = "ROOT",
    max_paths: int = 3
) -> List[Tuple[List[str], float]]:
    """
    Find top attack paths from root to leaf nodes.
    
    Args:
        G: NetworkX directed graph
        target: Starting node (typically "ROOT")
        max_paths: Maximum number of paths to return
    
    Returns:
        List of (path, total_effort) tuples, sorted by effort
    """
    # Find all leaf nodes (nodes with no outgoing edges)
    leaves = [n for n in G.nodes if G.out_degree(n) == 0]
    
    if not leaves:
        # If no leaves, find nodes furthest from root
        if target in G:
            leaves = [n for n in G.nodes if n != target]
        else:
            return []
    
    paths = []
    
    for leaf in leaves:
        try:
            # Try to find shortest path by weight
            path = nx.shortest_path(
                G,
                source=target,
                target=leaf,
                weight="weight"
            )
            
            # Calculate total effort
            total_effort = sum(
                G[u][v]["weight"]
                for u, v in zip(path[:-1], path[1:])
            )
            
            paths.append((path, total_effort))
            
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            # No path exists from target to this leaf
            continue
    
    # Sort by effort (ascending) and return top paths
    sorted_paths = sorted(paths, key=lambda x: x[1])
    return sorted_paths[:max_paths]


def get_graph_stats(G: nx.DiGraph) -> Dict[str, Any]:
    """
    Get statistical information about the attack graph.
    
    Returns:
        Dictionary with graph statistics
    """
    stats = {
        "num_nodes": G.number_of_nodes(),
        "num_edges": G.number_of_edges(),
        "is_dag": nx.is_directed_acyclic_graph(G),
        "density": nx.density(G),
    }
    
    # Find root nodes (no incoming edges)
    roots = [n for n in G.nodes if G.in_degree(n) == 0]
    stats["root_nodes"] = roots
    
    # Find leaf nodes (no outgoing edges)
    leaves = [n for n in G.nodes if G.out_degree(n) == 0]
    stats["leaf_nodes"] = leaves
    
    # Average path length
    if stats["is_dag"] and len(roots) > 0 and len(leaves) > 0:
        try:
            path_lengths = []
            for root in roots:
                for leaf in leaves:
                    try:
                        length = nx.shortest_path_length(G, root, leaf)
                        path_lengths.append(length)
                    except nx.NetworkXNoPath:
                        continue
            
            if path_lengths:
                stats["avg_path_length"] = sum(path_lengths) / len(path_lengths)
            else:
                stats["avg_path_length"] = 0
        except:
            stats["avg_path_length"] = 0
    else:
        stats["avg_path_length"] = 0
    
    return stats


def visualize_graph_ascii(G: nx.DiGraph, max_depth: int = 3) -> str:
    """
    Create a simple ASCII visualization of the graph.
    
    Args:
        G: NetworkX directed graph
        max_depth: Maximum depth to visualize
    
    Returns:
        ASCII string representation
    """
    output = []
    roots = [n for n in G.nodes if G.in_degree(n) == 0]
    
    if not roots:
        return "No root nodes found in graph"
    
    def traverse(node: str, depth: int, prefix: str):
        if depth > max_depth:
            return
        
        indent = "  " * depth
        output.append(f"{indent}{prefix}{node}")
        
        # Get successors
        successors = list(G.successors(node))
        for i, succ in enumerate(successors):
            is_last = (i == len(successors) - 1)
            new_prefix = "└─ " if is_last else "├─ "
            traverse(succ, depth + 1, new_prefix)
    
    for root in roots:
        traverse(root, 0, "")
    
    return "\n".join(output)
