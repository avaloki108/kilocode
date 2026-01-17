// kilocode_change start
export interface AttackNode {
	id: string
	label?: string
	type?: string
}

export interface AttackEdge {
	from: string
	to: string
	effort: number
	description?: string
}

export interface AttackPath {
	nodes: string[]
	totalEffort: number
}

/**
 * Default maximum depth for path traversal in attack graphs.
 * This prevents infinite loops in cyclic graphs and limits computation time.
 * A depth of 6 is chosen to balance between finding meaningful multi-hop attack
 * chains and avoiding combinatorial explosion in large graphs.
 */
const DEFAULT_MAX_PATH_DEPTH = 6

/**
 * AttackGraph represents a directed graph of attack steps and their relationships.
 * Nodes represent attack states or objectives, and edges represent actions with
 * associated effort costs. This structure enables:
 * - Path enumeration between entry and target nodes
 * - Effort-based ranking to identify optimal attack routes
 * - Strategic analysis for security auditing and penetration testing
 *
 * @example
 * ```typescript
 * const graph = new AttackGraph()
 * graph.addNode({ id: "entry", label: "Public endpoint" })
 * graph.addNode({ id: "escalate", label: "Privilege escalation" })
 * graph.addNode({ id: "target", label: "Admin access" })
 * graph.addEdge({ from: "entry", to: "escalate", effort: 3 })
 * graph.addEdge({ from: "escalate", to: "target", effort: 5 })
 *
 * const paths = graph.rankPaths("entry", "target")
 * // paths[0] = { nodes: ["entry", "escalate", "target"], totalEffort: 8 }
 * ```
 */
export class AttackGraph {
	// kilocode_change end
	private readonly nodes = new Map<string, AttackNode>()
	private readonly edges = new Map<string, AttackEdge[]>()

	addNode(node: AttackNode): void {
		this.nodes.set(node.id, node)
		if (!this.edges.has(node.id)) {
			this.edges.set(node.id, [])
		}
	}

	addEdge(edge: AttackEdge): void {
		if (!this.nodes.has(edge.from)) {
			this.addNode({ id: edge.from })
		}
		if (!this.nodes.has(edge.to)) {
			this.addNode({ id: edge.to })
		}

		const existing = this.edges.get(edge.from)
		if (!existing) {
			this.edges.set(edge.from, [edge])
			return
		}

		existing.push(edge)
	}

	getNodes(): AttackNode[] {
		return [...this.nodes.values()]
	}

	getEdges(from: string): AttackEdge[] {
		return this.edges.get(from) ?? []
	}

	getAllEdges(): AttackEdge[] {
		return [...this.edges.values()].flat()
	}

	// kilocode_change start
	/**
	 * Enumerates all paths from start node to end node within the specified depth limit.
	 * Uses depth-first search with backtracking to find all viable attack paths.
	 *
	 * @param start - The starting node ID (typically an entry point)
	 * @param end - The target node ID (typically the objective)
	 * @param maxDepth - Maximum path length to explore (default: 6). Prevents infinite
	 *                   loops in cyclic graphs and limits computation time.
	 * @returns Array of attack paths with nodes and cumulative effort costs
	 *
	 * @example
	 * ```typescript
	 * const paths = graph.getPathsBetween("entry", "target", 5)
	 * // Returns all paths ≤5 hops from entry to target
	 * ```
	 */
	getPathsBetween(start: string, end: string, maxDepth = DEFAULT_MAX_PATH_DEPTH): AttackPath[] {
		// kilocode_change end
		const results: AttackPath[] = []
		const visited = new Set<string>()

		const traverse = (current: string, path: string[], effort: number, depth: number) => {
			if (depth > maxDepth) {
				return
			}

			if (current === end) {
				results.push({ nodes: [...path], totalEffort: effort })
				return
			}

			visited.add(current)
			for (const edge of this.getEdges(current)) {
				if (visited.has(edge.to)) {
					continue
				}
				path.push(edge.to)
				traverse(edge.to, path, effort + edge.effort, depth + 1)
				path.pop()
			}
			visited.delete(current)
		}

		traverse(start, [start], 0, 0)
		return results
	}

	// kilocode_change start
	/**
	 * Finds and ranks all attack paths by total effort (ascending order).
	 * Lower effort paths represent easier or more efficient attack routes.
	 *
	 * @param start - The starting node ID
	 * @param end - The target node ID
	 * @param maxDepth - Maximum path length to explore (default: 6)
	 * @returns Array of attack paths sorted by total effort (lowest first)
	 *
	 * @example
	 * ```typescript
	 * const rankedPaths = graph.rankPaths("entry", "target")
	 * // rankedPaths[0] contains the lowest-effort path
	 * ```
	 */
	rankPaths(start: string, end: string, maxDepth = DEFAULT_MAX_PATH_DEPTH): AttackPath[] {
		// kilocode_change end
		return this.getPathsBetween(start, end, maxDepth).sort((a, b) => a.totalEffort - b.totalEffort)
	}
}
