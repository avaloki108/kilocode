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

export class AttackGraph {
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

	getPathsBetween(start: string, end: string, maxDepth = 6): AttackPath[] {
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

	rankPaths(start: string, end: string, maxDepth = 6): AttackPath[] {
		return this.getPathsBetween(start, end, maxDepth).sort((a, b) => a.totalEffort - b.totalEffort)
	}
}
