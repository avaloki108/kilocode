import type { AttackGraph, AttackPath } from "./attackGraph"

export interface StrategyDigestOptions {
	maxPaths?: number
}

export class StrategyManager {
	private currentDigest: string | null = null

	getDigest(): string | null {
		return this.currentDigest
	}

	updateDigestIfNeeded(
		attackGraph: AttackGraph,
		stepCount: number,
		digestInterval: number,
		options: StrategyDigestOptions = {},
	): string | null {
		if (digestInterval <= 0 || stepCount % digestInterval !== 0) {
			return null
		}

		this.currentDigest = this.generateDigest(attackGraph, options)
		return this.currentDigest
	}

	generateDigest(attackGraph: AttackGraph, options: StrategyDigestOptions = {}): string {
		const maxPaths = options.maxPaths ?? 3
		const nodes = attackGraph.getNodes()

		if (nodes.length < 2) {
			return "Strategy Digest: Attack graph has insufficient data to rank paths."
		}

		const edges = attackGraph.getAllEdges()
		const incoming = new Set(edges.map((edge) => edge.to))
		const outgoing = new Set(edges.map((edge) => edge.from))
		const entryNodes = nodes.filter((node) => !incoming.has(node.id))
		const exitNodes = nodes.filter((node) => !outgoing.has(node.id))
		const start = entryNodes[0]?.id ?? nodes[0]?.id
		const end = exitNodes[0]?.id ?? nodes[nodes.length - 1]?.id
		if (!start || !end) {
			return "Strategy Digest: Attack graph has insufficient data to rank paths."
		}

		const rankedPaths = attackGraph.rankPaths(start, end).slice(0, maxPaths)

		if (rankedPaths.length === 0) {
			return "Strategy Digest: No viable attack paths found yet."
		}

		const formattedPaths = rankedPaths.map((path, index) => this.formatPath(path, index + 1))

		return ["Strategy Digest:", ...formattedPaths].join("\n")
	}

	private formatPath(path: AttackPath, index: number): string {
		return `${index}. ${path.nodes.join(" -> ")} (effort ${path.totalEffort})`
	}
}
