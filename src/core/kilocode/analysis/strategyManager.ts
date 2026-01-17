// kilocode_change start
import type { AttackGraph, AttackPath } from "./attackGraph"

export interface StrategyDigestOptions {
	maxPaths?: number
}

/**
 * StrategyManager generates periodic strategy digests for closed-loop auditing.
 * A digest summarizes the top-ranked attack paths from an attack graph, providing
 * concise strategic guidance that can be injected into planner prompts.
 *
 * Use cases:
 * - Periodic strategy updates during multi-stage security analysis
 * - Summarizing attack surface for human reviewers
 * - Providing context to automated security agents
 *
 * @example
 * ```typescript
 * const manager = new StrategyManager()
 * const graph = buildAttackGraph(findings)
 *
 * // Update digest every 5 analysis steps
 * const digest = manager.updateDigestIfNeeded(graph, stepCount, 5)
 * if (digest) {
 *   console.log(digest)
 *   // "Strategy Digest:
 *   //  1. entry -> escalate -> target (effort 8)
 *   //  2. entry -> bypass -> target (effort 12)"
 * }
 * ```
 */
export class StrategyManager {
	// kilocode_change end
	private currentDigest: string | null = null

	getDigest(): string | null {
		return this.currentDigest
	}

	// kilocode_change start
	/**
	 * Conditionally updates the strategy digest based on the current step count.
	 * Only generates a new digest when stepCount is a multiple of digestInterval.
	 *
	 * @param attackGraph - The attack graph to analyze
	 * @param stepCount - Current analysis step number (0-indexed or 1-indexed)
	 * @param digestInterval - How often to regenerate the digest (e.g., every 5 steps)
	 * @param options - Configuration for digest generation (e.g., maxPaths to include)
	 * @returns The newly generated digest string, or null if not at an interval boundary
	 *
	 * @example
	 * ```typescript
	 * // Generate digest every 10 steps
	 * for (let step = 0; step < 100; step++) {
	 *   const digest = manager.updateDigestIfNeeded(graph, step, 10)
	 *   if (digest) {
	 *     injectIntoPrompt(digest)
	 *   }
	 * }
	 * ```
	 */
	updateDigestIfNeeded(
		// kilocode_change end
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

	// kilocode_change start
	/**
	 * Generates a strategy digest by ranking attack paths and formatting them
	 * as a human-readable summary. The digest identifies entry/exit nodes and
	 * ranks the top attack paths by effort.
	 *
	 * @param attackGraph - The attack graph to analyze
	 * @param options - Configuration options (maxPaths defaults to 3)
	 * @returns A formatted string describing the top attack paths with effort estimates
	 *
	 * @example
	 * ```typescript
	 * const digest = manager.generateDigest(graph, { maxPaths: 5 })
	 * // Returns:
	 * // "Strategy Digest:
	 * //  1. A -> B -> C (effort 3)
	 * //  2. A -> D -> C (effort 6)"
	 * ```
	 */
	generateDigest(attackGraph: AttackGraph, options: StrategyDigestOptions = {}): string {
		// kilocode_change end
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
