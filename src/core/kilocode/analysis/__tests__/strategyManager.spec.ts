import { describe, it, expect } from "vitest"
import { AttackGraph } from "../attackGraph"
import { StrategyManager } from "../strategyManager"

const createGraph = () => {
	const graph = new AttackGraph()
	graph.addNode({ id: "A", label: "entry" })
	graph.addNode({ id: "B", label: "pivot" })
	graph.addNode({ id: "C", label: "target" })
	graph.addNode({ id: "D", label: "detour" })
	graph.addEdge({ from: "A", to: "B", effort: 1 })
	graph.addEdge({ from: "B", to: "C", effort: 2 })
	graph.addEdge({ from: "A", to: "D", effort: 1 })
	graph.addEdge({ from: "D", to: "C", effort: 5 })
	return graph
}

describe("AttackGraph", () => {
	it("ranks paths by total effort", () => {
		const graph = createGraph()
		const paths = graph.rankPaths("A", "C")

		expect(paths[0]).toEqual({ nodes: ["A", "B", "C"], totalEffort: 3 })
		expect(paths[1]).toEqual({ nodes: ["A", "D", "C"], totalEffort: 6 })
	})
})

describe("StrategyManager", () => {
	it("generates a digest with ranked paths", () => {
		const graph = createGraph()
		const manager = new StrategyManager()

		const digest = manager.generateDigest(graph)

		expect(digest).toContain("Strategy Digest")
		expect(digest).toContain("A -> B -> C")
		expect(digest).toContain("effort 3")
	})

	it("updates digest at the configured interval", () => {
		const graph = createGraph()
		const manager = new StrategyManager()

		const skipDigest = manager.updateDigestIfNeeded(graph, 1, 2)
		const digest = manager.updateDigestIfNeeded(graph, 2, 2)

		expect(skipDigest).toBeNull()
		expect(digest).toContain("Strategy Digest")
	})
})
