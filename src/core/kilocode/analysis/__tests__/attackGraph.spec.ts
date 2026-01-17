// kilocode_change - new file
import { describe, it, expect } from "vitest"
import { AttackGraph } from "../attackGraph"

describe("AttackGraph", () => {
	describe("basic path ranking", () => {
		it("ranks paths by total effort", () => {
			const graph = new AttackGraph()
			graph.addNode({ id: "A", label: "entry" })
			graph.addNode({ id: "B", label: "pivot" })
			graph.addNode({ id: "C", label: "target" })
			graph.addNode({ id: "D", label: "detour" })
			graph.addEdge({ from: "A", to: "B", effort: 1 })
			graph.addEdge({ from: "B", to: "C", effort: 2 })
			graph.addEdge({ from: "A", to: "D", effort: 1 })
			graph.addEdge({ from: "D", to: "C", effort: 5 })

			const paths = graph.rankPaths("A", "C")

			expect(paths[0]).toEqual({ nodes: ["A", "B", "C"], totalEffort: 3 })
			expect(paths[1]).toEqual({ nodes: ["A", "D", "C"], totalEffort: 6 })
		})

		it("finds all paths within maxDepth", () => {
			const graph = new AttackGraph()
			graph.addNode({ id: "A" })
			graph.addNode({ id: "B" })
			graph.addNode({ id: "C" })
			graph.addEdge({ from: "A", to: "B", effort: 1 })
			graph.addEdge({ from: "B", to: "C", effort: 1 })

			const paths = graph.getPathsBetween("A", "C")

			expect(paths).toHaveLength(1)
			expect(paths[0]).toEqual({ nodes: ["A", "B", "C"], totalEffort: 2 })
		})
	})

	describe("edge cases", () => {
		it("returns empty array for empty graph", () => {
			const graph = new AttackGraph()

			const paths = graph.rankPaths("A", "C")

			expect(paths).toEqual([])
		})

		it("returns empty array when no path exists between nodes", () => {
			const graph = new AttackGraph()
			graph.addNode({ id: "A" })
			graph.addNode({ id: "B" })
			graph.addNode({ id: "C" })
			graph.addEdge({ from: "A", to: "B", effort: 1 })
			// No edge to C, so no path from A to C

			const paths = graph.rankPaths("A", "C")

			expect(paths).toEqual([])
		})

		it("handles disconnected nodes", () => {
			const graph = new AttackGraph()
			graph.addNode({ id: "A" })
			graph.addNode({ id: "B" })
			graph.addNode({ id: "C" })
			graph.addNode({ id: "D" })
			graph.addEdge({ from: "A", to: "B", effort: 1 })
			graph.addEdge({ from: "C", to: "D", effort: 1 })
			// Two disconnected subgraphs

			const paths = graph.rankPaths("A", "D")

			expect(paths).toEqual([])
		})

		it("returns empty array for paths exceeding maxDepth", () => {
			const graph = new AttackGraph()
			// Create a long chain: A -> B -> C -> D -> E -> F -> G -> H
			const nodes = ["A", "B", "C", "D", "E", "F", "G", "H"]
			nodes.forEach((id) => graph.addNode({ id }))
			for (let i = 0; i < nodes.length - 1; i++) {
				graph.addEdge({ from: nodes[i], to: nodes[i + 1], effort: 1 })
			}

			// With maxDepth=3, can't reach H from A (requires 7 hops)
			const paths = graph.getPathsBetween("A", "H", 3)

			expect(paths).toEqual([])
		})

		it("finds path within custom maxDepth", () => {
			const graph = new AttackGraph()
			// Create a chain: A -> B -> C
			graph.addNode({ id: "A" })
			graph.addNode({ id: "B" })
			graph.addNode({ id: "C" })
			graph.addEdge({ from: "A", to: "B", effort: 1 })
			graph.addEdge({ from: "B", to: "C", effort: 1 })

			const paths = graph.getPathsBetween("A", "C", 5)

			expect(paths).toHaveLength(1)
			expect(paths[0]).toEqual({ nodes: ["A", "B", "C"], totalEffort: 2 })
		})

		it("handles single-node graph (start equals end)", () => {
			const graph = new AttackGraph()
			graph.addNode({ id: "A" })

			const paths = graph.rankPaths("A", "A")

			expect(paths).toHaveLength(1)
			expect(paths[0]).toEqual({ nodes: ["A"], totalEffort: 0 })
		})

		it("avoids cycles by not revisiting nodes", () => {
			const graph = new AttackGraph()
			// Create a cycle: A -> B -> C -> A
			graph.addNode({ id: "A" })
			graph.addNode({ id: "B" })
			graph.addNode({ id: "C" })
			graph.addNode({ id: "D" })
			graph.addEdge({ from: "A", to: "B", effort: 1 })
			graph.addEdge({ from: "B", to: "C", effort: 1 })
			graph.addEdge({ from: "C", to: "A", effort: 1 }) // Cycle
			graph.addEdge({ from: "C", to: "D", effort: 1 })

			const paths = graph.rankPaths("A", "D")

			// Should find A -> B -> C -> D without getting stuck in cycle
			expect(paths).toHaveLength(1)
			expect(paths[0]).toEqual({ nodes: ["A", "B", "C", "D"], totalEffort: 3 })
		})

		it("handles multiple paths with same effort", () => {
			const graph = new AttackGraph()
			graph.addNode({ id: "A" })
			graph.addNode({ id: "B" })
			graph.addNode({ id: "C" })
			graph.addNode({ id: "D" })
			graph.addEdge({ from: "A", to: "B", effort: 5 })
			graph.addEdge({ from: "B", to: "D", effort: 5 })
			graph.addEdge({ from: "A", to: "C", effort: 5 })
			graph.addEdge({ from: "C", to: "D", effort: 5 })

			const paths = graph.rankPaths("A", "D")

			expect(paths).toHaveLength(2)
			expect(paths[0].totalEffort).toBe(10)
			expect(paths[1].totalEffort).toBe(10)
		})
	})

	describe("graph operations", () => {
		it("adds nodes and edges correctly", () => {
			const graph = new AttackGraph()

			graph.addNode({ id: "A", label: "Node A" })
			graph.addEdge({ from: "A", to: "B", effort: 1 })

			const nodes = graph.getNodes()
			const edges = graph.getAllEdges()

			expect(nodes).toHaveLength(2) // A and B (auto-created)
			expect(edges).toHaveLength(1)
			expect(edges[0]).toEqual({ from: "A", to: "B", effort: 1 })
		})

		it("auto-creates nodes when adding edges", () => {
			const graph = new AttackGraph()

			graph.addEdge({ from: "A", to: "B", effort: 1 })

			const nodes = graph.getNodes()

			expect(nodes).toHaveLength(2)
			expect(nodes.map((n) => n.id)).toContain("A")
			expect(nodes.map((n) => n.id)).toContain("B")
		})

		it("supports multiple edges from same node", () => {
			const graph = new AttackGraph()

			graph.addEdge({ from: "A", to: "B", effort: 1 })
			graph.addEdge({ from: "A", to: "C", effort: 2 })
			graph.addEdge({ from: "A", to: "D", effort: 3 })

			const edgesFromA = graph.getEdges("A")

			expect(edgesFromA).toHaveLength(3)
		})

		it("returns empty array for edges from non-existent node", () => {
			const graph = new AttackGraph()

			const edges = graph.getEdges("nonexistent")

			expect(edges).toEqual([])
		})
	})
})
