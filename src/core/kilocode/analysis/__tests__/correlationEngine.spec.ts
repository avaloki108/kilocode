import { describe, it, expect } from "vitest"
import { CorrelationEngine } from "../correlationEngine"
import type { AnalysisFinding } from "../types"

const baseFinding = (): AnalysisFinding => ({
	title: "Reentrancy",
	description: "Issue detected.",
	severity: "medium",
	evidence: [],
	provenance: [{ source: "StaticAnalyzer", timestamp: new Date("2025-01-01T00:00:00Z") }],
	location: { file: "contracts/Vault.sol", line: 42 },
})

describe("CorrelationEngine", () => {
	it("merges duplicate findings and combines evidence/provenance", () => {
		const findingA: AnalysisFinding = {
			...baseFinding(),
			description: "Static analysis flagged a pattern.",
			evidence: [{ id: "e1", type: "code", description: "Vulnerable call", data: "call" }],
		}

		const findingB: AnalysisFinding = {
			...baseFinding(),
			title: "Reentrancy vulnerability",
			severity: "high",
			evidence: [{ id: "e2", type: "log", description: "Exploit trace", data: "trace" }],
			provenance: [{ source: "DynamicAnalyzer", timestamp: new Date("2025-01-02T00:00:00Z") }],
		}

		const engine = new CorrelationEngine()
		const merged = engine.mergeFindings([findingA, findingB])

		expect(merged).toHaveLength(1)
		expect(merged[0].severity).toBe("high")
		expect(merged[0].evidence).toHaveLength(2)
		expect(merged[0].provenance).toHaveLength(2)
	})

	it("boosts confidence with evidence and multiple sources", () => {
		const finding: AnalysisFinding = {
			...baseFinding(),
			evidence: [{ id: "e1", type: "code", description: "Proof", data: "snippet" }],
			provenance: [
				{ source: "StaticAnalyzer", timestamp: new Date("2025-01-01T00:00:00Z") },
				{ source: "DynamicAnalyzer", timestamp: new Date("2025-01-02T00:00:00Z") },
			],
		}

		const engine = new CorrelationEngine()
		const merged = engine.mergeFindings([finding])

		expect(merged[0].confidence).toBeGreaterThan(0.7)
	})

	it("reduces confidence when findings are contradicted", () => {
		const finding: AnalysisFinding = {
			...baseFinding(),
			contradicted: true,
		}

		const engine = new CorrelationEngine()
		const merged = engine.mergeFindings([finding])

		expect(merged[0].confidence).toBeLessThan(0.6)
	})
})
