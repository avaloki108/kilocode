// kilocode_change start
export type Severity = "low" | "medium" | "high" | "critical"

/**
 * Evidence represents supporting data that substantiates an analysis finding.
 * Evidence can include code snippets, log traces, stack traces, or other artifacts
 * that demonstrate the presence of a security issue or vulnerability.
 *
 * @example
 * ```typescript
 * const evidence: Evidence = {
 *   id: "ev-001",
 *   type: "code-snippet",
 *   description: "Vulnerable function call without input validation",
 *   data: { snippet: "user.balance -= amount", location: "withdraw.sol:42" }
 * }
 * ```
 */
export interface Evidence {
	/** Unique identifier for this evidence item */
	id: string
	/** Category of evidence (e.g., "code-snippet", "log-trace", "stack-trace", "exploit-proof") */
	type: string
	/** Human-readable description of what this evidence demonstrates */
	description: string
	/** Supporting data - can be structured (JSON object) or unstructured (string) depending on evidence type */
	data: string | Record<string, unknown>
}

/**
 * Provenance tracks the origin and lineage of an analysis finding,
 * enabling audit reproducibility and supporting multi-tool correlation.
 * Each provenance entry represents one analysis step or tool invocation
 * that contributed to discovering or confirming the finding.
 *
 * @example
 * ```typescript
 * const provenance: Provenance = {
 *   source: "static-analyzer",
 *   tool: "slither",
 *   version: "0.10.0",
 *   stepId: "scan-contracts-001",
 *   timestamp: new Date("2025-01-15T10:30:00Z"),
 *   details: "Full contract scan with reentrancy detector enabled"
 * }
 * ```
 */
export interface Provenance {
	/** Name or identifier of the analysis source (e.g., "slither", "manual-review", "dynamic-fuzzer") */
	source: string
	/** Specific tool name if applicable */
	tool?: string
	/** Tool version for reproducibility */
	version?: string
	/** Identifier of the analysis step or workflow stage that produced this finding */
	stepId?: string
	/** When this finding was discovered or confirmed */
	timestamp: Date
	/** Additional context about the analysis conditions or configuration */
	details?: string
}
// kilocode_change end

export interface FindingLocation {
	file?: string
	line?: number
	functionName?: string
}

export interface AnalysisFinding {
	id?: string
	title: string
	description: string
	severity: Severity
	confidence?: number
	exploitability?: number
	evidence: Evidence[]
	provenance: Provenance[]
	reproduction?: string
	location?: FindingLocation
	contradicted?: boolean
}
