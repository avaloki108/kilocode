export type Severity = "low" | "medium" | "high" | "critical"

export interface Evidence {
	id: string
	type: string
	description: string
	data: string
}

export interface Provenance {
	source: string
	tool?: string
	version?: string
	stepId?: string
	timestamp: Date
	details?: string
}

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
