// kilocode_change - new file

/**
 * Static Analysis Result Normalizer
 *
 * This module provides unified normalization of results from multiple static analysis tools
 * (Slither, Mythril, Aderyn, Crytic) to a standard format.
 */

import type { SlitherResult, SlitherVulnerability } from "./slither/SlitherIntegration.js"
import type { MythrilResult, MythrilVulnerability } from "./mythril/MythrilIntegration.js"
import type { AderynResult, AderynVulnerability } from "./aderyn/AderynIntegration.js"
import type { CryticResult, CryticVulnerability } from "./crytic/CryticIntegration.js"

/**
 * Normalized vulnerability format
 */
export interface NormalizedVulnerability {
	id: string // Unique identifier
	source: "slither" | "mythril" | "aderyn" | "crytic" | "agent"
	severity: "critical" | "high" | "medium" | "low" | "informational"
	category: string // Vulnerability category (e.g., reentrancy, arithmetic, access_control)
	title: string // Human-readable title
	description: string // Detailed description
	locations: {
		file: string
		line: number
		column: number
		function?: string
		contract?: string
	}[]
	confidence?: "high" | "medium" | "low"
	metadata?: {
		[key: string]: any
	}
}

/**
 * Normalized analysis result
 */
export interface NormalizedAnalysisResult {
	success: boolean
	error?: string
	vulnerabilities: NormalizedVulnerability[]
	toolResults: {
		slither?: SlitherResult
		mythril?: MythrilResult
		aderyn?: AderynResult
		crytic?: CryticResult
	}
	analysisDuration: number // Total duration in milliseconds
}

/**
 * Vulnerability category mapping
 */
const CATEGORY_MAP: Record<string, string> = {
	// Reentrancy
	reentrancy: "reentrancy",
	"re-entrancy": "reentrancy",
	"external-call": "reentrancy",

	// Arithmetic
	arithmetic: "arithmetic",
	overflow: "arithmetic",
	underflow: "arithmetic",
	"integer-overflow": "arithmetic",
	"integer-underflow": "arithmetic",
	"unchecked-math": "arithmetic",

	// Access Control
	"access-control": "access_control",
	access_control: "access_control",
	"unprotected-function": "access_control",
	"missing-onlyowner": "access_control",
	"tx-origin": "access_control",
	delegatecall: "access_control",

	// Front Running
	"front-running": "front_running",
	frontrun: "front_running",
	"transaction-ordering": "front_running",

	// Logic Errors
	"logic-error": "logic_error",
	logic_error: "logic_error",
	"unchecked-return": "logic_error",
	"uninitialized-storage": "logic_error",

	// Gas Issues
	gas: "gas_issue",
	"gas-optimization": "gas_issue",
	"high-gas": "gas_issue",

	// Storage Issues
	storage: "storage",
	"uninitialized-storage": "storage",
	"storage-array": "storage",

	// Timestamp
	timestamp: "timestamp",
	"timestamp-dependence": "timestamp",

	// Oracle Manipulation
	oracle: "oracle_manipulation",
	"oracle-manipulation": "oracle_manipulation",
	"price-manipulation": "oracle_manipulation",

	// Transaction Origin
	"tx.origin": "tx_origin",
	"tx-origin": "tx_origin",

	// Delegatecall
	delegatecall: "delegatecall",
	"delegate-call": "delegatecall",
}

/**
 * Severity mapping
 */
const SEVERITY_MAP: Record<string, NormalizedVulnerability["severity"]> = {
	critical: "critical",
	high: "high",
	medium: "medium",
	low: "low",
	informational: "informational",
	information: "informational",
	low: "low",
	medium: "medium",
	high: "high",
	critical: "critical",
}

/**
 * Static Analysis Result Normalizer
 */
export class StaticAnalysisNormalizer {
	/**
	 * Normalize Slither vulnerability
	 */
	private normalizeSlitherVulnerability(vuln: SlitherVulnerability, sourceFile: string): NormalizedVulnerability {
		return {
			id: `slither-${vuln.check}-${vuln.elements[0]?.source_mapping?.start || 0}`,
			source: "slither",
			severity: this.mapSeverity(vuln.impact),
			category: this.mapCategory(vuln.check),
			title: vuln.check,
			description: vuln.description,
			locations: vuln.elements.map((el) => ({
				file: el.source_mapping?.filename || sourceFile,
				line: el.source_mapping?.start || 0,
				column: el.source_mapping?.length || 0,
				function: el.name,
				contract: el.type === "contract" ? el.name : undefined,
			})),
			confidence: this.mapConfidence(vuln.confidence),
		}
	}

	/**
	 * Normalize Mythril vulnerability
	 */
	private normalizeMythrilVulnerability(vuln: MythrilVulnerability, sourceFile: string): NormalizedVulnerability {
		return {
			id: `mythril-${vuln.swcId}-${vuln.locations[0]?.address || "0"}`,
			source: "mythril",
			severity: this.mapSeverity(vuln.severity),
			category: this.mapCategory(vuln.swcId),
			title: vuln.swcTitle,
			description: vuln.description,
			locations: vuln.locations.map((loc) => ({
				file: sourceFile,
				line: loc.pc || 0,
				column: 0,
				function: loc.functionName,
				contract: loc.address,
			})),
		}
	}

	/**
	 * Normalize Aderyn vulnerability
	 */
	private normalizeAderynVulnerability(vuln: AderynVulnerability, sourceFile: string): NormalizedVulnerability {
		return {
			id: `aderyn-${vuln.detectorId}-${vuln.locations[0]?.line || 0}`,
			source: "aderyn",
			severity: this.mapSeverity(vuln.severity),
			category: this.mapCategory(vuln.detectorId),
			title: vuln.detectorName,
			description: vuln.description,
			locations: vuln.locations.map((loc) => ({
				file: loc.file || sourceFile,
				line: loc.line,
				column: loc.column,
				function: loc.function,
				contract: loc.contract,
			})),
		}
	}

	/**
	 * Normalize Crytic vulnerability
	 */
	private normalizeCryticVulnerability(vuln: CryticVulnerability, sourceFile: string): NormalizedVulnerability {
		return {
			id: `crytic-${vuln.check}-${vuln.locations[0]?.line || 0}`,
			source: "crytic",
			severity: this.mapSeverity(vuln.severity),
			category: this.mapCategory(vuln.check),
			title: vuln.check,
			description: vuln.description,
			locations: vuln.locations.map((loc) => ({
				file: loc.file || sourceFile,
				line: loc.line,
				column: loc.column,
				function: loc.function,
				contract: loc.contract,
			})),
		}
	}

	/**
	 * Map severity to standard format
	 */
	private mapSeverity(severity: string): NormalizedVulnerability["severity"] {
		return SEVERITY_MAP[severity.toLowerCase()] || "informational"
	}

	/**
	 * Map confidence to standard format
	 */
	private mapConfidence(confidence: string): NormalizedVulnerability["confidence"] {
		const confLower = confidence.toLowerCase()
		if (confLower === "high") return "high"
		if (confLower === "medium") return "medium"
		return "low"
	}

	/**
	 * Map check/detector to category
	 */
	private mapCategory(check: string): string {
		const checkLower = check.toLowerCase()

		// Check exact matches first
		if (CATEGORY_MAP[checkLower]) {
			return CATEGORY_MAP[checkLower]
		}

		// Check for partial matches
		for (const [key, category] of Object.entries(CATEGORY_MAP)) {
			if (checkLower.includes(key)) {
				return category
			}
		}

		return "logic_error" // Default category
	}

	/**
	 * Normalize Slither result
	 */
	normalizeSlitherResult(result: SlitherResult, sourceFile: string): NormalizedAnalysisResult {
		return {
			success: result.success,
			error: result.error,
			vulnerabilities: result.vulnerabilities.map((v) => this.normalizeSlitherVulnerability(v, sourceFile)),
			toolResults: {
				slither: result,
			},
			analysisDuration: result.analysisDuration,
		}
	}

	/**
	 * Normalize Mythril result
	 */
	normalizeMythrilResult(result: MythrilResult, sourceFile: string): NormalizedAnalysisResult {
		return {
			success: result.success,
			error: result.error,
			vulnerabilities: result.vulnerabilities.map((v) => this.normalizeMythrilVulnerability(v, sourceFile)),
			toolResults: {
				mythril: result,
			},
			analysisDuration: result.analysisDuration,
		}
	}

	/**
	 * Normalize Aderyn result
	 */
	normalizeAderynResult(result: AderynResult, sourceFile: string): NormalizedAnalysisResult {
		return {
			success: result.success,
			error: result.error,
			vulnerabilities: result.vulnerabilities.map((v) => this.normalizeAderynVulnerability(v, sourceFile)),
			toolResults: {
				aderyn: result,
			},
			analysisDuration: result.analysisDuration,
		}
	}

	/**
	 * Normalize Crytic result
	 */
	normalizeCryticResult(result: CryticResult, sourceFile: string): NormalizedAnalysisResult {
		return {
			success: result.success,
			error: result.error,
			vulnerabilities: result.vulnerabilities.map((v) => this.normalizeCryticVulnerability(v, sourceFile)),
			toolResults: {
				crytic: result,
			},
			analysisDuration: result.analysisDuration,
		}
	}

	/**
	 * Normalize and combine multiple analysis results
	 */
	normalizeCombinedResults(
		results: {
			slither?: SlitherResult
			mythril?: MythrilResult
			aderyn?: AderynResult
			crytic?: CryticResult
		},
		sourceFile: string,
	): NormalizedAnalysisResult {
		const vulnerabilities: NormalizedVulnerability[] = []
		const toolResults: NormalizedAnalysisResult["toolResults"] = {}
		let totalDuration = 0
		let hasError = false
		let errorMessage = ""

		// Normalize each tool result
		if (results.slither) {
			const normalized = this.normalizeSlitherResult(results.slither, sourceFile)
			vulnerabilities.push(...normalized.vulnerabilities)
			toolResults.slither = results.slither
			totalDuration += results.slither.analysisDuration
			if (results.slither.error) {
				hasError = true
				errorMessage += results.slither.error + "; "
			}
		}

		if (results.mythril) {
			const normalized = this.normalizeMythrilResult(results.mythril, sourceFile)
			vulnerabilities.push(...normalized.vulnerabilities)
			toolResults.mythril = results.mythril
			totalDuration += results.mythril.analysisDuration
			if (results.mythril.error) {
				hasError = true
				errorMessage += results.mythril.error + "; "
			}
		}

		if (results.aderyn) {
			const normalized = this.normalizeAderynResult(results.aderyn, sourceFile)
			vulnerabilities.push(...normalized.vulnerabilities)
			toolResults.aderyn = results.aderyn
			totalDuration += results.aderyn.analysisDuration
			if (results.aderyn.error) {
				hasError = true
				errorMessage += results.aderyn.error + "; "
			}
		}

		if (results.crytic) {
			const normalized = this.normalizeCryticResult(results.crytic, sourceFile)
			vulnerabilities.push(...normalized.vulnerabilities)
			toolResults.crytic = results.crytic
			totalDuration += results.crytic.analysisDuration
			if (results.crytic.error) {
				hasError = true
				errorMessage += results.crytic.error + "; "
			}
		}

		// Deduplicate vulnerabilities by location
		const deduplicated = this.deduplicateVulnerabilities(vulnerabilities)

		return {
			success: !hasError,
			error: errorMessage.trim() || undefined,
			vulnerabilities: deduplicated,
			toolResults,
			analysisDuration: totalDuration,
		}
	}

	/**
	 * Deduplicate vulnerabilities by location
	 */
	private deduplicateVulnerabilities(vulnerabilities: NormalizedVulnerability[]): NormalizedVulnerability[] {
		const seen = new Map<string, NormalizedVulnerability>()
		const deduplicated: NormalizedVulnerability[] = []

		for (const vuln of vulnerabilities) {
			const key = `${vuln.file}:${vuln.line}:${vuln.column}:${vuln.title}`
			if (!seen.has(key)) {
				seen.set(key, vuln)
				deduplicated.push(vuln)
			}
		}

		return deduplicated
	}

	/**
	 * Merge vulnerabilities from multiple sources
	 */
	mergeVulnerabilities(vulnerabilities: NormalizedVulnerability[]): {
		merged: NormalizedVulnerability[]
		conflicts: NormalizedVulnerability[]
	} {
		const merged: NormalizedVulnerability[] = []
		const conflicts: NormalizedVulnerability[] = []
		const vulnerabilityMap = new Map<string, NormalizedVulnerability[]>()

		// Group vulnerabilities by location
		for (const vuln of vulnerabilities) {
			const key = `${vuln.file}:${vuln.line}:${vuln.column}`
			if (!vulnerabilityMap.has(key)) {
				vulnerabilityMap.set(key, [vuln])
			} else {
				vulnerabilityMap.get(key)!.push(vuln)
			}
		}

		// Merge and detect conflicts
		for (const [key, vulns] of vulnerabilityMap.entries()) {
			if (vulns.length === 1) {
				merged.push(vulns[0])
			} else {
				// Multiple tools found the same vulnerability - create conflict entry
				const conflictVuln: NormalizedVulnerability = {
					...vulns[0],
					id: `conflict-${key}`,
					title: `Multiple findings: ${vulns.map((v) => v.title).join(", ")}`,
					description: `Found by ${vulns.map((v) => v.source).join(", ")}`,
					metadata: {
						conflicts: vulns.map((v) => ({
							source: v.source,
							severity: v.severity,
						})),
					},
				}
				conflicts.push(conflictVuln)
				// Add merged entry with highest severity
				const highestSeverity = this.getHighestSeverity(vulns.map((v) => v.severity))
				merged.push({
					...vulns[0],
					severity: highestSeverity,
				})
			}
		}

		return { merged, conflicts }
	}

	/**
	 * Get highest severity from list
	 */
	private getHighestSeverity(severities: NormalizedVulnerability["severity"][]): NormalizedVulnerability["severity"] {
		if (severities.includes("critical")) return "critical"
		if (severities.includes("high")) return "high"
		if (severities.includes("medium")) return "medium"
		if (severities.includes("low")) return "low"
		return "informational"
	}

	/**
	 * Generate summary statistics
	 */
	generateSummary(result: NormalizedAnalysisResult): {
		total: number
		bySeverity: Record<NormalizedVulnerability["severity"], number>
		byCategory: Record<string, number>
		bySource: Record<string, number>
	} {
		const bySeverity: Record<NormalizedVulnerability["severity"], number> = {
			critical: 0,
			high: 0,
			medium: 0,
			low: 0,
			informational: 0,
		}
		const byCategory: Record<string, number> = {}
		const bySource: Record<string, number> = {}

		for (const vuln of result.vulnerabilities) {
			bySeverity[vuln.severity]++
			byCategory[vuln.category] = (byCategory[vuln.category] || 0) + 1
			bySource[vuln.source] = (bySource[vuln.source] || 0) + 1
		}

		return {
			total: result.vulnerabilities.length,
			bySeverity,
			byCategory,
			bySource,
		}
	}
}

/**
 * Create a static analysis normalizer instance
 */
export function createStaticAnalysisNormalizer(): StaticAnalysisNormalizer {
	return new StaticAnalysisNormalizer()
}
