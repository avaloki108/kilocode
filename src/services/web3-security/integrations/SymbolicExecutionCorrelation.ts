// kilocode_change - new file

/**
 * Symbolic Execution Result Correlation
 *
 * This module provides correlation between symbolic execution results
 * and static analysis results to provide comprehensive vulnerability detection.
 */

import type {
	Vulnerability,
	VulnerabilityCategory,
} from "../../packages/core-schemas/src/web3-security/vulnerability.js"
import type {
	AnalysisResult,
	SmartContract,
	AnalysisContext,
} from "../../packages/core-schemas/src/web3-security/analysis.js"

/**
 * Correlated vulnerability
 */
export interface CorrelatedVulnerability extends Vulnerability {
	/** Correlation confidence score */
	correlationConfidence: number
	/** Sources that detected this vulnerability */
	sources: string[]
	/** Correlation notes */
	notes: string[]
}

/**
 * Correlation result
 */
export interface CorrelationResult {
	/** Analysis ID */
	analysisId: string
	/** Target contract */
	target: SmartContract
	/** Analysis timestamp */
	timestamp: string
	/** Static analysis results */
	staticAnalysis: AnalysisResult[]
	/** Symbolic execution results */
	symbolicExecution: AnalysisResult[]
	/** Correlated vulnerabilities */
	correlatedVulnerabilities: CorrelatedVulnerability[]
	/** Correlation statistics */
	statistics: {
		/** Total vulnerabilities found */
		totalVulnerabilities: number
		/** Vulnerabilities by severity */
		bySeverity: Record<string, number>
		/** Vulnerabilities by category */
		byCategory: Record<string, number>
		/** Correlation confidence */
		averageConfidence: number
		/** High confidence vulnerabilities */
		highConfidenceCount: number
		/** Low confidence vulnerabilities */
		lowConfidenceCount: number
	}
}

/**
 * Correlation configuration
 */
export interface CorrelationConfig {
	/** Minimum confidence threshold */
	minConfidence?: number
	/** Maximum confidence threshold */
	maxConfidence?: number
	/** Weight for static analysis results */
	staticWeight?: number
	/** Weight for symbolic execution results */
	symbolicWeight?: number
	/** Enable cross-validation */
	enableCrossValidation?: boolean
}

/**
 * Symbolic Execution Correlation Service
 */
export class SymbolicExecutionCorrelation {
	private config: CorrelationConfig

	constructor(config?: CorrelationConfig) {
		this.config = {
			minConfidence: config?.minConfidence || 0.5,
			maxConfidence: config?.maxConfidence || 1.0,
			staticWeight: config?.staticWeight || 0.6,
			symbolicWeight: config?.symbolicWeight || 0.8,
			enableCrossValidation: config?.enableCrossValidation ?? true,
		}
	}

	/**
	 * Correlate static and symbolic execution results
	 */
	async correlate(staticAnalysis: AnalysisResult[], symbolicExecution: AnalysisResult[]): Promise<CorrelationResult> {
		const analysisId = this.generateCorrelationId()

		// Extract vulnerabilities from both sources
		const staticVulnerabilities = this.extractVulnerabilities(staticAnalysis)
		const symbolicVulnerabilities = this.extractVulnerabilities(symbolicExecution)

		// Correlate vulnerabilities
		const correlatedVulnerabilities = this.correlateVulnerabilities(staticVulnerabilities, symbolicVulnerabilities)

		// Calculate statistics
		const statistics = this.calculateStatistics(correlatedVulnerabilities)

		return {
			analysisId,
			target: staticAnalysis[0]?.target || {
				name: "unknown",
				language: "solidity",
				version: "0.8.0",
				sourceCode: "",
				filePath: "unknown",
			},
			timestamp: new Date().toISOString(),
			staticAnalysis,
			symbolicExecution,
			correlatedVulnerabilities,
			statistics,
		}
	}

	/**
	 * Extract vulnerabilities from analysis results
	 */
	private extractVulnerabilities(analysisResults: AnalysisResult[]): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		for (const result of analysisResults) {
			if (result.vulnerabilities) {
				vulnerabilities.push(...result.vulnerabilities)
			}
		}

		return vulnerabilities
	}

	/**
	 * Correlate vulnerabilities from multiple sources
	 */
	private correlateVulnerabilities(
		staticVulnerabilities: Vulnerability[],
		symbolicVulnerabilities: Vulnerability[],
	): CorrelatedVulnerability[] {
		const correlated: CorrelatedVulnerability[] = []
		const vulnerabilityMap = new Map<string, Vulnerability[]>()

		// Group vulnerabilities by ID
		for (const vuln of staticVulnerabilities) {
			const existing = vulnerabilityMap.get(vuln.id) || []
			existing.push({ ...vuln, sources: [...(existing[0]?.sources || []), vuln.source] })
			vulnerabilityMap.set(vuln.id, existing)
		}

		for (const vuln of symbolicVulnerabilities) {
			const existing = vulnerabilityMap.get(vuln.id) || []
			existing.push({ ...vuln, sources: [...(existing[0]?.sources || []), vuln.source] })
			vulnerabilityMap.set(vuln.id, existing)
		}

		// Calculate correlation confidence
		for (const [id, vulnerabilities] of vulnerabilityMap.entries()) {
			if (vulnerabilities.length > 1) {
				// Multiple sources detected same vulnerability
				const confidence = this.calculateConfidence(vulnerabilities)
				const notes = this.generateCorrelationNotes(vulnerabilities)

				correlated.push({
					...this.mergeVulnerabilities(vulnerabilities),
					correlationConfidence: confidence,
					sources: vulnerabilities.map((v) => v.source),
					notes,
				})
			}
		}

		return correlated
	}

	/**
	 * Calculate correlation confidence
	 */
	private calculateConfidence(vulnerabilities: Vulnerability[]): number {
		const uniqueSources = new Set(vulnerabilities.map((v) => v.source))
		const sourceCount = uniqueSources.size

		// More sources = higher confidence
		let confidence = 0.5 + sourceCount * 0.1

		// Cap at 1.0
		return Math.min(confidence, 1.0)
	}

	/**
	 * Generate correlation notes
	 */
	private generateCorrelationNotes(vulnerabilities: Vulnerability[]): string[] {
		const notes: string[] = []

		for (const vuln of vulnerabilities) {
			if (vuln.sources.length > 1) {
				notes.push(`Detected by multiple sources: ${vuln.sources.join(", ")}`)
			}
		}

		return notes
	}

	/**
	 * Merge multiple vulnerability instances
	 */
	private mergeVulnerabilities(vulnerabilities: Vulnerability[]): Vulnerability {
		const merged: Vulnerability = { ...vulnerabilities[0] }

		// Merge locations
		const locations = vulnerabilities.flatMap((v) => v.locations || [])
		merged.locations = this.deduplicateLocations(locations)

		// Merge severity (use highest)
		const severities = vulnerabilities.map((v) => v.severity)
		const severityOrder = ["critical", "high", "medium", "low", "informational"]
		for (const sev of severityOrder) {
			if (severities.includes(sev)) {
				merged.severity = sev as any
				break
			}
		}

		// Merge category (use most common)
		const categories = vulnerabilities.map((v) => v.category)
		const categoryCounts = new Map<VulnerabilityCategory, number>()
		for (const cat of categories) {
			categoryCounts.set(cat, (categoryCounts.get(cat) || 0) + 1)
		}
		const mostCommon = [...categoryCounts.entries()].sort((a, b) => b[1] - a[1])[0][0]
		if (mostCommon) {
			merged.category = mostCommon[0]
		}

		return merged
	}

	/**
	 * Deduplicate locations
	 */
	private deduplicateLocations(
		locations: { file: string; line: number; column: number }[],
	): { file: string; line: number; column: number }[] {
		const seen = new Set<string>()
		const deduplicated: { file: string; line: number; column: number }[] = []

		for (const loc of locations) {
			const key = `${loc.file}:${loc.line}:${loc.column}`
			if (!seen.has(key)) {
				seen.add(key)
				deduplicated.push(loc)
			}
		}

		return deduplicated
	}

	/**
	 * Calculate correlation statistics
	 */
	private calculateStatistics(correlatedVulnerabilities: CorrelatedVulnerability[]) {
		const totalVulnerabilities = correlatedVulnerabilities.length

		const bySeverity: Record<string, number> = {
			critical: 0,
			high: 0,
			medium: 0,
			low: 0,
			informational: 0,
		}

		const byCategory: Record<string, number> = {}

		let totalConfidence = 0
		let highConfidenceCount = 0
		let lowConfidenceCount = 0

		for (const vuln of correlatedVulnerabilities) {
			// Count by severity
			bySeverity[vuln.severity] = (bySeverity[vuln.severity] || 0) + 1

			// Count by category
			byCategory[vuln.category] = (byCategory[vuln.category] || 0) + 1

			// Track confidence
			totalConfidence += vuln.correlationConfidence
			if (vuln.correlationConfidence >= 0.8) {
				highConfidenceCount++
			} else if (vuln.correlationConfidence < 0.5) {
				lowConfidenceCount++
			}
		}

		const averageConfidence = totalVulnerabilities > 0 ? totalConfidence / totalVulnerabilities : 0

		return {
			totalVulnerabilities,
			bySeverity,
			byCategory,
			averageConfidence,
			highConfidenceCount,
			lowConfidenceCount,
		}
	}

	/**
	 * Generate correlation ID
	 */
	private generateCorrelationId(): string {
		return `correlation-${Date.now()}-${Math.random().toString(36).substring(7)}`
	}
}
