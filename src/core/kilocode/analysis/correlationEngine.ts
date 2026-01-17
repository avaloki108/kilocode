// kilocode_change start
import type { AnalysisFinding, Evidence, Provenance, Severity } from "./types"

const severityOrder: Severity[] = ["low", "medium", "high", "critical"]

const compareSeverity = (a: Severity, b: Severity): Severity => {
	return severityOrder.indexOf(a) >= severityOrder.indexOf(b) ? a : b
}

const combine = <T>(items: T[], extras: T[]): T[] => {
	return [...items, ...extras]
}

/**
 * Confidence scoring model constants.
 * These weights define how different attributes contribute to overall confidence:
 * - Base confidence is higher when provenance exists (demonstrates traceability)
 * - Evidence boosts confidence (shows concrete proof)
 * - Multiple provenance sources increase confidence (cross-validation)
 * - Contradicted findings receive a penalty (conflicting information)
 */
const CONFIDENCE_BASE_WITH_PROVENANCE = 0.6
const CONFIDENCE_BASE_WITHOUT_PROVENANCE = 0.4
const CONFIDENCE_EVIDENCE_BOOST = 0.2
const CONFIDENCE_PROVENANCE_PER_ADDITIONAL = 0.1
const CONFIDENCE_PROVENANCE_MAX_BOOST = 0.2
const CONFIDENCE_CONTRADICTION_PENALTY = 0.3

/**
 * Calculates a confidence score for an analysis finding based on:
 * - Presence of provenance (origin tracking)
 * - Supporting evidence
 * - Number of confirming sources
 * - Whether the finding has been contradicted
 *
 * Score ranges from 0.0 (no confidence) to 1.0 (high confidence).
 *
 * @param finding - The finding to score
 * @returns Confidence score clamped to [0, 1]
 */
const calculateConfidence = (finding: AnalysisFinding): number => {
	const hasProvenance = finding.provenance.length > 0
	const base = hasProvenance ? CONFIDENCE_BASE_WITH_PROVENANCE : CONFIDENCE_BASE_WITHOUT_PROVENANCE

	const hasEvidence = finding.evidence.length > 0
	const evidenceBoost = hasEvidence ? CONFIDENCE_EVIDENCE_BOOST : 0

	const additionalProvenanceCount = Math.max(0, finding.provenance.length - 1)
	const provenanceBoost = Math.min(
		CONFIDENCE_PROVENANCE_MAX_BOOST,
		additionalProvenanceCount * CONFIDENCE_PROVENANCE_PER_ADDITIONAL,
	)

	const contradictionPenalty = finding.contradicted ? CONFIDENCE_CONTRADICTION_PENALTY : 0
	const raw = base + evidenceBoost + provenanceBoost - contradictionPenalty

	return Math.max(0, Math.min(1, raw))
}
// kilocode_change end

// kilocode_change start
/**
 * Generates a unique key for deduplicating findings.
 * Prefers explicit IDs, falls back to location-based keys, then text-based keys.
 * This prevents unrelated findings from being merged when they lack location data.
 *
 * @param finding - The finding to generate a key for
 * @returns A unique string key for correlation
 */
const locationKey = (finding: AnalysisFinding): string => {
	// Prefer a stable, explicit identifier if present.
	if (finding.id) {
		return finding.id
	}

	// Next, try to derive a key from the location information.
	const location = finding.location
	const locationKeyParts = [location?.file, location?.line, location?.functionName].filter(Boolean)
	if (locationKeyParts.length > 0) {
		return locationKeyParts.join(":")
	}

	// If there is no id and no location, fall back to a key based on title/description
	// so that unrelated findings are not merged solely because they lack location data.
	const textKeyParts = [finding.title, finding.description].filter(Boolean)
	if (textKeyParts.length > 0) {
		return textKeyParts.join("|")
	}

	// As a final fallback, derive a deterministic key from other fields that should
	// always be present, ensuring we never return an empty string.
	return ["finding", finding.severity, finding.contradicted ? "contradicted" : "normal"].join("|")
}
// kilocode_change end

// kilocode_change start
/**
 * CorrelationEngine merges duplicate findings to reduce noise and improve signal quality.
 * It combines evidence and provenance from multiple sources, reconciles severity levels,
 * and computes confidence scores based on cross-validation.
 *
 * Merging strategy:
 * - Findings with the same ID or location are considered duplicates
 * - Evidence and provenance are combined (union)
 * - Severity is upgraded to the highest reported level
 * - Confidence increases with multiple confirming sources
 * - Exploitability is set to the maximum reported value (if any)
 * - Contradicted flag is set if any source reports contradiction
 *
 * @example
 * ```typescript
 * const engine = new CorrelationEngine()
 * const findings: AnalysisFinding[] = [
 *   { id: "vuln-001", severity: "medium", evidence: [...], provenance: [...] },
 *   { id: "vuln-001", severity: "high", evidence: [...], provenance: [...] }
 * ]
 *
 * const merged = engine.mergeFindings(findings)
 * // merged[0] has severity "high" and combined evidence/provenance
 * ```
 */
export class CorrelationEngine {
	/**
	 * Merges duplicate findings and computes confidence scores.
	 * Findings are grouped by location or ID, then combined into single findings
	 * with aggregated evidence, provenance, and reconciled severity.
	 *
	 * @param findings - Array of findings to merge (may contain duplicates)
	 * @returns Deduplicated array of findings with confidence scores
	 */
	mergeFindings(findings: AnalysisFinding[]): AnalysisFinding[] {
		// kilocode_change end
		const merged = new Map<string, AnalysisFinding>()

		for (const finding of findings) {
			const key = locationKey(finding)
			const existing = merged.get(key)

			if (!existing) {
				merged.set(key, { ...finding, confidence: finding.confidence ?? calculateConfidence(finding) })
				continue
			}

			// kilocode_change start
			const combinedEvidence: Evidence[] = combine(existing.evidence, finding.evidence)
			const combinedProvenance: Provenance[] = combine(existing.provenance, finding.provenance)
			const combinedSeverity = compareSeverity(existing.severity, finding.severity)

			// Fix: Correctly handle exploitability calculation to preserve 0 values
			const maxExploitability = Math.max(existing.exploitability ?? 0, finding.exploitability ?? 0)
			const combinedExploitability = maxExploitability > 0 ? maxExploitability : undefined

			const combined = {
				...existing,
				title: existing.title.length >= finding.title.length ? existing.title : finding.title,
				description: [existing.description, finding.description].filter(Boolean).join("\n"),
				severity: combinedSeverity,
				evidence: combinedEvidence,
				provenance: combinedProvenance,
				exploitability: combinedExploitability,
				reproduction: existing.reproduction ?? finding.reproduction,
				contradicted: existing.contradicted || finding.contradicted,
			}
			// kilocode_change end

			combined.confidence = calculateConfidence(combined)
			merged.set(key, combined)
		}

		return [...merged.values()]
	}
}
