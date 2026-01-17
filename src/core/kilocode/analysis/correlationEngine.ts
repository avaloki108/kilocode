import type { AnalysisFinding, Evidence, Provenance, Severity } from "./types"

const severityOrder: Severity[] = ["low", "medium", "high", "critical"]

const compareSeverity = (a: Severity, b: Severity): Severity => {
	return severityOrder.indexOf(a) >= severityOrder.indexOf(b) ? a : b
}

const combine = <T>(items: T[], extras: T[]): T[] => {
	return [...items, ...extras]
}

const calculateConfidence = (finding: AnalysisFinding): number => {
	const base = finding.provenance.length > 0 ? 0.6 : 0.4
	const evidenceBoost = finding.evidence.length > 0 ? 0.2 : 0
	const provenanceBoost = Math.min(0.2, (finding.provenance.length - 1) * 0.1)
	const contradictionPenalty = finding.contradicted ? 0.3 : 0
	const raw = base + evidenceBoost + provenanceBoost - contradictionPenalty

	return Math.max(0, Math.min(1, raw))
}

const locationKey = (finding: AnalysisFinding): string => {
	if (finding.id) {
		return finding.id
	}

	const location = finding.location
	return [location?.file, location?.line, location?.functionName].filter(Boolean).join(":")
}

export class CorrelationEngine {
	mergeFindings(findings: AnalysisFinding[]): AnalysisFinding[] {
		const merged = new Map<string, AnalysisFinding>()

		for (const finding of findings) {
			const key = locationKey(finding)
			const existing = merged.get(key)

			if (!existing) {
				merged.set(key, { ...finding, confidence: finding.confidence ?? calculateConfidence(finding) })
				continue
			}

			const combinedEvidence: Evidence[] = combine(existing.evidence, finding.evidence)
			const combinedProvenance: Provenance[] = combine(existing.provenance, finding.provenance)
			const combinedSeverity = compareSeverity(existing.severity, finding.severity)
			const combined = {
				...existing,
				title: existing.title.length >= finding.title.length ? existing.title : finding.title,
				description: [existing.description, finding.description].filter(Boolean).join("\n"),
				severity: combinedSeverity,
				evidence: combinedEvidence,
				provenance: combinedProvenance,
				exploitability: Math.max(existing.exploitability ?? 0, finding.exploitability ?? 0) || undefined,
				reproduction: existing.reproduction ?? finding.reproduction,
				contradicted: existing.contradicted || finding.contradicted,
			}

			combined.confidence = calculateConfidence(combined)
			merged.set(key, combined)
		}

		return [...merged.values()]
	}
}
