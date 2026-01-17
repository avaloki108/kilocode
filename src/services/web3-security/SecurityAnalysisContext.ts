// kilocode_change - new file
import type {
	Vulnerability,
	VulnerabilitySeverity,
	VulnerabilityCategory,
	ChainType,
	EVMChain,
} from "@kilocode/core-schemas"

/**
 * SecurityAnalysisContext - Tracks state and progress of security analysis
 *
 * This context maintains information about ongoing analyses, tool execution status,
 * and accumulated results for comprehensive smart contract security analysis.
 */
export interface AnalysisPhase {
	id: string
	name: string
	status: "pending" | "running" | "completed" | "failed"
	startTime?: string
	endTime?: string
	progress?: number
}

export interface ToolExecutionStatus {
	toolName: string
	status: "idle" | "running" | "completed" | "failed"
	startTime: string
	progress?: number
	vulnerabilitiesFound?: number
}

export interface SecurityAnalysisContext {
	// Analysis metadata
	analysisId: string
	contractPath: string
	contractName?: string
	chainType: ChainType
	evmChain?: EVMChain
	startTime: string
	endTime?: string
	status: "initializing" | "analyzing" | "completed" | "failed" | "cancelled"

	// Analysis configuration
	config: {
		depth: "quick" | "standard" | "deep"
		tools: string[]
		targetCategories: VulnerabilityCategory[]
		parallelExecution: boolean
		maxConcurrentTools: number
	}

	// Analysis progress
	phases: AnalysisPhase[]
	currentPhase?: string
	overallProgress: number

	// Tool execution status
	toolStatuses: ToolExecutionStatus[]

	// Accumulated results
	vulnerabilities: Vulnerability[]
	deduplicatedVulnerabilities: Vulnerability[]
	summary: {
		total: number
		critical: number
		high: number
		medium: number
		low: number
		informational: number
	}

	// Error tracking
	errors: Array<{
		tool: string
		message: string
		timestamp: string
		recoverable: boolean
	}>

	// Metrics
	metrics: {
		totalExecutionTime: number
		totalVulnerabilitiesFound: number
		toolsExecuted: number
		toolsSucceeded: number
		toolsFailed: number
		averageConfidence: number
	}

	// Caching
	cacheHit: boolean
	cacheKey: string
}

/**
 * Create a new SecurityAnalysisContext instance
 */
export function createSecurityAnalysisContext(params: {
	analysisId: string
	contractPath: string
	contractName?: string
	chainType: ChainType
	evmChain?: EVMChain
	config?: Partial<SecurityAnalysisContext["config"]>
}): SecurityAnalysisContext {
	const now = new Date().toISOString()

	return {
		// Analysis metadata
		analysisId: params.analysisId,
		contractPath: params.contractPath,
		contractName: params.contractName,
		chainType: params.chainType,
		evmChain: params.evmChain,
		startTime: now,
		status: "initializing",

		// Analysis configuration
		config: {
			depth: params.config?.depth || "standard",
			tools: params.config?.tools || [],
			targetCategories: params.config?.targetCategories || [],
			parallelExecution: params.config?.parallelExecution || false,
			maxConcurrentTools: params.config?.maxConcurrentTools || 3,
		},

		// Analysis progress
		phases: [],
		overallProgress: 0,

		// Tool execution status
		toolStatuses: [],

		// Accumulated results
		vulnerabilities: [],
		deduplicatedVulnerabilities: [],
		summary: {
			total: 0,
			critical: 0,
			high: 0,
			medium: 0,
			low: 0,
			informational: 0,
		},

		// Error tracking
		errors: [],

		// Metrics
		metrics: {
			totalExecutionTime: 0,
			totalVulnerabilitiesFound: 0,
			toolsExecuted: 0,
			toolsSucceeded: 0,
			toolsFailed: 0,
			averageConfidence: 0,
		},

		// Caching
		cacheHit: false,
		cacheKey: "",
	}
}

/**
 * Update analysis status
 */
export function updateStatus(context: SecurityAnalysisContext, status: SecurityAnalysisContext["status"]): void {
	context.status = status
}

/**
 * Add a phase to the analysis
 */
export function addPhase(
	context: SecurityAnalysisContext,
	phase: Omit<AnalysisPhase, "id" | "name" | "status" | "startTime" | "endTime" | "progress">,
): void {
	const phaseWithDefaults: AnalysisPhase = {
		id: phase.id || `phase-${context.phases.length + 1}`,
		name: phase.name || `Phase ${context.phases.length + 1}`,
		status: phase.status || "pending",
		startTime: phase.startTime || new Date().toISOString(),
	}

	context.phases.push(phaseWithDefaults)
}

/**
 * Update a phase status
 */
export function updatePhase(
	context: SecurityAnalysisContext,
	phaseId: string,
	updates: Partial<Omit<AnalysisPhase, "status" | "endTime" | "progress">>,
): void {
	const phase = context.phases.find((p) => p.id === phaseId)
	if (phase) {
		Object.assign(phase, updates)
	}
}

/**
 * Add or update tool execution status
 */
export function updateToolStatus(
	context: SecurityAnalysisContext,
	toolName: string,
	updates: Partial<Omit<ToolExecutionStatus, "status" | "progress" | "vulnerabilitiesFound">>,
): void {
	const existing = context.toolStatuses.find((s) => s.toolName === toolName)
	if (existing) {
		Object.assign(existing, updates)
	} else {
		context.toolStatuses.push({
			toolName,
			status: updates.status || "idle",
			startTime: updates.startTime || new Date().toISOString(),
			progress: updates.progress,
			vulnerabilitiesFound: updates.vulnerabilitiesFound,
		})
	}
}

/**
 * Add vulnerabilities to the context
 */
export function addVulnerabilities(context: SecurityAnalysisContext, vulnerabilities: Vulnerability[]): void {
	context.vulnerabilities.push(...vulnerabilities)
	updateSummary(context)
}

/**
 * Update deduplicated vulnerabilities
 */
export function updateDeduplicatedVulnerabilities(
	context: SecurityAnalysisContext,
	vulnerabilities: Vulnerability[],
): void {
	context.deduplicatedVulnerabilities = vulnerabilities
}

/**
 * Update summary statistics
 */
export function updateSummary(context: SecurityAnalysisContext): void {
	const summary = {
		total: context.vulnerabilities.length,
		critical: context.vulnerabilities.filter((v) => v.severity === "critical").length,
		high: context.vulnerabilities.filter((v) => v.severity === "high").length,
		medium: context.vulnerabilities.filter((v) => v.severity === "medium").length,
		low: context.vulnerabilities.filter((v) => v.severity === "low").length,
		informational: context.vulnerabilities.filter((v) => v.severity === "informational").length,
	}

	context.summary = summary
}

/**
 * Add an error to the context
 */
export function addError(
	context: SecurityAnalysisContext,
	error: {
		tool: string
		message: string
		recoverable?: boolean
	},
): void {
	context.errors.push({
		...error,
		timestamp: new Date().toISOString(),
	})
}

/**
 * Update metrics
 */
export function updateMetrics(
	context: SecurityAnalysisContext,
	updates: Partial<SecurityAnalysisContext["metrics"]>,
): void {
	Object.assign(context.metrics, updates)
}

/**
 * Calculate overall progress
 */
export function updateOverallProgress(context: SecurityAnalysisContext): void {
	if (context.phases.length === 0) {
		context.overallProgress = 0
		return
	}

	const totalPhases = context.phases.length
	const completedPhases = context.phases.filter((p) => p.status === "completed").length
	const runningPhases = context.phases.filter((p) => p.status === "running").length

	// Weight phases: running phases count more than completed
	const progress = (completedPhases * 2 + runningPhases) / (totalPhases * 2)
	context.overallProgress = Math.round(progress * 100)
}

/**
 * Mark analysis as completed
 */
export function completeAnalysis(context: SecurityAnalysisContext): void {
	context.status = "completed"
	context.endTime = new Date().toISOString()

	// Complete all pending phases
	for (const phase of context.phases) {
		if (phase.status === "pending" || phase.status === "running") {
			phase.status = "completed"
			phase.endTime = context.endTime
		}
	}

	// Complete all pending tools
	for (const toolStatus of context.toolStatuses) {
		if (toolStatus.status === "idle" || toolStatus.status === "running") {
			toolStatus.status = "completed"
		}
	}
}

/**
 * Cancel the analysis
 */
export function cancelAnalysis(context: SecurityAnalysisContext): void {
	context.status = "cancelled"
	context.endTime = new Date().toISOString()

	// Cancel all running phases
	for (const phase of context.phases) {
		if (phase.status === "running") {
			phase.status = "failed"
			phase.endTime = context.endTime
		}
	}

	// Cancel all running tools
	for (const toolStatus of context.toolStatuses) {
		if (toolStatus.status === "running") {
			toolStatus.status = "failed"
		}
	}
}

/**
 * Get analysis report
 */
export function getAnalysisReport(context: SecurityAnalysisContext) {
	return {
		analysisId: context.analysisId,
		contractPath: context.contractPath,
		contractName: context.contractName,
		chainType: context.chainType,
		evmChain: context.evmChain,
		timestamp: context.startTime,
		analysisDuration: context.endTime
			? new Date(context.endTime).getTime() - new Date(context.startTime).getTime()
			: 0,
		vulnerabilities: context.deduplicatedVulnerabilities,
		summary: context.summary,
		toolsUsed: context.toolStatuses.filter((s) => s.status === "completed").map((s) => s.toolName),
		errors: context.errors,
		metrics: context.metrics,
		cacheHit: context.cacheHit,
	}
}

/**
 * Check if analysis is complete
 */
export function isAnalysisComplete(context: SecurityAnalysisContext): boolean {
	return context.status === "completed"
}

/**
 * Check if analysis is running
 */
export function isAnalysisRunning(context: SecurityAnalysisContext): boolean {
	return context.status === "analyzing"
}

/**
 * Get active phase
 */
export function getCurrentPhase(context: SecurityAnalysisContext): AnalysisPhase | undefined {
	return context.phases.find((p) => p.status === "running")
}

/**
 * Get active tools
 */
export function getActiveTools(context: SecurityAnalysisContext): string[] {
	return context.toolStatuses.filter((s) => s.status === "running").map((s) => s.toolName)
}
