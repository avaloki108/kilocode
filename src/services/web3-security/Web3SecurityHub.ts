// kilocode_change - new file
import type {
	Vulnerability,
	VulnerabilityReport,
	VulnerabilitySeverity,
	VulnerabilityCategory,
	ChainType,
	EVMChain,
} from "@kilocode/core-schemas"

/**
 * Web3SecurityHub - Central orchestration service for smart contract security analysis
 *
 * This service coordinates multiple security analysis tools (Slither, Mythril, Aderyn, Crytic,
 * Foundry, Hardhat, Echidna, Manticore, Maian) and manages their execution,
 * result aggregation, and report generation.
 */
export interface Web3SecurityHubConfig {
	// Tool configuration
	enabledTools: string[]
	toolTimeout: number
	maxConcurrentTools: number

	// Analysis configuration
	defaultAnalysisDepth: "quick" | "standard" | "deep"
	defaultChainType: ChainType
	defaultEVMChain?: EVMChain

	// Output configuration
	outputFormat: "json" | "markdown" | "sarif"
	enableCaching: boolean
	cacheTTL: number
}

export interface AnalysisResult {
	success: boolean
	vulnerabilities: Vulnerability[]
	toolResults: ToolResult[]
	executionTime: number
	error?: string
}

export interface ToolResult {
	tool: string
	vulnerabilities: Vulnerability[]
	executionTime: number
	success: boolean
	error?: string
}

export class Web3SecurityHub {
	private config: Web3SecurityHubConfig
	private activeAnalyses: Map<string, AnalysisResult>
	private cache: Map<string, { result: VulnerabilityReport; timestamp: number }>
	private toolRegistry: Map<string, SecurityTool>

	constructor(config: Web3SecurityHubConfig) {
		this.config = config
		this.activeAnalyses = new Map()
		this.cache = new Map()
		this.toolRegistry = new Map()
	}

	/**
	 * Register a security tool with the hub
	 */
	registerTool(tool: SecurityTool): void {
		this.toolRegistry.set(tool.name, tool)
	}

	/**
	 * Unregister a security tool from the hub
	 */
	unregisterTool(toolName: string): void {
		this.toolRegistry.delete(toolName)
	}

	/**
	 * Get a registered tool by name
	 */
	getTool(toolName: string): SecurityTool | undefined {
		return this.toolRegistry.get(toolName)
	}

	/**
	 * Get all registered tools
	 */
	getAllTools(): SecurityTool[] {
		return Array.from(this.toolRegistry.values())
	}

	/**
	 * Analyze a smart contract using all enabled tools
	 */
	async analyzeContract(params: AnalyzeContractParams): Promise<AnalysisResult> {
		const { contractPath, contractName, chainType, evmChain, tools, depth, targetCategories } = params

		// Check cache first
		const cacheKey = this.getCacheKey(params)
		const cached = this.cache.get(cacheKey)
		if (cached && this.config.enableCaching) {
			const age = Date.now() - cached.timestamp
			if (age < this.config.cacheTTL * 1000) {
				return {
					success: true,
					vulnerabilities: cached.result.vulnerabilities,
					toolResults: [],
					executionTime: 0,
				}
			}
		}

		// Determine which tools to use
		const toolsToUse = tools || this.config.enabledTools
		const availableTools = toolsToUse
			.map((name) => this.toolRegistry.get(name))
			.filter((tool): tool is SecurityTool => tool !== undefined)

		if (availableTools.length === 0) {
			return {
				success: false,
				vulnerabilities: [],
				toolResults: [],
				executionTime: 0,
				error: "No available tools for analysis",
			}
		}

		// Execute tools in parallel or sequentially based on config
		const startTime = Date.now()
		const toolResults: ToolResult[] = []

		if (this.config.maxConcurrentTools > 1) {
			// Parallel execution
			const promises = availableTools.map((tool) => this.executeTool(tool, params))
			const results = await Promise.allSettled(promises)
			toolResults.push(
				...results.map((result, index) => ({
					tool: availableTools[index].name,
					vulnerabilities: result.vulnerabilities || [],
					executionTime: result.executionTime || 0,
					success: result.success,
					error: result.error,
				})),
			)
		} else {
			// Sequential execution
			for (const tool of availableTools) {
				const result = await this.executeTool(tool, params)
				toolResults.push(result)
			}
		}

		const executionTime = Date.now() - startTime

		// Aggregate and deduplicate vulnerabilities
		const allVulnerabilities = toolResults.flatMap((result) => result.vulnerabilities)
		const deduplicatedVulnerabilities = this.deduplicateVulnerabilities(allVulnerabilities)

		// Create final report
		const report: VulnerabilityReport = {
			contractPath,
			contractName,
			chainType,
			evmChain,
			timestamp: new Date().toISOString(),
			analysisDuration: executionTime,
			vulnerabilities: deduplicatedVulnerabilities,
			summary: this.calculateSummary(deduplicatedVulnerabilities),
			toolsUsed: toolResults.filter((result) => result.success).map((result) => result.tool as any),
			analysisConfig: {
				depth,
				tools: toolsToUse,
				targetCategories,
			},
		}

		// Cache the result
		if (this.config.enableCaching) {
			this.cache.set(cacheKey, {
				result: report,
				timestamp: Date.now(),
			})
		}

		return {
			success: true,
			vulnerabilities: deduplicatedVulnerabilities,
			toolResults,
			executionTime,
		}
	}

	/**
	 * Execute a single tool with the given parameters
	 */
	private async executeTool(
		tool: SecurityTool,
		params: AnalyzeContractParams,
	): Promise<{ vulnerabilities?: Vulnerability[]; executionTime?: number; success: boolean; error?: string }> {
		const startTime = Date.now()

		try {
			// Check if tool supports the requested chain
			if (!tool.supportedChains.includes(params.chainType)) {
				return {
					success: false,
					error: `Tool ${tool.name} does not support chain type ${params.chainType}`,
				}
			}

			// Execute the tool
			const result = await tool.analyze({
				contractPath: params.contractPath,
				contractName: params.contractName,
				chainType: params.chainType,
				evmChain: params.evmChain,
				depth: params.depth,
				targetCategories: params.targetCategories,
			})

			const executionTime = Date.now() - startTime

			return {
				vulnerabilities: result.vulnerabilities,
				executionTime,
				success: true,
			}
		} catch (error) {
			return {
				success: false,
				error: error instanceof Error ? error.message : String(error),
			}
		}
	}

	/**
	 * Deduplicate vulnerabilities based on location and description
	 */
	private deduplicateVulnerabilities(vulnerabilities: Vulnerability[]): Vulnerability[] {
		const seen = new Map<string, Vulnerability>()
		const deduplicated: Vulnerability[] = []

		for (const vuln of vulnerabilities) {
			const key = `${vuln.category}-${vuln.title}-${vuln.locations[0]?.file}:${vuln.locations[0]?.line}`
			if (!seen.has(key)) {
				seen.set(key, vuln)
				deduplicated.push(vuln)
			}
		}

		return deduplicated
	}

	/**
	 * Calculate summary statistics for vulnerabilities
	 */
	private calculateSummary(vulnerabilities: Vulnerability[]) {
		const summary = {
			total: vulnerabilities.length,
			critical: 0,
			high: 0,
			medium: 0,
			low: 0,
			informational: 0,
		}

		for (const vuln of vulnerabilities) {
			summary[vuln.severity]++
		}

		return summary
	}

	/**
	 * Generate a cache key for the analysis parameters
	 */
	private getCacheKey(params: AnalyzeContractParams): string {
		return `${params.contractPath}-${params.chainType}-${params.depth}-${params.tools?.join(",") || "all"}`
	}

	/**
	 * Clear the analysis cache
	 */
	clearCache(): void {
		this.cache.clear()
	}

	/**
	 * Get cache statistics
	 */
	getCacheStats(): { size: number; keys: string[] } {
		return {
			size: this.cache.size,
			keys: Array.from(this.cache.keys()),
		}
	}

	/**
	 * Cancel an active analysis
	 */
	cancelAnalysis(analysisId: string): boolean {
		const analysis = this.activeAnalyses.get(analysisId)
		if (analysis) {
			this.activeAnalyses.delete(analysisId)
			return true
		}
		return false
	}

	/**
	 * Get status of all active analyses
	 */
	getActiveAnalyses(): Map<string, AnalysisResult> {
		return new Map(this.activeAnalyses)
	}
}

/**
 * SecurityTool interface - Base interface for all security analysis tools
 */
export interface SecurityTool {
	name: string
	description: string
	supportedChains: ChainType[]
	supportedCategories: VulnerabilityCategory[]
	analyze(params: ToolAnalysisParams): Promise<ToolAnalysisResult>
}

/**
 * Parameters for tool analysis
 */
export interface ToolAnalysisParams {
	contractPath: string
	contractName?: string
	chainType: ChainType
	evmChain?: EVMChain
	depth: "quick" | "standard" | "deep"
	targetCategories?: VulnerabilityCategory[]
}

/**
 * Result from tool analysis
 */
export interface ToolAnalysisResult {
	vulnerabilities: Vulnerability[]
	executionTime?: number
	success: boolean
	error?: string
}

/**
 * Parameters for contract analysis
 */
export interface AnalyzeContractParams {
	contractPath: string
	contractName?: string
	chainType?: ChainType
	evmChain?: EVMChain
	tools?: string[]
	depth?: "quick" | "standard" | "deep"
	targetCategories?: VulnerabilityCategory[]
}

/**
 * Create a new Web3SecurityHub instance with default configuration
 */
export function createWeb3SecurityHub(config?: Partial<Web3SecurityHubConfig>): Web3SecurityHub {
	const defaultConfig: Web3SecurityHubConfig = {
		enabledTools: ["slither", "mythril", "aderyn", "crytic", "foundry", "hardhat", "echidna", "manticore", "maian"],
		toolTimeout: 300000, // 5 minutes
		maxConcurrentTools: 3,
		defaultAnalysisDepth: "standard",
		defaultChainType: "evm",
		outputFormat: "json",
		enableCaching: true,
		cacheTTL: 3600000, // 1 hour
	}

	return new Web3SecurityHub({ ...defaultConfig, ...config })
}
