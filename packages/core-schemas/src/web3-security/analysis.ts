// kilocode_change - new file
import { z } from "zod"

/**
 * Analysis depth levels
 */
export const analysisDepthSchema = z.enum(["quick", "standard", "deep"])

export type AnalysisDepth = z.infer<typeof analysisDepthSchema>

/**
 * Analysis method types
 */
export const analysisMethodSchema = z.enum([
	"static",
	"dynamic",
	"symbolic",
	"fuzzing",
	"formal_verification",
	"manual",
])

export type AnalysisMethod = z.infer<typeof analysisMethodSchema>

/**
 * Chain types
 */
export const chainTypeSchema = z.enum(["evm", "solana", "cosmos", "polkadot", "near", "aptos", "sui", "movr"])

export type ChainType = z.infer<typeof chainTypeSchema>

/**
 * EVM-specific chain identifiers
 */
export const evmChainSchema = z.enum([
	"ethereum",
	"bsc",
	"polygon",
	"arbitrum",
	"optimism",
	"avalanche",
	"fantom",
	"moonbeam",
	"base",
	"linea",
	"celo",
	"gnosis",
	"aurora",
	"harmony",
])

export type EVMChain = z.infer<typeof evmChainSchema>

/**
 * Tool capabilities
 */
export const toolCapabilitiesSchema = z.object({
	vulnerabilityTypes: z.array(
		z.enum([
			"reentrancy",
			"arithmetic",
			"access_control",
			"front_running",
			"logic_error",
			"gas_issue",
			"storage",
			"delegatecall",
			"timestamp",
			"tx_origin",
			"oracle_manipulation",
			"logic_flaw",
		]),
	),
	supportedChains: z.array(chainTypeSchema),
	analysisMethods: z.array(analysisMethodSchema),
	maxFileSize: z.number().optional(),
	requiresCompilation: z.boolean().optional(),
	requiresDeployment: z.boolean().optional(),
})

export type ToolCapabilities = z.infer<typeof toolCapabilitiesSchema>

/**
 * Analysis result from a single tool
 */
export const analysisResultSchema = z.object({
	tool: z.string(),
	method: analysisMethodSchema,
	vulnerabilities: z.array(z.any()),
	executionTime: z.number(),
	success: z.boolean(),
	error: z.string().optional(),
	metadata: z.record(z.string(), z.unknown()).optional(),
})

export type AnalysisResult = z.infer<typeof analysisResultSchema>

/**
 * Smart contract metadata
 */
export const smartContractSchema = z.object({
	path: z.string(),
	name: z.string().optional(),
	address: z.string().optional(),
	chainType: chainTypeSchema,
	evmChain: evmChainSchema.optional(),
	compilerVersion: z.string().optional(),
	optimizerRuns: z.number().optional(),
	fileSize: z.number().optional(),
	lastModified: z.number().optional(),
})

export type SmartContract = z.infer<typeof smartContractSchema>

/**
 * Analysis context - tracks state during analysis
 */
export const analysisContextSchema = z.object({
	id: z.string(),
	contract: smartContractSchema,
	status: z.enum(["pending", "running", "completed", "failed", "cancelled"]),
	startTime: z.number(),
	endTime: z.number().optional(),
	progress: z.number().min(0).max(100),
	currentTool: z.string().optional(),
	results: z.array(analysisResultSchema),
	aggregatedVulnerabilities: z.array(z.any()),
	configuration: z.record(z.string(), z.unknown()),
})

export type AnalysisContext = z.infer<typeof analysisContextSchema>

/**
 * Analysis configuration
 */
export const analysisConfigSchema = z.object({
	// Tool selection
	enabledTools: z.array(z.string()),
	toolTimeouts: z.record(z.string(), z.number()).default({}),

	// Vulnerability detection
	vulnerabilityTypes: z
		.array(
			z.enum([
				"reentrancy",
				"arithmetic",
				"access_control",
				"front_running",
				"logic_error",
				"gas_issue",
				"storage",
				"delegatecall",
				"timestamp",
				"tx_origin",
				"oracle_manipulation",
				"logic_flaw",
			]),
		)
		.default([]),
	severityThreshold: z.enum(["critical", "high", "medium", "low", "informational"]).default("medium"),
	falsePositiveThreshold: z.number().min(0).max(100).default(5),

	// Chain-specific
	chainType: chainTypeSchema.default("evm"),
	chainConfig: z.record(z.string(), z.unknown()).optional(),

	// Analysis depth
	analysisDepth: analysisDepthSchema.default("standard"),
	maxAnalysisTime: z.number().min(60).max(3600).default(300),

	// Reporting
	reportFormat: z.enum(["markdown", "json", "sarif"]).default("markdown"),
	includeExploitScenarios: z.boolean().default(true),
	includeRemediation: z.boolean().default(true),

	// Advanced options
	parallelExecution: z.boolean().default(true),
	cacheResults: z.boolean().default(true),
	incrementalAnalysis: z.boolean().default(false),
})

export type AnalysisConfig = z.infer<typeof analysisConfigSchema>

/**
 * Fuzzing configuration
 */
export const fuzzingConfigSchema = z.object({
	enabled: z.boolean(),
	maxTestCases: z.number().min(1).max(100000).default(1000),
	maxDuration: z.number().min(60).max(3600).default(300),
	targetFunctions: z.array(z.string()).default([]),
	seed: z.string().optional(),
})

export type FuzzingConfig = z.infer<typeof fuzzingConfigSchema>

/**
 * Symbolic execution configuration
 */
export const symbolicExecutionConfigSchema = z.object({
	enabled: z.boolean(),
	maxDepth: z.number().min(1).max(100).default(50),
	maxTime: z.number().min(60).max(3600).default(600),
	targetPaths: z.array(z.string()).default([]),
	solver: z.enum(["z3", "cvc5", "boogie"]).default("z3"),
})

export type SymbolicExecutionConfig = z.infer<typeof symbolicExecutionConfigSchema>
