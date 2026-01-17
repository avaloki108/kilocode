// kilocode_change - new file
/**
 * Web3 Security Schemas
 *
 * Core schemas for smart contract security analysis, vulnerability detection,
 * and plugin management for the Web3 Security Platform.
 */

// Vulnerability types
export {
	vulnerabilitySeveritySchema,
	type VulnerabilitySeverity,
	vulnerabilityCategorySchema,
	type VulnerabilityCategory,
	chainTypeSchema,
	type ChainType,
	evmChainSchema,
	type EVMChain,
	vulnerabilitySourceSchema,
	type VulnerabilitySource,
	codeLocationSchema,
	type CodeLocation,
	vulnerabilitySchema,
	type Vulnerability,
	vulnerabilityReportSchema,
	type VulnerabilityReport,
	detectionResultSchema,
	type DetectionResult,
} from "./vulnerability.js"

// Analysis types
export {
	analysisDepthSchema,
	type AnalysisDepth,
	analysisMethodSchema,
	type AnalysisMethod,
	toolCapabilitiesSchema,
	type ToolCapabilities,
	analysisResultSchema,
	type AnalysisResult,
	smartContractSchema,
	type SmartContract,
	analysisContextSchema,
	type AnalysisContext,
	analysisConfigSchema,
	type AnalysisConfig,
	fuzzingConfigSchema,
	type FuzzingConfig,
	symbolicExecutionConfigSchema,
	type SymbolicExecutionConfig,
} from "./analysis.js"

// Plugin types
export {
	pluginStateSchema,
	type PluginState,
	pluginCapabilitySchema,
	type PluginCapability,
	securityPluginSchema,
	type SecurityPlugin,
	pluginManifestSchema,
	type PluginManifest,
	marketplacePluginSchema,
	type MarketplacePlugin,
} from "./plugins.js"
