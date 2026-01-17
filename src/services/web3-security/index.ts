// kilocode_change - new file
/**
 * Web3 Security Services
 *
 * Core services for smart contract security analysis including:
 * - Web3SecurityHub: Central orchestration service
 * - SecurityAnalysisContext: Analysis state tracking
 * - Tool integrations: Slither, Mythril, Aderyn, Crytic, Foundry, Hardhat, Echidna, Manticore, Maian
 * - Agent implementations: Vulnerability detection sub-agents
 * - Report generation: Markdown, JSON, SARIF
 * - Blockchain providers: EVM and Solana
 * - Plugin system: Registry, loader, lifecycle management
 */

export { createWeb3SecurityHub } from "./Web3SecurityHub.js"
export {
	createSecurityAnalysisContext,
	updateStatus,
	addPhase,
	updatePhase,
	addVulnerabilities,
	updateDeduplicatedVulnerabilities,
	updateSummary,
	addError,
	updateMetrics,
	updateOverallProgress,
	completeAnalysis,
	cancelAnalysis,
	getAnalysisReport,
	isAnalysisComplete,
	isAnalysisRunning,
	getCurrentPhase,
	getActiveTools,
} from "./SecurityAnalysisContext.js"
