// kilocode_change - new file

/**
 * Hardhat Integration
 *
 * This module provides integration with Hardhat for smart contract testing,
 * fuzzing, and verification. Hardhat is a development environment for
 * Ethereum software.
 *
 * @see https://hardhat.org/
 */

import type { Vulnerability, CodeLocation } from "../../packages/core-schemas/src/web3-security/vulnerability.js"
import type {
	AnalysisResult,
	SmartContract,
	AnalysisContext,
} from "../../packages/core-schemas/src/web3-security/analysis.js"

/**
 * Hardhat test result
 */
export interface HardhatTestResult {
	/** Test name */
	name: string
	/** Test status: pass, fail, or skipped */
	status: "pass" | "fail" | "skipped"
	/** Test execution time in seconds */
	duration: number
	/** Gas used by test */
	gasUsed?: number
	/** Error message if test failed */
	error?: string
	/** Stack trace if test failed */
	stackTrace?: string
	/** Test file path */
	file: string
	/** Line number of test */
	line: number
}

/**
 * Hardhat coverage result
 */
export interface HardhatCoverageResult {
	/** Contract name */
	contract: string
	/** Function name */
	function: string
	/** Lines covered */
	linesCovered: number
	/** Total lines */
	totalLines: number
	/** Percentage coverage */
	coverage: number
	/** Branches covered */
	branchesCovered: number
	/** Total branches */
	totalBranches: number
}

/**
 * Hardhat gas profiler result
 */
export interface HardhatGasResult {
	/** Contract name */
	contract: string
	/** Function name */
	function: string
	/** Gas used */
	gasUsed: number
	/** Deployment cost */
	deploymentCost?: number
	/** Gas optimization suggestions */
	optimizations?: string[]
}

/**
 * Hardhat analysis result
 */
export interface HardhatResult {
	/** Analysis ID */
	analysisId: string
	/** Target contract */
	target: SmartContract
	/** Analysis timestamp */
	timestamp: string
	/** Test results */
	tests: HardhatTestResult[]
	/** Coverage results */
	coverage: HardhatCoverageResult[]
	/** Gas profiler results */
	gasProfile: HardhatGasResult[]
	/** Overall statistics */
	statistics: {
		/** Total tests run */
		totalTests: number
		/** Tests passed */
		passed: number
		/** Tests failed */
		failed: number
		/** Tests skipped */
		skipped: number
		/** Overall coverage percentage */
		overallCoverage: number
		/** Total gas used */
		totalGasUsed: number
	}
	/** Vulnerabilities detected */
	vulnerabilities: Vulnerability[]
	/** Raw output from Hardhat */
	rawOutput: string
}

/**
 * Hardhat analysis configuration
 */
export interface HardhatAnalysisConfig {
	/** Working directory for Hardhat */
	workingDir: string
	/** Target contract or test file */
	target: string
	/** Network configuration */
	network?: {
		/** Network name */
		name?: string
		/** RPC URL */
		url?: string
		/** Chain ID */
		chainId?: number
		/** Account to use */
		account?: string
	}
	/** Test configuration */
	tests?: {
		/** Specific test to run */
		testName?: string
		/** Test pattern to match */
		testPattern?: string
		/** Verbosity level */
		verbosity?: number
		/** Timeout in seconds */
		timeout?: number
	}
	/** Coverage configuration */
	coverage?: {
		/** Enable coverage collection */
		enabled?: boolean
		/** Coverage report format (lcov, html, json) */
		format?: "lcov" | "html" | "json"
		/** Minimum coverage threshold */
		threshold?: number
	}
	/** Gas profiler configuration */
	gasProfiler?: {
		/** Enable gas profiling */
		enabled?: boolean
		/** Show gas optimization suggestions */
		optimizations?: boolean
	}
	/** Compiler configuration */
	compiler?: {
		/** Solidity version */
		version?: string
		/** Optimization enabled */
		optimization?: boolean
		/** Optimization runs */
		runs?: number
		/** EVM version */
		evmVersion?: string
	}
}

/**
 * Hardhat Integration Service
 */
export class HardhatIntegration {
	private hardhatPath: string
	private workingDir: string

	constructor(config: { hardhatPath?: string; workingDir: string }) {
		this.hardhatPath = config.hardhatPath || "npx hardhat"
		this.workingDir = config.workingDir
	}

	/**
	 * Run Hardhat tests
	 */
	async runTests(config: HardhatAnalysisConfig): Promise<HardhatResult> {
		const analysisId = this.generateAnalysisId()

		// Build command
		const command = this.buildTestCommand(config)

		// Execute command
		const result = await this.executeCommand(command)

		// Parse results
		const testResults = this.parseTestResults(result.stdout)
		const coverage = config.coverage?.enabled ? this.parseCoverageResults(result.stdout) : []
		const gasProfile = config.gasProfiler?.enabled ? this.parseGasResults(result.stdout) : []
		const vulnerabilities = this.detectVulnerabilities(testResults, coverage, gasProfile)

		// Calculate statistics
		const statistics = this.calculateStatistics(testResults, coverage, gasProfile)

		return {
			analysisId,
			target: {
				name: config.target,
				language: "solidity",
				version: config.compiler?.version || "0.8.0",
				sourceCode: "",
				filePath: config.target,
			},
			timestamp: new Date().toISOString(),
			tests: testResults,
			coverage,
			gasProfile,
			statistics,
			vulnerabilities,
			rawOutput: result.stdout,
		}
	}

	/**
	 * Generate coverage report
	 */
	async generateCoverage(config: HardhatAnalysisConfig): Promise<HardhatResult> {
		const coverageConfig = {
			...config,
			coverage: {
				enabled: true,
				format: config.coverage?.format || "json",
				threshold: config.coverage?.threshold || 80,
			},
		}

		return this.runTests(coverageConfig)
	}

	/**
	 * Run gas profiler
	 */
	async runGasProfiler(config: HardhatAnalysisConfig): Promise<HardhatResult> {
		const gasConfig = {
			...config,
			gasProfiler: {
				enabled: true,
				optimizations: config.gasProfiler?.optimizations || true,
			},
		}

		return this.runTests(gasConfig)
	}

	/**
	 * Build test command
	 */
	private buildTestCommand(config: HardhatAnalysisConfig): string {
		const parts = [this.hardhatPath, "test"]

		// Add target
		if (config.target) {
			parts.push(config.target)
		}

		// Add network options
		if (config.network) {
			if (config.network.name) {
				parts.push(`--network ${config.network.name}`)
			}
			if (config.network.url) {
				parts.push(`--url ${config.network.url}`)
			}
		}

		// Add test options
		if (config.tests) {
			if (config.tests.testName) {
				parts.push(`--grep ${config.tests.testName}`)
			}
			if (config.tests.testPattern) {
				parts.push(`--grep ${config.tests.testPattern}`)
			}
			if (config.tests.verbosity) {
				parts.push(`--verbose ${config.tests.verbosity}`)
			}
			if (config.tests.timeout) {
				parts.push(`--timeout ${config.tests.timeout}`)
			}
		}

		// Add coverage options
		if (config.coverage?.enabled) {
			parts.push("--coverage")
			if (config.coverage.format) {
				parts.push(`--coverage-report ${config.coverage.format}`)
			}
			if (config.coverage.threshold) {
				parts.push(`--coverage-threshold ${config.coverage.threshold}`)
			}
		}

		// Add gas profiler options
		if (config.gasProfiler?.enabled) {
			parts.push("--gas-reporter")
			if (config.gasProfiler.optimizations) {
				parts.push("--gas-optimizations")
			}
		}

		// Add JSON output
		parts.push("--json")

		return parts.join(" ")
	}

	/**
	 * Execute command
	 */
	private async executeCommand(
		command: string,
		workingDir?: string,
	): Promise<{ stdout: string; stderr: string; exitCode: number }> {
		// This is a placeholder - actual implementation would use child_process
		// For now, return mock data
		return {
			stdout: JSON.stringify({
				test_results: [
					{
						name: "testExample",
						status: "pass",
						duration: 0.1,
						gasUsed: 100000,
						file: "test/Example.t.sol",
						line: 10,
					},
				],
			}),
			stderr: "",
			exitCode: 0,
		}
	}

	/**
	 * Parse test results
	 */
	private parseTestResults(output: string): HardhatTestResult[] {
		try {
			const data = JSON.parse(output)
			return (data.test_results || []).map((test: any) => ({
				name: test.name,
				status: test.status,
				duration: test.duration,
				gasUsed: test.gasUsed,
				error: test.error,
				stackTrace: test.stackTrace,
				file: test.file,
				line: test.line,
			}))
		} catch (error) {
			console.error("Failed to parse Hardhat test results:", error)
			return []
		}
	}

	/**
	 * Parse coverage results
	 */
	private parseCoverageResults(output: string): HardhatCoverageResult[] {
		try {
			const data = JSON.parse(output)
			return (data.coverage || []).map((cov: any) => ({
				contract: cov.contract,
				function: cov.function,
				linesCovered: cov.linesCovered,
				totalLines: cov.totalLines,
				coverage: cov.coverage,
				branchesCovered: cov.branchesCovered,
				totalBranches: cov.totalBranches,
			}))
		} catch (error) {
			console.error("Failed to parse Hardhat coverage results:", error)
			return []
		}
	}

	/**
	 * Parse gas profiler results
	 */
	private parseGasResults(output: string): HardhatGasResult[] {
		try {
			const data = JSON.parse(output)
			return (data.gas_report || []).map((gas: any) => ({
				contract: gas.contract,
				function: gas.function,
				gasUsed: gas.gasUsed,
				deploymentCost: gas.deploymentCost,
				optimizations: gas.optimizations || [],
			}))
		} catch (error) {
			console.error("Failed to parse Hardhat gas results:", error)
			return []
		}
	}

	/**
	 * Detect vulnerabilities from test results
	 */
	private detectVulnerabilities(
		testResults: HardhatTestResult[],
		coverage: HardhatCoverageResult[],
		gasProfile: HardhatGasResult[],
	): Vulnerability[] {
		const vulnerabilities: Vulnerability[] = []

		// Detect failed tests
		for (const test of testResults.filter((t) => t.status === "fail")) {
			vulnerabilities.push({
				id: `hardhat-test-fail-${test.name}`,
				source: "hardhat",
				severity: "medium",
				category: "logic_error",
				title: "Test Failure",
				description: `Test ${test.name} failed: ${test.error || "Unknown error"}`,
				locations: [
					{
						file: test.file,
						line: test.line,
						column: 0,
					},
				],
			})
		}

		// Detect low coverage
		for (const cov of coverage.filter((c) => c.coverage < 50)) {
			vulnerabilities.push({
				id: `hardhat-low-coverage-${cov.contract}-${cov.function}`,
				source: "hardhat",
				severity: "low",
				category: "logic_error",
				title: "Low Code Coverage",
				description: `Function ${cov.function} in contract ${cov.contract} has only ${cov.coverage}% coverage`,
				locations: [
					{
						file: cov.contract,
						line: 0,
						column: 0,
					},
				],
			})
		}

		// Detect high gas usage
		for (const gas of gasProfile.filter((g) => g.gasUsed > 100000)) {
			vulnerabilities.push({
				id: `hardhat-high-gas-${gas.contract}-${gas.function}`,
				source: "hardhat",
				severity: "low",
				category: "gas_issue",
				title: "High Gas Usage",
				description: `Function ${gas.function} in contract ${gas.contract} uses ${gas.gasUsed} gas, which is high`,
				locations: [
					{
						file: gas.contract,
						line: 0,
						column: 0,
					},
				],
			})
		}

		return vulnerabilities
	}

	/**
	 * Calculate statistics
	 */
	private calculateStatistics(
		testResults: HardhatTestResult[],
		coverage: HardhatCoverageResult[],
		gasProfile: HardhatGasResult[],
	) {
		const totalTests = testResults.length
		const passed = testResults.filter((t) => t.status === "pass").length
		const failed = testResults.filter((t) => t.status === "fail").length
		const skipped = testResults.filter((t) => t.status === "skipped").length
		const overallCoverage =
			coverage.length > 0 ? coverage.reduce((sum, c) => sum + c.coverage, 0) / coverage.length : 0
		const totalGasUsed = gasProfile.reduce((sum, g) => sum + g.gasUsed, 0)

		return {
			totalTests,
			passed,
			failed,
			skipped,
			overallCoverage,
			totalGasUsed,
		}
	}

	/**
	 * Generate analysis ID
	 */
	private generateAnalysisId(): string {
		return `hardhat-${Date.now()}-${Math.random().toString(36).substring(7)}`
	}
}
